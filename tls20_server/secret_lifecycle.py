"""Ownership boundaries for temporary handshake keys and failure tracebacks.

This releases managed references; it cannot wipe immutable Python allocations
or copies retained by application callbacks, providers or explicit key logging.
"""

import functools
import sys

from . import crypto


def clear_protocol_tracebacks(error):
    """Keep traceback locations, but not completed protocol frames' locals.

    Do not clear caller/callback frames or mutate shared credentials/providers.
    Follow both exception chains: a retained cause can otherwise keep the same
    secrets alive after the public handshake exception has been sanitized.
    """
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(value for value in (current.__cause__, current.__context__)
                       if value is not None)
        for child in getattr(current, "exceptions", ()):
            pending.append(child)
        trace = current.__traceback__
        while trace is not None:
            frame = trace.tb_frame
            if frame.f_globals.get("__name__", "").startswith("tls20_server."):
                try:
                    frame.clear()
                except RuntimeError:
                    pass  # An outer protocol caller may still be executing.
            trace = trace.tb_next


def handshake_boundary(method):
    """Close failed streams and release secret-bearing completed trace frames."""
    @functools.wraps(method)
    async def guarded(reader, writer, *args, **kwargs):
        try:
            return await method(reader, writer, *args, **kwargs)
        except BaseException as error:
            try:
                if writer is not None:
                    writer.close()
            except (OSError, AttributeError):
                pass
            finally:
                clear_protocol_tracebacks(error)
            raise
    return guarded


def protocol_boundary(method):
    """Release completed protocol frames without changing live channel state.

    A pre-send validation error must not abort independent pending requests.
    The operation itself owns its state transition and transport cleanup.
    """
    @functools.wraps(method)
    async def guarded(*args, **kwargs):
        try:
            return await method(*args, **kwargs)
        except BaseException as error:
            clear_protocol_tracebacks(error)
            raise
    return guarded


def sync_protocol_boundary(method):
    """Synchronous counterpart for application-authenticator operations."""
    @functools.wraps(method)
    def guarded(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except BaseException as error:
            clear_protocol_tracebacks(error)
            raise
    return guarded


class HandshakeSecrets:
    """Own temporary epochs/ephemerals until handoff or handshake termination."""

    def __init__(self):
        self.records = []
        self.keys = []
        self.channel = None

    def record(self, *args, **kwargs):
        state = crypto.RecordState(*args, **kwargs)
        self.records.append(state)
        return state

    def traffic_key(self, group, provider=None):
        key, public = crypto.traffic_key(group, provider=provider)
        self.keys.append(key)
        return key, public

    def close_record(self, state):
        """Retire an epoch immediately after its last permitted use."""
        if state is not None:
            state.close()
            self.records = [value for value in self.records if value is not state]

    def close_key(self, key):
        close = getattr(key, "close", None)
        if close is not None:
            close()
        self.keys = [value for value in self.keys if value is not key]

    def establish(self, channel):
        # A channel may still fail before return (e.g. during ticket issuance).
        self.channel = channel

    def release(self, channel):
        if self.channel is not channel:
            raise RuntimeError("handshake channel ownership mismatch")
        self.channel = None
        try:
            self.close(preserve_error=False)
        except BaseException:
            # A failing finalizer must not turn a would-be successful return
            # into an exception that leaves its unretrieved channel usable.
            channel.abort()
            raise
        return channel

    def close(self, *, preserve_error=True):
        primary = sys.exception() if preserve_error else None
        channel, self.channel = self.channel, None
        records, self.records = self.records, []
        keys, self.keys = self.keys, []
        callbacks = ([channel.abort] if channel is not None else [])
        callbacks.extend(state.close for state in records)
        callbacks.extend(key.close for key in keys if hasattr(key, "close"))
        failures = []
        for close in callbacks:
            try:
                close()
            except BaseException as error:
                failures.append(error)
        if failures:
            if primary is not None:
                primary.add_note("Additional handshake resource cleanup failed; all owned cleanup operations were attempted.")
            else:
                raise failures[0]
