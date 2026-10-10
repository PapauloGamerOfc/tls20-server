"""Bounded asynchronous TLS 2.0 termination and local byte-stream relay."""

from __future__ import annotations

import asyncio
from contextlib import suppress
import logging
import time
from typing import Any

from .config import Config
from .handshake import server_handshake
from .pki import load_credentials


LOG = logging.getLogger(__name__)
CHUNK_SIZE = 16384
CLOSE_WAIT_SECONDS = 1
HANDLER_SHUTDOWN_SECONDS = 3


class RelayLimitError(Exception):
    """A configured connection quota has been reached."""


def _abort_writer(writer: asyncio.StreamWriter | None) -> None:
    """Discard buffered output; close() alone can wait forever for a peer."""
    if writer is None:
        return
    with suppress(Exception):
        writer.transport.abort()
    with suppress(Exception):
        writer.close()


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=CLOSE_WAIT_SECONDS)
    except asyncio.CancelledError:
        _abort_writer(writer)
        raise
    except Exception:
        _abort_writer(writer)


async def _relay(channel: Any, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Config) -> None:
    last_activity = time.monotonic()

    async def to_backend() -> None:
        nonlocal last_activity
        total = 0
        while True:
            content = await channel.recv()
            if content is None:
                # The profile closes the secure stream after close_notify;
                # do not forward later backend bytes after the peer closed.
                return
            if not content:
                # Empty application records are valid, but cannot keep an
                # otherwise idle connection alive indefinitely.
                continue
            if len(content) > config.max_bytes_per_direction - total:
                raise RelayLimitError("Client byte quota reached")
            total += len(content)
            last_activity = time.monotonic()
            writer.write(content)
            await writer.drain()

    async def to_client() -> None:
        nonlocal last_activity
        total = 0
        while True:
            content = await reader.read(CHUNK_SIZE)
            if not content:
                # This relay deliberately does not parse HTTP. A backend EOF
                # does not prove an HTTP response was complete: Content-Length,
                # chunk framing, etc. must still be checked by the client.
                LOG.info("HTTP upstream closed; application framing determines response completeness")
                return
            if len(content) > config.max_bytes_per_direction - total:
                raise RelayLimitError("Upstream byte quota reached")
            total += len(content)
            last_activity = time.monotonic()
            await channel.send(content)

    async def idle_watchdog() -> None:
        while True:
            remaining = config.idle_timeout_seconds - (time.monotonic() - last_activity)
            if remaining <= 0:
                raise TimeoutError("Connection idle timeout")
            await asyncio.sleep(remaining)

    upload = asyncio.create_task(to_backend())
    download = asyncio.create_task(to_client())
    idle = asyncio.create_task(idle_watchdog())
    owned = {upload, download, idle}
    try:
        pending = set(owned)
        while True:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            # Propagate every error before treating any simultaneous completion
            # as a clean EOF. In particular, never hide an authentication error.
            for task in done:
                task.result()
            if download in done or upload in done:
                return
    finally:
        for task in owned:
            if not task.done():
                task.cancel()
        await asyncio.gather(*owned, return_exceptions=True)


class RunningServer:
    """Own the listener and all accepted connection tasks."""

    def __init__(self, config: Config, credentials: Any):
        self.config = config
        self.credentials = credentials
        self.server: asyncio.AbstractServer
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._upstream_writers: set[asyncio.StreamWriter] = set()
        self._closing = False

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closing or len(self._tasks) >= self.config.max_connections:
            # Admission is synchronous, before spawning another task or doing
            # cryptography; saturated connections are not queued in user space.
            _abort_writer(writer)
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        self._writers.add(writer)

        def finished(done: asyncio.Task[None]) -> None:
            # A task cancelled before its first execution never enters its
            # finally block. Abort before releasing its admission slot, so a
            # buffered transport cannot outlive connection-limit accounting.
            _abort_writer(writer)
            self._writers.discard(writer)
            self._tasks.discard(done)

        task.add_done_callback(finished)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        channel = None
        upstream_writer = None
        clean_end = False
        try:
            async with asyncio.timeout(self.config.max_connection_seconds):
                channel = await asyncio.wait_for(
                    server_handshake(
                        reader, writer, self.credentials, self.config.server_name,
                        timeout=self.config.handshake_timeout_seconds,
                    ), timeout=self.config.handshake_timeout_seconds,
                )
                # This line is unreachable before the client's authenticated
                # Finished has been verified by server_handshake.
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.upstream.host, self.config.upstream.port),
                    timeout=self.config.connect_timeout_seconds,
                )
                self._upstream_writers.add(upstream_writer)
                await _relay(channel, upstream_reader, upstream_writer, self.config)
                clean_end = True
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            LOG.info("Connection closed after a configured timeout")
        except RelayLimitError:
            LOG.info("Connection closed after a configured byte quota")
        except Exception as exc:
            # Exception text may contain untrusted certificate, name, or wire
            # data. Record only its class, never plaintext or secret material.
            LOG.info("Connection failed (%s)", type(exc).__name__)
        finally:
            try:
                if channel is not None:
                    if clean_end and not self._closing:
                        with suppress(Exception):
                            await asyncio.wait_for(channel.close(), timeout=CLOSE_WAIT_SECONDS)
                    channel.abort()
            finally:
                try:
                    await _close_writer(upstream_writer)
                finally:
                    _abort_writer(upstream_writer)
                    self._upstream_writers.discard(upstream_writer)
                    try:
                        await _close_writer(writer)
                    finally:
                        _abort_writer(writer)

    async def close(self) -> None:
        self._closing = True
        self.server.close()
        for writer in tuple(self._writers | self._upstream_writers):
            _abort_writer(writer)
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        try:
            if tasks:
                _, pending = await asyncio.wait(tasks, timeout=HANDLER_SHUTDOWN_SECONDS)
                for task in pending:
                    task.cancel()
                if pending:
                    LOG.warning("Connection tasks exceeded their shutdown deadline; transports aborted")
            # New Python versions wait for accepted transports as well as the
            # listener. Their buffered output has already been discarded.
            with suppress(TimeoutError):
                await asyncio.wait_for(self.server.wait_closed(), timeout=CLOSE_WAIT_SECONDS)
        finally:
            # Also execute when this close() call itself is cancelled.
            for writer in tuple(self._writers | self._upstream_writers):
                _abort_writer(writer)
            for task in tuple(self._tasks):
                if not task.done():
                    task.cancel()

    async def __aenter__(self) -> RunningServer:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()


async def start_server(config: Config, credentials: Any = None) -> RunningServer:
    """Validate local credentials before opening a TCP listening socket."""
    if credentials is None:
        credentials = load_credentials(
            config.certificate_chain, config.private_key, config.server_name
        )
    running = RunningServer(config, credentials)
    running.server = await asyncio.start_server(
        running._accept, config.listen.host, config.listen.port,
        limit=65536, backlog=min(config.max_connections, 128),
    )
    return running
