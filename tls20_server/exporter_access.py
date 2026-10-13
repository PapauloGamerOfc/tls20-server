"""Explicit, connection-scoped exporter capabilities during a handshake.

Exporting key material is not authorization. Early exporters are replayable;
normal exporters before peer Finished do not authenticate that peer. Callbacks
must not authorize irreversible effects from either fact alone.
"""

from . import crypto as c
from .errors import ProtocolError
from .secret_lifecycle import sync_protocol_boundary


class ExporterAccess:
    def __init__(self, secret, *, stage, role, peer_authenticated=False, hash_name=None):
        if stage not in ("early", "server-finished") or role not in ("client", "server"):
            raise ValueError("invalid exporter stage or role")
        self._secret = secret
        self.hash_name = c.secret_hash(secret, hash_name)
        self.stage, self.role = stage, role
        self.replayable = stage == "early"
        self.peer_authenticated = bool(peer_authenticated)
        self.handshake_completed = False

    @property
    def active(self):
        return self._secret is not None

    @sync_protocol_boundary
    def export(self, label, context=b"", length=32):
        if not self.active:
            raise ProtocolError("exporter capability is no longer active")
        if not isinstance(context, bytes) or type(length) is not int:
            raise ValueError("exporter context and length types")
        return c.exporter(self._secret, label, context, length, self.hash_name)

    def complete(self, *, peer_authenticated):
        if self.active:
            self.handshake_completed = True
            self.peer_authenticated = bool(peer_authenticated)

    def close(self):
        self._secret = None
        self.peer_authenticated = False


async def expose(callback, secret, handles, *, stage, role, peer_authenticated=False, hash_name=None):
    if callback is None or secret is None:
        return
    import inspect
    access = ExporterAccess(secret, stage=stage, role=role, peer_authenticated=peer_authenticated, hash_name=hash_name)
    handles.append(access)  # Register BEFORE the callback, including cancellation.
    result = callback(access)
    if inspect.isawaitable(result):
        await result
