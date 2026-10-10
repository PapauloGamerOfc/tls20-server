"""Async stream handshake for the independent draft-01 profile.

The wire contract is pinned to tls20-spec commit babaa838a45713764031becae3420f489f8ffca8.
This Python prototype cannot guarantee physical erasure of immutable secrets.
"""

import asyncio
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto as c
from . import messages as m
from .errors import ProtocolError
from .pki import validate_chain


MAX_BODY = 262144
MAX_TRANSCRIPT = 1048576
MAX_HANDSHAKE_RECORDS = 4096
APPLICATION_PROTOCOL = b"http/1.1"


class Transcript:
    def __init__(self):
        self.data = bytearray(c.PREFACE)

    def add(self, message):
        if len(self.data) + len(message) > MAX_TRANSCRIPT:
            raise ProtocolError("handshake transcript limit exceeded")
        self.data.extend(message)

    def snapshot(self):
        return bytes(self.data)


class Wire:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.pending = bytearray()
        self.handshake_records = 0
        self.handshake = True
        self.deadline = None

    def check_deadline(self):
        if self.deadline is not None and asyncio.get_running_loop().time() >= self.deadline:
            raise TimeoutError("handshake deadline exceeded")

    def count(self):
        if self.handshake:
            if self.handshake_records >= MAX_HANDSHAKE_RECORDS:
                raise ProtocolError("handshake record limit exceeded")
            self.handshake_records += 1

    async def exact(self, count):
        self.check_deadline()
        try:
            data = await self.reader.readexactly(count)
            self.check_deadline()
            return data
        except asyncio.IncompleteReadError as exc:
            raise ProtocolError("unclean transport EOF") from exc

    async def read_record(self, state=None):
        header = await self.exact(5)
        kind, version = header[0], header[1:3]
        length = int.from_bytes(header[3:], "big")
        if version != b"\x03\x03":
            raise ProtocolError("invalid record framing version")
        if state is None:
            if kind not in (21, 22) or not 1 <= length <= 16384:
                raise ProtocolError("invalid plaintext record")
        elif kind != 23 or not 17 <= length <= 16401:
            raise ProtocolError("invalid protected record")
        self.count()
        fragment = await self.exact(length)
        if state is None:
            return fragment, kind
        return state.open(header + fragment)

    async def send_frame(self, message, state=None):
        for offset in range(0, len(message), 16384):
            self.check_deadline()
            fragment = message[offset:offset + 16384]
            self.count()
            if state is None:
                wire = b"\x16\x03\x03" + len(fragment).to_bytes(2, "big") + fragment
            else:
                wire = state.seal(fragment, 22)
            self.writer.write(wire)
            await self.writer.drain()

    async def receive_frame(self, expected, state=None, *, boundary=False):
        while True:
            self.check_deadline()
            if len(self.pending) >= 4:
                kind = self.pending[0]
                length = int.from_bytes(self.pending[1:4], "big")
                if kind != expected or length > MAX_BODY:
                    raise ProtocolError("unexpected or oversized handshake message")
                if kind in (15, 20) and length != 32:
                    raise ProtocolError("invalid authenticator size")
                if len(self.pending) >= length + 4:
                    message = bytes(self.pending[:length + 4])
                    del self.pending[:length + 4]
                    if boundary and self.pending:
                        raise ProtocolError("handshake bytes cross a key transition")
                    return message
            fragment, kind = await self.read_record(state)
            if kind == 21:
                raise ProtocolError("peer aborted the handshake")
            if kind != 22 or not fragment:
                raise ProtocolError("application data before authentication")
            if len(self.pending) + len(fragment) > MAX_BODY + 4 + 16384:
                raise ProtocolError("handshake reassembly limit exceeded")
            self.pending.extend(fragment)


class SecureChannel:
    """One established duplex channel. Network EOF is not clean closure."""

    def __init__(self, wire, send_secret, receive_secret):
        if wire.pending:
            raise ProtocolError("leftover handshake bytes")
        self.wire = wire
        self.wire.handshake = False
        self.wire.deadline = None
        self.sender = c.RecordState(send_secret, "seal")
        self.receiver = c.RecordState(receive_secret, "open")
        self.send_lock = asyncio.Lock()
        self.receive_lock = asyncio.Lock()
        self.sent_close = False
        self.received_close = False
        self.read_cancelled = False
        self.closed = False

    def abort(self):
        self.closed = True
        # close() may wait indefinitely for a peer that stopped reading. This
        # path is explicitly an abort, so discard buffered output immediately.
        self.wire.writer.transport.abort()

    async def recv(self):
        async with self.receive_lock:
            if self.received_close:
                return None
            if self.closed or self.read_cancelled:
                raise ProtocolError("connection is closed")
            try:
                content, kind = await self.wire.read_record(self.receiver)
                if kind == 23:
                    return content
                if kind == 21 and content == b"\x01\x00":
                    self.received_close = True
                    return None
                raise ProtocolError("peer alert or unexpected post-handshake message")
            except asyncio.CancelledError:
                # A partial record cannot be resumed, but the independent send
                # direction may still send close_notify during relay cleanup.
                self.read_cancelled = True
                raise
            except BaseException:
                self.abort()
                raise

    async def send(self, content):
        async with self.send_lock:
            if self.closed or self.sent_close or self.received_close or self.read_cancelled:
                raise ProtocolError("connection is closing")
            try:
                chunks = (content[i:i + 16384] for i in range(0, len(content), 16384))
                for chunk in chunks:
                    self.wire.writer.write(self.sender.seal(chunk, 23))
                    await self.wire.writer.drain()
            except BaseException:
                self.abort()
                raise

    async def close(self):
        try:
            async with asyncio.timeout(1):
                async with self.send_lock:
                    if not self.closed and not self.sent_close:
                        self.sent_close = True
                        self.wire.writer.write(self.sender.seal(b"\x01\x00", 21))
                        await self.wire.writer.drain()
        except (OSError, ProtocolError, TimeoutError):
            pass
        finally:
            # Preserve queued close_notify on the normal path; force-abort only
            # if flushing/closing does not finish within the bounded deadline.
            self.closed = True
            self.wire.writer.close()
            try:
                async with asyncio.timeout(1):
                    await self.wire.writer.wait_closed()
            except (OSError, TimeoutError):
                self.abort()
            except asyncio.CancelledError:
                self.abort()
                raise


def handshake_keys(root, transcript):
    digest = c.digest(transcript.snapshot())
    return c.label_expand(root, "c hs", digest, 32), c.label_expand(root, "s hs", digest, 32)


def application_keys(root, transcript):
    digest = c.digest(transcript.snapshot())
    app_root = c.label_expand(root, "application", digest, 32)
    return c.label_expand(app_root, "c ap", digest, 32), c.label_expand(app_root, "s ap", digest, 32)


def check_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise ValueError("handshake timeout must be positive and at most 30 seconds")


async def server_handshake(reader, writer, credentials, server_name, timeout=10):
    check_timeout(timeout)
    wire = Wire(reader, writer)
    wire.deadline = asyncio.get_running_loop().time() + timeout
    transcript = Transcript()
    try:
        async with asyncio.timeout(timeout):
            if await wire.exact(len(c.PREFACE)) != c.PREFACE:
                raise ProtocolError("not the experimental draft-01 protocol")
            ch = await wire.receive_frame(1, boundary=True)
            hello = m.parse_client_hello(ch[4:])
            if hello.name != server_name or hello.protocol != APPLICATION_PROTOCOL:
                raise ProtocolError("unsupported service identity or application protocol")
            static_public = c.public_bytes(credentials.private_key)
            if hello.A == hello.B or static_public in (hello.A, hello.B):
                raise ProtocolError("non-independent key shares")
            transcript.add(ch)
            ephemeral = X25519PrivateKey.generate()
            ephemeral_public = c.public_bytes(ephemeral)
            if ephemeral_public in (hello.A, hello.B, static_public):
                raise ProtocolError("non-independent key shares")
            # Reject both zero agreements before sending a server flight.
            traffic_root = c.extract(c.ZERO32, c.dh(ephemeral, hello.B))
            auth_root = c.extract(c.ZERO32, c.dh(credentials.private_key, hello.A))
            sh = m.server_hello(ephemeral_public, os.urandom(32))
            transcript.add(sh)
            client_secret, server_secret = handshake_keys(traffic_root, transcript)
            receiver = c.RecordState(client_secret, "open")
            sender = c.RecordState(server_secret, "seal")
            await wire.send_frame(sh)
            for message in (m.encrypted_extensions(APPLICATION_PROTOCOL), m.certificate(credentials.chain_der)):
                transcript.add(message)
                await wire.send_frame(message, sender)
            cv = m.frame(15, c.server_proof(auth_root, transcript.snapshot()))
            transcript.add(cv)
            await wire.send_frame(cv, sender)
            sf = m.frame(20, c.finished(server_secret, transcript.snapshot()))
            transcript.add(sf)
            await wire.send_frame(sf, sender)
            cf = await wire.receive_frame(20, receiver, boundary=True)
            if not c.verify_finished(client_secret, transcript.snapshot(), cf[4:]):
                raise ProtocolError("client Finished verification failed")
            transcript.add(cf)
            client_app, server_app = application_keys(traffic_root, transcript)
            wire.check_deadline()
            return SecureChannel(wire, server_app, client_app)
    except BaseException:
        writer.transport.abort()
        raise


async def client_handshake(reader, writer, server_name, trust_roots, *, revocation_policy, timeout=10):
    check_timeout(timeout)
    m.validate_name(server_name)
    wire = Wire(reader, writer)
    wire.deadline = asyncio.get_running_loop().time() + timeout
    transcript = Transcript()
    try:
        async with asyncio.timeout(timeout):
            auth_private = X25519PrivateKey.generate()
            traffic_private = X25519PrivateKey.generate()
            auth_public, traffic_public = c.public_bytes(auth_private), c.public_bytes(traffic_private)
            if auth_public == traffic_public:
                raise ProtocolError("non-independent key shares")
            ch = m.client_hello(auth_public, traffic_public, server_name, os.urandom(32))
            transcript.add(ch)
            writer.write(c.PREFACE)
            await wire.send_frame(ch)
            sh = await wire.receive_frame(2, boundary=True)
            ephemeral_public = m.parse_server_hello(sh[4:])
            if ephemeral_public in (auth_public, traffic_public):
                raise ProtocolError("non-independent key shares")
            transcript.add(sh)
            traffic_root = c.extract(c.ZERO32, c.dh(traffic_private, ephemeral_public))
            client_secret, server_secret = handshake_keys(traffic_root, transcript)
            sender = c.RecordState(client_secret, "seal")
            receiver = c.RecordState(server_secret, "open")
            ee = await wire.receive_frame(8, receiver)
            m.parse_encrypted_extensions(ee[4:], APPLICATION_PROTOCOL)
            transcript.add(ee)
            cert = await wire.receive_frame(11, receiver)
            chain_der = m.parse_certificate(cert[4:])
            # Bounded local validation; no certificate-controlled network requests.
            static_key = validate_chain(chain_der, trust_roots, server_name, revocation_policy)
            wire.check_deadline()
            static_public = c.public_bytes(static_key)
            if static_public in (auth_public, traffic_public, ephemeral_public):
                raise ProtocolError("non-independent certified key")
            transcript.add(cert)
            auth_root = c.extract(c.ZERO32, c.dh(auth_private, static_public))
            cv = await wire.receive_frame(15, receiver)
            if not c.verify_proof(auth_root, transcript.snapshot(), cv[4:]):
                raise ProtocolError("server authentication verification failed")
            transcript.add(cv)
            sf = await wire.receive_frame(20, receiver, boundary=True)
            if not c.verify_finished(server_secret, transcript.snapshot(), sf[4:]):
                raise ProtocolError("server Finished verification failed")
            transcript.add(sf)
            cf = m.frame(20, c.finished(client_secret, transcript.snapshot()))
            await wire.send_frame(cf, sender)
            transcript.add(cf)
            client_app, server_app = application_keys(traffic_root, transcript)
            wire.check_deadline()
            return SecureChannel(wire, client_app, server_app)
    except BaseException:
        writer.transport.abort()
        raise
