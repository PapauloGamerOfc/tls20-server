"""Async stream implementation of the current TLS 2.0 authenticated profile.
This Python prototype cannot guarantee physical erasure of immutable secrets.
"""

import asyncio
import hmac
import inspect
import math
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from . import crypto as c
from . import messages as m
from .errors import ProtocolError
from .pki import validate_chain
from .tickets import SessionTicket


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

    def retry(self, client_hello, retry):
        self.data = bytearray(c.PREFACE + b"\xfe\x00\x00\x20" + c.digest(client_hello) + retry)


class Wire:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.pending = bytearray()
        self.handshake_records = 0
        self.handshake = True
        self.deadline = None
        self.allow_ccs = False

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

    async def raw_record(self):
        header = await self.exact(5)
        kind, version = header[0], header[1:3]
        length = int.from_bytes(header[3:], "big")
        # Plaintext legacy_record_version is ignored; supported_versions in
        # the Hello is the authenticated selection. Ciphertext uses 0x0303.
        if kind == 23 and version != b"\x03\x03":
            raise ProtocolError("invalid record framing version")
        if not 1 <= length <= (16640 if kind == 23 else 16384):
            raise ProtocolError("invalid record length")
        self.count()
        fragment = await self.exact(length)
        return header + fragment

    async def read_record(self, state=None):
        while True:
            record = await self.raw_record()
            kind, fragment = record[0], record[5:]
            if kind == 20 and self.handshake and self.allow_ccs and fragment == b"\x01":
                continue
            break
        if state is None:
            if kind not in (21, 22):
                raise ProtocolError("invalid plaintext record")
            return fragment, kind
        return state.open(record)

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

    async def send_ccs(self):
        self.check_deadline()
        self.count()
        self.writer.write(b"\x14\x03\x03\x00\x01\x01")
        await self.writer.drain()

    async def receive_frame(self, expected, state=None, *, boundary=False):
        while True:
            self.check_deadline()
            if len(self.pending) >= 4:
                kind = self.pending[0]
                length = int.from_bytes(self.pending[1:4], "big")
                expected_types = (expected,) if isinstance(expected, int) else expected
                if kind not in expected_types or length > MAX_BODY:
                    raise ProtocolError("unexpected or oversized handshake message")
                if kind == 20 and length != 32:
                    raise ProtocolError("invalid authenticator size")
                if len(self.pending) >= length + 4:
                    message = bytes(self.pending[:length + 4])
                    del self.pending[:length + 4]
                    if boundary and self.pending:
                        raise ProtocolError("handshake bytes cross a key transition")
                    m.decode_frame(message)
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

    def __init__(self, wire, send_secret, receive_secret, *, exporter_secret=None,
                 resumption_secret=None, ticket_cache=None, name="", context=b"",
                 certificate_chain=None, resumed=False, early_data_accepted=False,
                 handshake_transcript=b"", client_credentials=None, client_auth_validator=None,
                 peer_post_handshake_auth=False, local_post_handshake_auth=False,
                 authenticated_client=None):
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
        self.exporter_secret = exporter_secret
        self.resumption_secret = resumption_secret
        self.ticket_cache, self.name, self.context = ticket_cache, name, context
        self.certificate_chain = certificate_chain or []
        self.resumed, self.early_data_accepted = resumed, early_data_accepted
        self.post_handshake = bytearray()
        self.handshake_transcript = handshake_transcript
        self.client_credentials, self.client_auth_validator = client_credentials, client_auth_validator
        self.peer_post_handshake_auth, self.local_post_handshake_auth = peer_post_handshake_auth, local_post_handshake_auth
        self.authenticated_client = authenticated_client
        self.pending_client_auth = {}
        self._active_client_auth = None
        self._seen_auth_contexts = set()

    def _clear_auth(self):
        pending, self.pending_client_auth = self.pending_client_auth, {}
        self._active_client_auth = None
        for state in pending.values():
            state["private"] = None
            if not state["future"].done():
                state["future"].cancel()

    async def request_client_auth(self, *, required=False, max_pending=128):
        """Return a Future completed by recv(); application must keep reading.

        max_pending is a local memory budget, not a TLS protocol maximum.
        Canceling the Future aborts the connection, consuming its private state.
        """
        if (not self.peer_post_handshake_auth or self.client_auth_validator is None
                or not self.handshake_transcript or self.closed or self.read_cancelled
                or self.received_close or self.sent_close):
            raise ProtocolError("post-handshake client authentication is unavailable")
        if max_pending < 1 or len(self.pending_client_auth) >= max_pending:
            raise ProtocolError("local pending authentication budget")
        context = os.urandom(32)
        while context in self.pending_client_auth:
            context = os.urandom(32)
        private = X25519PrivateKey.generate()
        request = m.certificate_request(context, c.public_bytes(private))
        future = asyncio.get_running_loop().create_future()
        state = {"private": private, "future": future, "required": required,
                 "transcript": bytearray(self.handshake_transcript + request),
                 "stage": "certificate", "chain": [], "key": None, "context": context}
        self.pending_client_auth[context] = state
        future.add_done_callback(lambda done: self.abort() if done.cancelled() and not self.closed else None)
        try:
            await self.send_handshake(request)
        except BaseException:
            self.abort()
            raise
        return future

    async def _answer_client_auth(self, request):
        context, share, algorithms = m.parse_certificate_request(request[4:])
        if (not self.local_post_handshake_auth or not context or context in self._seen_auth_contexts
                or len(self._seen_auth_contexts) >= 4096):
            raise ProtocolError("unsolicited, repeated or over-budget client-auth request")
        self._seen_auth_contexts.add(context)
        transcript = bytearray(self.handshake_transcript + request)
        async with self.send_lock:
            try:
                for message in _client_auth_messages(self.client_credentials, context, share,
                                                     algorithms, self.exporter_secret, transcript):
                    await self.wire.send_frame(message, self.sender)
                await self.wire.send_frame(m.frame(20, c.finished(self.sender.secret, bytes(transcript))), self.sender)
            except BaseException:
                self.abort()
                raise

    async def _receive_client_auth(self, frame):
        kind, body = m.decode_frame(frame)
        if kind == 11:
            if self._active_client_auth is not None or not body:
                raise ProtocolError("interleaved client authentication response")
            size = body[0]
            context = body[1:1+size]
            state = self.pending_client_auth.get(context)
            if state is None or state["stage"] != "certificate":
                raise ProtocolError("unsolicited client authentication certificate")
            state["chain"] = m.parse_certificate(body, context=context, allow_empty=True)
            state["transcript"].extend(frame)
            self._active_client_auth = state
            if state["chain"]:
                _check_certificate_offer(state["chain"], m.CERT_ALGORITHMS)
                state["key"] = await _validate_client(self.client_auth_validator, state["chain"])
                state["stage"] = "proof"
            else:
                state["stage"] = "finished"
            return
        state = self._active_client_auth
        if state is None:
            raise ProtocolError("unsolicited client authentication proof")
        if kind == 15 and state["stage"] == "proof":
            expected = c.client_proof(self.exporter_secret, state["private"],
                                     c.public_bytes(state["key"]), bytes(state["transcript"]))
            if body[:2] != b"\xfe\x01" or not hmac.compare_digest(expected, body[4:]):
                raise ProtocolError("client MAC verification failed")
            state["transcript"].extend(frame)
            state["stage"] = "finished"
        elif kind == 20 and state["stage"] == "finished":
            if not c.verify_finished(self.receiver.secret, bytes(state["transcript"]), body):
                raise ProtocolError("post-handshake client Finished failed")
            if state["required"] and not state["chain"]:
                raise ProtocolError("client certificate required")
            self.authenticated_client = tuple(state["chain"]) if state["chain"] else None
            del self.pending_client_auth[state["context"]]
            self._active_client_auth = None
            state["private"] = None
            if not state["future"].done():
                state["future"].set_result(self.authenticated_client)
        else:
            raise ProtocolError("unexpected client authentication message")

    def exporter(self, label, context=b"", length=32):
        if self.exporter_secret is None:
            raise ProtocolError("exporter unavailable")
        return c.exporter(self.exporter_secret, label, context, length)

    async def send_handshake(self, message):
        async with self.send_lock:
            if self.closed or self.sent_close:
                raise ProtocolError("connection is closing")
            try:
                await self.wire.send_frame(message, self.sender)
            except BaseException:
                self.abort()
                raise

    async def key_update(self, request_peer=False):
        async with self.send_lock:
            if self.closed or self.sent_close:
                raise ProtocolError("connection is closing")
            try:
                await self.wire.send_frame(m.frame(24, bytes((int(bool(request_peer)),))), self.sender)
                self.sender.update()
            except BaseException:
                self.abort()
                raise

    async def _post_handshake(self, content):
        self.post_handshake.extend(content)
        if len(self.post_handshake) > MAX_BODY + 16384:
            raise ProtocolError("post-handshake message limit")
        while len(self.post_handshake) >= 4:
            size = int.from_bytes(self.post_handshake[1:4], "big") + 4
            if size > MAX_BODY + 4:
                raise ProtocolError("post-handshake message limit")
            if len(self.post_handshake) < size:
                return
            frame = bytes(self.post_handshake[:size]); del self.post_handshake[:size]
            kind, body = m.decode_frame(frame)
            if kind == 24:
                if self.post_handshake:
                    raise ProtocolError("KeyUpdate must end its record")
                self.receiver.update()
                if body == b"\x01":
                    await self.key_update(False)
            elif kind == 13:
                await self._answer_client_auth(frame)
            elif kind in (11, 15, 20):
                await self._receive_client_auth(frame)
            elif kind == 4 and self.resumption_secret is not None and self.name:
                identity, nonce, lifetime, age_add, limit = m.parse_new_session_ticket(body)
                if self.ticket_cache is not None:
                    self.ticket_cache.put(SessionTicket(identity,
                        c.label_expand(self.resumption_secret, "resumption", nonce, 32),
                        self.name, APPLICATION_PROTOCOL, time.monotonic(), lifetime,
                        age_add, limit, context=self.context,
                        certificate_chain=self.certificate_chain))
            else:
                raise ProtocolError("unexpected post-handshake message")

    def abort(self):
        self.closed = True
        self._clear_auth()
        transport = self.wire.writer.transport
        # A completed close can detach the transport from its event loop.
        # is_closing() alone is insufficient: close() can still be waiting
        # for a peer to read buffered output, which must be discarded here.
        if transport.is_closing() and transport.get_write_buffer_size() == 0:
            return
        transport.abort()

    async def recv(self):
        async with self.receive_lock:
            if self.received_close:
                return None
            if self.closed or self.read_cancelled:
                raise ProtocolError("connection is closed")
            try:
                while True:
                    content, kind = await self.wire.read_record(self.receiver)
                    if kind == 22:
                        await self._post_handshake(content)
                        continue
                    if self.post_handshake:
                        raise ProtocolError("interleaved fragmented handshake")
                    if kind == 23:
                        return content
                    if kind == 21 and content == b"\x01\x00":
                        self.received_close = True
                        self._clear_auth()
                        return None
                    raise ProtocolError("peer alert or unexpected post-handshake message")
            except asyncio.CancelledError:
                # A partial record cannot be resumed, but the independent send
                # direction may still send close_notify during relay cleanup.
                self.read_cancelled = True
                # Authentication cannot continue without this receive stream.
                # Do not retain verifier scalars/futures after interruption.
                if self.pending_client_auth:
                    self.abort()
                raise
            except BaseException:
                self.abort()
                raise

    async def send(self, content):
        async with self.send_lock:
            if self.closed or self.sent_close or self.read_cancelled:
                raise ProtocolError("connection is closing")
            try:
                chunks = (content[i:i + 16384] for i in range(0, len(content), 16384))
                for chunk in chunks:
                    if (self.sender.sequence >= c.MAX_RECORDS - 1
                            or self.sender.content_bytes + len(chunk) + 5 > c.MAX_CONTENT_BYTES):
                        await self.wire.send_frame(m.frame(24, b"\x00"), self.sender)
                        self.sender.update()
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
            self._clear_auth()
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
    return (c.derive_secret(root, "c hs traffic", transcript.snapshot()),
            c.derive_secret(root, "s hs traffic", transcript.snapshot()))


def application_keys(root, transcript):
    master = c.master_secret(root)
    return (c.derive_secret(master, "c ap traffic", transcript.snapshot()),
            c.derive_secret(master, "s ap traffic", transcript.snapshot()))


def check_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("handshake timeout must be finite and positive")


def _check_certificate_offer(chain, offered):
    if not offered:
        raise ProtocolError("missing signature_algorithms_cert")
    for index, der in enumerate(chain):
        cert = x509.load_der_x509_certificate(der)
        if index == len(chain) - 1 and cert.subject == cert.issuer:
            try:
                if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    cert.verify_directly_issued_by(cert)
                    continue  # Self-signed CA; actual anchor trust is checked separately.
            except (ValueError, x509.ExtensionNotFound):
                pass
        scheme = {"1.3.101.112": 0x0807, "1.2.840.10045.4.3.2": 0x0403}.get(
            cert.signature_algorithm_oid.dotted_string)
        if scheme not in offered:
            raise ProtocolError("certificate signature was not offered")


def _retry_psks_unchanged(first, second):
    """Only PSKs incompatible with this SHA-256 selection may disappear."""
    cursor = 0
    for identity, _, binder in first.psk_offers:
        if cursor < len(second.psk_offers) and second.psk_offers[cursor][0] == identity:
            if len(second.psk_offers[cursor][2]) != len(binder):
                return False
            cursor += 1
        elif len(binder) == 32:
            return False
    return cursor == len(second.psk_offers)


async def _validate_client(validator, chain):
    if validator is None:
        raise ProtocolError("client credential trust validator is required")
    result = validator(chain)
    if inspect.isawaitable(result):
        result = await result
    # This is a trust boundary supplied by the application: the callback must
    # check credential usage, lifetime, status, identity AND authorization.
    # No server-EKU validator or unauthenticated key extraction is substituted.
    if not isinstance(result, X25519PublicKey):
        raise ProtocolError("client trust validator must return an authorized X25519 public key")
    leaf_key = x509.load_der_x509_certificate(chain[0]).public_key()
    if c.public_bytes(result) != c.public_bytes(leaf_key):
        raise ProtocolError("authorized client key does not match the actual credential")
    return result


def _client_auth_messages(credentials, context, share, algorithms, exporter_secret, transcript):
    chain = credentials.chain_der if credentials is not None else []
    if chain:
        _check_certificate_offer(chain, algorithms)
        leaf = x509.load_der_x509_certificate(chain[0]).public_key()
        if c.public_bytes(leaf) != c.public_bytes(credentials.private_key):
            raise ProtocolError("client credential and private key mismatch")
        if c.public_bytes(credentials.private_key) == share:
            raise ProtocolError("client proof and verifier keys must be independent")
    cert = m.certificate(chain, context=context, allow_empty=True)
    transcript.extend(cert)
    result = [cert]
    if chain:
        cv = m.certificate_verify(c.client_proof(exporter_secret, credentials.private_key,
                                 share, bytes(transcript)), client=True)
        transcript.extend(cv)
        result.append(cv)
    return result


async def server_handshake(reader, writer, credentials, server_name, timeout=10, *,
                           ticket_store=None, max_early_data=0, on_early_data=None,
                           client_auth_validator=None, require_client_auth=False):
    check_timeout(timeout)
    if require_client_auth and client_auth_validator is None:
        raise ValueError("required client authentication needs an explicit trust validator")
    wire = Wire(reader, writer)
    wire.deadline = asyncio.get_running_loop().time() + timeout
    transcript = Transcript()
    try:
        async with asyncio.timeout(timeout):
            if await wire.exact(len(c.PREFACE)) != c.PREFACE:
                raise ProtocolError("not the TLS 2.0 experimental protocol")
            ch = await wire.receive_frame(1, boundary=True)
            hello = m.parse_client_hello(ch[4:])
            wire.allow_ccs = True
            if 44 in hello.extensions:
                raise ProtocolError("unsolicited cookie in initial ClientHello")
            if hello.name != server_name or hello.protocol != APPLICATION_PROTOCOL:
                raise ProtocolError("unsupported service identity or application protocol")
            sent_ccs = False
            if not hello.B:
                hrr = m.server_hello(b"", bytes(32), session_id=hello.session_id,
                                     group=hello.group, retry=True)
                await wire.send_frame(hrr)
                if hello.session_id:
                    await wire.send_ccs()
                    sent_ccs = True
                transcript.retry(ch, hrr)
                discarded = 0
                while True:
                    record = await wire.raw_record()
                    if record[0] == 20 and record[5:] == b"\x01":
                        continue
                    if record[0] == 22:
                        wire.pending.extend(record[5:]); break
                    discarded += len(record)
                    if not hello.early_data or record[0] != 23 or discarded > 1048576:
                        raise ProtocolError("unexpected record after retry")
                ch2 = await wire.receive_frame(1, boundary=True)
                second = m.parse_client_hello(ch2[4:])
                mutable = {21, 41, 42, 44, 51}
                stable = lambda h: {k: v for k, v in h.extension_values if k not in mutable}
                if (second.fixed_hello != hello.fixed_hello or stable(second) != stable(hello)
                        or not second.B or second.group != hello.group or second.early_data
                        or not _retry_psks_unchanged(hello, second) or 44 in second.extensions
                        or second.share_groups != (hello.group,)):
                    raise ProtocolError("ClientHello changed forbidden fields after retry")
                ch, hello = ch2, second
            static_public = c.public_bytes(credentials.private_key)
            if static_public in (hello.A, hello.B):
                raise ProtocolError("non-independent key shares")
            ticket_context = c.digest(b"".join(credentials.chain_der)
                + bytes((client_auth_validator is not None, require_client_auth)))
            ticket, selected_identity, psk_age, psk_binder = None, 0, 0, b""
            if ticket_store is not None:
                for index, (identity, age, proof) in enumerate(hello.psk_offers):
                    candidate = ticket_store.lookup(identity, server_name, APPLICATION_PROTOCOL, ticket_context)
                    if candidate is not None:
                        ticket, selected_identity, psk_age, psk_binder = candidate, index, age, proof
                        break
            if ticket is not None and not hmac.compare_digest(
                    c.binder(ticket.psk, transcript.snapshot() + ch[:-hello.binder_vector_size]), psk_binder):
                raise ProtocolError("PSK binder verification failed")
            authenticated_client = None
            if ticket is not None and client_auth_validator is not None:
                if ticket.client_certificate_chain:
                    try:
                        await _validate_client(client_auth_validator, ticket.client_certificate_chain)
                        authenticated_client = tuple(ticket.client_certificate_chain)
                    except (ProtocolError, ValueError):
                        ticket = None
                elif require_client_auth:
                    ticket = None
            accepted = bool(ticket is not None and hello.early_data and max_early_data
                and selected_identity == 0 and on_early_data is not None
                and ticket_store.consume_early(ticket, psk_age))
            if ticket is None:
                if len(hello.A) != 32:
                    raise ProtocolError("credential authentication requires auth_share")
                _check_certificate_offer(credentials.chain_der, hello.certificate_algorithms)
            transcript.add(ch)
            ephemeral, ephemeral_public = c.traffic_key(hello.group)
            if ephemeral_public in (hello.A, hello.B, static_public):
                raise ProtocolError("non-independent key shares")
            # Reject both zero agreements before sending a server flight.
            traffic_root = c.handshake_secret(c.traffic_dh(ephemeral, hello.group, hello.B),
                                              ticket.psk if ticket else c.ZERO32)
            auth_shared = c.dh(credentials.private_key, hello.A) if ticket is None else None
            sh = m.server_hello(ephemeral_public, os.urandom(32),
                                session_id=hello.session_id, resumed=ticket is not None,
                                group=hello.group, selected_identity=selected_identity)
            transcript.add(sh)
            client_secret, server_secret = handshake_keys(traffic_root, transcript)
            receiver = c.RecordState(client_secret, "open")
            sender = c.RecordState(server_secret, "seal")
            await wire.send_frame(sh)
            if hello.session_id and not sent_ccs:
                await wire.send_ccs()
            messages = [m.encrypted_extensions(APPLICATION_PROTOCOL, early_data=accepted)]
            client_auth_private = None
            if ticket is None and client_auth_validator is not None:
                client_auth_private = X25519PrivateKey.generate()
                if c.public_bytes(client_auth_private) in (static_public, ephemeral_public, hello.A, hello.B):
                    raise ProtocolError("client verifier key must be independent")
                messages.append(m.certificate_request(b"", c.public_bytes(client_auth_private)))
            if ticket is None:
                messages.append(m.certificate(credentials.chain_der))
            for message in messages:
                transcript.add(message)
                await wire.send_frame(message, sender)
            if ticket is None:
                auth_root = c.authentication_root(traffic_root, auth_shared, transcript.snapshot())
                cv = m.certificate_verify(c.server_proof(auth_root, transcript.snapshot()))
                transcript.add(cv)
                await wire.send_frame(cv, sender)
            sf = m.frame(20, c.finished(server_secret, transcript.snapshot()))
            transcript.add(sf)
            await wire.send_frame(sf, sender)
            client_app, server_app = application_keys(traffic_root, transcript)
            exporter = c.derive_secret(c.master_secret(traffic_root), "exp master", transcript.snapshot())
            if hello.early_data:
                early_receiver = (c.RecordState(c.derive_secret(c.extract(c.ZERO32, ticket.psk),
                    "c e traffic", c.PREFACE + ch), "open") if accepted else None)
                total, discarded = 0, 0
                while True:
                    record = await wire.raw_record()
                    if record[0] == 20 and record[5:] == b"\x01":
                        continue
                    if accepted:
                        content, kind = early_receiver.open(record)
                        if kind == 22:
                            wire.pending.extend(content)
                            eoed = await wire.receive_frame(5, early_receiver, boundary=True)
                            transcript.add(eoed)
                            await on_early_data(b"")
                            break
                        if kind != 23:
                            raise ProtocolError("early epoch carries only application data")
                        total += len(content)
                        if total > min(max_early_data, ticket.max_early_data):
                            raise ProtocolError("early data limit exceeded")
                        if content:
                            await on_early_data(content)
                    else:
                        result = receiver.try_open(record)
                        if result is not None:
                            content, kind = result
                            if kind != 22 or not content:
                                raise ProtocolError("expected authenticated handshake after early data")
                            wire.pending.extend(content)
                            break
                        discarded += len(record)
                        if record[0] != 23 or discarded > 1048576:
                            raise ProtocolError("rejected early data discard limit")
            client_chain = list(authenticated_client or [])
            if client_auth_private is not None:
                cert = await wire.receive_frame(11, receiver)
                client_chain = m.parse_certificate(cert[4:], allow_empty=True)
                transcript.add(cert)
                if client_chain:
                    _check_certificate_offer(client_chain, m.CERT_ALGORITHMS)
                    key = await _validate_client(client_auth_validator, client_chain)
                    cv = await wire.receive_frame(15, receiver)
                    expected = c.client_proof(exporter, client_auth_private,
                                             c.public_bytes(key), transcript.snapshot())
                    if cv[4:6] != b"\xfe\x01" or not hmac.compare_digest(expected, cv[8:]):
                        raise ProtocolError("initial client MAC verification failed")
                    transcript.add(cv)
            cf = await wire.receive_frame(20, receiver, boundary=True)
            if not c.verify_finished(client_secret, transcript.snapshot(), cf[4:]):
                raise ProtocolError("client Finished verification failed")
            transcript.add(cf)
            if require_client_auth and not client_chain:
                raise ProtocolError("client certificate required")
            authenticated_client = tuple(client_chain) if client_chain else None
            client_auth_private = None
            wire.check_deadline()
            channel = SecureChannel(wire, server_app, client_app, exporter_secret=exporter,
                resumed=ticket is not None, early_data_accepted=accepted,
                handshake_transcript=transcript.snapshot(), client_auth_validator=client_auth_validator,
                peer_post_handshake_auth=49 in hello.extensions, authenticated_client=authenticated_client)
            if ticket_store is not None and 45 in hello.extensions:
                resumption = c.derive_secret(c.master_secret(traffic_root), "res master", transcript.snapshot())
                message = ticket_store.issue(resumption, server_name, APPLICATION_PROTOCOL,
                    max_early_data if on_early_data is not None else 0, ticket_context, client_chain)
                if message is not None:
                    await channel.send_handshake(message)
            return channel
    except BaseException:
        writer.transport.abort()
        raise


async def client_handshake(reader, writer, server_name, trust_roots, *, revocation_policy, timeout=10,
                           ticket_cache=None, early_data=b"", cache_context=b"",
                           traffic_group=0x001d, force_retry=False, client_credentials=None,
                           post_handshake_auth=False):
    check_timeout(timeout)
    m.validate_name(server_name)
    wire = Wire(reader, writer)
    wire.deadline = asyncio.get_running_loop().time() + timeout
    transcript = Transcript()
    cache_fields = (b"".join(root.public_bytes(serialization.Encoding.DER) for root in trust_roots),
                    revocation_policy.encode("ascii"), cache_context,
                    b"\x01" + c.digest(b"".join(client_credentials.chain_der)) if client_credentials else b"\x00")
    roots_hash = c.digest(b"TLS20 client ticket context\x00" + b"".join(
        len(field).to_bytes(4, "big") + field for field in cache_fields))
    ticket = ticket_cache.take(server_name, APPLICATION_PROTOCOL, roots_hash) if ticket_cache else None
    try:
        async with asyncio.timeout(timeout):
            if ticket:
                try:
                    validate_chain(ticket.certificate_chain, trust_roots, server_name, revocation_policy)
                except ProtocolError:
                    # Stale authentication state is not authority to resume.
                    # A normal full handshake can validate a renewed credential.
                    ticket = None
            wire.check_deadline()
            offer_early = bool(ticket and early_data and len(early_data) <= ticket.max_early_data)
            auth_private = X25519PrivateKey.generate()
            traffic_private, traffic_public = c.traffic_key(traffic_group)
            auth_public = c.public_bytes(auth_private)
            if auth_public == traffic_public:
                raise ProtocolError("non-independent key shares")
            if (client_credentials is not None and c.public_bytes(client_credentials.private_key)
                    in (auth_public, traffic_public)):
                raise ProtocolError("client credential key must be independent of ephemeral keys")
            random = os.urandom(32)
            options = {"identity": ticket.identity, "age": ticket.obfuscated_age(),
                       "binder": bytes(32), "early_data": offer_early} if ticket else {}
            options.update(group=traffic_group, empty_share=force_retry, post_handshake_auth=post_handshake_auth)
            ch = m.client_hello(auth_public, traffic_public, server_name, random, **options)
            if ticket:
                options["binder"] = c.binder(ticket.psk, c.PREFACE + ch[:-35])
                ch = m.client_hello(auth_public, traffic_public, server_name, random, **options)
            transcript.add(ch)
            writer.write(c.PREFACE)
            await wire.send_frame(ch)
            wire.allow_ccs = True
            if offer_early:
                early_sender = c.RecordState(c.derive_secret(c.extract(c.ZERO32, ticket.psk),
                    "c e traffic", transcript.snapshot()), "seal")
                for offset in range(0, len(early_data), 16384):
                    writer.write(early_sender.seal(early_data[offset:offset+16384], 23))
                await writer.drain()
            sh = await wire.receive_frame(2, boundary=True)
            ephemeral_public, sid, resumed, group, retry, cookie = m.parse_server_hello(sh[4:], details=True)
            if retry:
                if sid or not force_retry and group == traffic_group:
                    raise ProtocolError("useless HelloRetryRequest")
                transcript.retry(ch, sh)
                if group:
                    traffic_private, traffic_public = c.traffic_key(group)
                    traffic_group = group
                options.update(group=traffic_group, empty_share=False, early_data=False, cookie=cookie)
                if ticket:
                    options.update(age=ticket.obfuscated_age(), binder=bytes(32))
                ch = m.client_hello(auth_public, traffic_public, server_name, random, **options)
                if ticket:
                    options["binder"] = c.binder(ticket.psk, transcript.snapshot() + ch[:-35])
                    ch = m.client_hello(auth_public, traffic_public, server_name, random, **options)
                transcript.add(ch)
                await wire.send_frame(ch)
                offer_early = False
                sh = await wire.receive_frame(2, boundary=True)
                ephemeral_public, sid, resumed, group, retry, cookie = m.parse_server_hello(sh[4:], details=True)
                if retry:
                    raise ProtocolError("second HelloRetryRequest")
            if sid or resumed and not ticket:
                raise ProtocolError("unsolicited session selection")
            if group != traffic_group:
                raise ProtocolError("server selected an unoffered share")
            if ephemeral_public in (auth_public, traffic_public):
                raise ProtocolError("non-independent key shares")
            transcript.add(sh)
            traffic_root = c.handshake_secret(c.traffic_dh(traffic_private, group, ephemeral_public),
                                              ticket.psk if resumed else c.ZERO32)
            client_secret, server_secret = handshake_keys(traffic_root, transcript)
            sender = c.RecordState(client_secret, "seal")
            receiver = c.RecordState(server_secret, "open")
            ee = await wire.receive_frame(8, receiver)
            accepted = m.parse_encrypted_extensions(ee[4:], APPLICATION_PROTOCOL, offered_early=offer_early)
            if accepted and not resumed:
                raise ProtocolError("early data requires selected PSK")
            transcript.add(ee)
            chain_der = ticket.certificate_chain if resumed else []
            client_auth_request = None
            if not resumed:
                cert = await wire.receive_frame((11, 13), receiver)
                if cert[0] == 13:
                    client_auth_request = m.parse_certificate_request(cert[4:])
                    if client_auth_request[0]:
                        raise ProtocolError("initial certificate request context must be empty")
                    transcript.add(cert)
                    cert = await wire.receive_frame(11, receiver)
                chain_der = m.parse_certificate(cert[4:])
                _check_certificate_offer(chain_der, m.CERT_ALGORITHMS)
                static_key = validate_chain(chain_der, trust_roots, server_name, revocation_policy)
                wire.check_deadline()
                static_public = c.public_bytes(static_key)
                if static_public in (auth_public, traffic_public, ephemeral_public):
                    raise ProtocolError("non-independent certified key")
                transcript.add(cert)
                auth_root = c.authentication_root(traffic_root, c.dh(auth_private, static_public), transcript.snapshot())
                cv = await wire.receive_frame(15, receiver)
                if cv[4:6] != b"\xfe\x00" or not c.verify_proof(auth_root, transcript.snapshot(), cv[8:]):
                    raise ProtocolError("server authentication verification failed")
                transcript.add(cv)
            sf = await wire.receive_frame(20, receiver, boundary=True)
            if not c.verify_finished(server_secret, transcript.snapshot(), sf[4:]):
                raise ProtocolError("server Finished verification failed")
            transcript.add(sf)
            client_app, server_app = application_keys(traffic_root, transcript)
            exporter = c.derive_secret(c.master_secret(traffic_root), "exp master", transcript.snapshot())
            if accepted:
                eoed = m.frame(5, b"")
                await wire.send_frame(eoed, early_sender)
                transcript.add(eoed)
            if client_auth_request is not None:
                context, share, algorithms = client_auth_request
                messages = _client_auth_messages(client_credentials, context, share,
                    algorithms, exporter, transcript.data)
                for message in messages:
                    await wire.send_frame(message, sender)
            cf = m.frame(20, c.finished(client_secret, transcript.snapshot()))
            await wire.send_frame(cf, sender)
            transcript.add(cf)
            wire.check_deadline()
            return SecureChannel(wire, client_app, server_app, exporter_secret=exporter,
                resumption_secret=c.derive_secret(c.master_secret(traffic_root), "res master", transcript.snapshot()),
                ticket_cache=ticket_cache, name=server_name, context=roots_hash, certificate_chain=chain_der,
                resumed=resumed, early_data_accepted=accepted, handshake_transcript=transcript.snapshot(),
                client_credentials=client_credentials, local_post_handshake_auth=post_handshake_auth)
    except BaseException:
        writer.transport.abort()
        raise
