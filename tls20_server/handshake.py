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
from .errors import ProtocolError, PeerClosed
from .pki import (validate_chain, certificate_signature_scheme, SUPPORTED_CERTIFICATE_ALGORITHMS,
                  supported_certificate_algorithms, certificate_public_key, verify_public_signature,
                  SM2_CERTIFICATE_IDENTIFIER, find_certificate_issuer, certificate_extensions)
from .tickets import SessionTicket
from .diagnostics import emit as emit_diagnostic
from .psk import ExternalPSK
from .credential_profiles import CredentialPolicy, resolve_peer, parse_x25519_spki, validate_delegation
from .credential_cache import (compress_certificate, decompress_certificate, material_hash,
    cached_certificate_body, resolve_cached_certificate, request_template_hash,
    cached_request_body, resolve_cached_request)
from .handshake_options import client_controls, server_controls, client_control_selection
from .exporter_access import expose as expose_exporter
from .secret_lifecycle import HandshakeSecrets, handshake_boundary, protocol_boundary
from .credential_selection import (encode_certificate_authorities, encode_oid_filters,
    preferred_credentials, match_credentials)
from types import SimpleNamespace


MAX_BODY = 262144
MAX_TRANSCRIPT = 1048576
MAX_HANDSHAKE_RECORDS = 4096
APPLICATION_PROTOCOL = b"http/1.1"


class _WriteStopped(ProtocolError):
    """A terminal event revoked writes; its owner completes alert/cleanup."""


class Transcript:
    def __init__(self):
        self.data = bytearray(c.PREFACE)

    def add(self, message):
        if len(self.data) + len(message) > MAX_TRANSCRIPT:
            raise ProtocolError("handshake transcript limit exceeded")
        self.data.extend(message)

    def snapshot(self):
        return bytes(self.data)

    def retry(self, client_hello, retry, hash_name="sha256"):
        digest = c.digest(client_hello, hash_name)
        self.data = bytearray(c.PREFACE + b"\xfe" + len(digest).to_bytes(3, "big") + digest + retry)


class Wire:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.pending = bytearray()
        self.handshake_records = 0
        self.handshake = True
        self.deadline = None
        self.allow_ccs = False
        self.write_guard = None

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
            raise ProtocolError("invalid record framing version", alert=47)
        if length > (16640 if kind == 23 else 16384):
            raise ProtocolError("invalid record length", alert=22)
        if length == 0 and kind in (21, 22):
            raise ProtocolError("empty handshake or alert record", alert=10)
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
                raise ProtocolError("invalid plaintext record", alert=10)
            return fragment, kind
        return state.open(record)

    async def send_frame(self, message, state=None):
        maximum = min(16384, state.record_limit - 1) if state else 16384
        for offset in range(0, len(message), maximum):
            self.check_deadline()
            if self.write_guard is not None:
                self.write_guard()
            fragment = message[offset:offset + maximum]
            self.count()
            if state is None:
                wire = b"\x16\x03\x03" + len(fragment).to_bytes(2, "big") + fragment
            else:
                wire = state.seal(fragment, 22)
            self.writer.write(wire)
            await self.writer.drain()

    async def fatal(self, error, state=None):
        """Best-effort fatal alert in the active write epoch, then orderly EOF."""
        if isinstance(error, PeerClosed):
            self.writer.close()
            return
        try:
            content = bytes((2, error.alert))
            self.writer.write(state.seal(content, 21) if state else b"\x15\x03\x03\x00\x02" + content)
            async with asyncio.timeout(0.5):
                await self.writer.drain()
            self.writer.close()
        except (OSError, ValueError, TimeoutError):
            self.writer.transport.abort()
        except BaseException:
            self.writer.transport.abort()
            raise

    async def send_ccs(self):
        self.check_deadline()
        self.count()
        self.writer.write(b"\x14\x03\x03\x00\x01\x01")
        await self.writer.drain()

    def process_alert(self, fragment):
        """Handle a plaintext or authenticated handshake-epoch alert."""
        if len(fragment) != 2:
            raise ProtocolError("malformed alert", alert=50)
        if fragment[1] not in (0, 90):
            raise PeerClosed("peer aborted the handshake", alert=fragment[1])
        if self.pending:
            raise ProtocolError("alert interleaves a fragmented handshake", alert=10)
        if fragment[1] == 0:
            raise PeerClosed("peer closed the handshake", alert=0)
        # user_canceled is advisory; keep reading for the peer's close_notify.

    async def receive_frame(self, expected, state=None, *, boundary=False):
        while True:
            self.check_deadline()
            if len(self.pending) >= 4:
                kind = self.pending[0]
                length = int.from_bytes(self.pending[1:4], "big")
                expected_types = (expected,) if isinstance(expected, int) else expected
                if kind not in expected_types:
                    raise ProtocolError("unexpected handshake message", alert=10)
                if length > MAX_BODY:
                    raise ProtocolError("oversized handshake message", alert=50)
                if kind == 20 and length not in (32, 48):
                    raise ProtocolError("invalid authenticator size", alert=50)
                if len(self.pending) >= length + 4:
                    message = bytes(self.pending[:length + 4])
                    del self.pending[:length + 4]
                    if boundary and self.pending:
                        raise ProtocolError("handshake bytes cross a key transition", alert=10)
                    m.decode_frame(message)
                    return message
            fragment, kind = await self.read_record(state)
            if kind == 21:
                self.process_alert(fragment)
                continue
            if kind != 22 or not fragment:
                raise ProtocolError("application data before authentication", alert=10)
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
                 authenticated_client=None, cipher_suite=0x1301, protocol=APPLICATION_PROTOCOL,
                 role="client", enable_authenticators=False, auth_share_secret=None,
                 peer_auth_share=b"", local_capabilities=(), peer_capabilities=(),
                 early_exporter_secret=None, psk_provenance="credential",
                 receive_record_limit=16385, send_record_limit=16385,
                 certificate_type=0, certificate_extensions=(), cache_types=(),
                 cached_request_templates=(), peer_cached_objects=(), client_request_templates=(),
                 client_credential_policy=None, client_certificate_type=0, client_auth_offers=(),
                 heartbeat_local_mode=None, heartbeat_peer_mode=None,
                 selected_external_psk_identity=b"", bootstrap_binding=None, bootstrap_authorization=None,
                 peer_authenticated=True, client_credential_candidates=(), native_provider=None, pake_identity=b"",
                 credential_expires_at=None, allowed_psk_modes=(1, 0),
                 certificate_feature_offers=(), certificate_features=()):
        if wire.pending:
            raise ProtocolError("leftover handshake bytes")
        self.wire = wire
        self.wire.handshake = False
        self.wire.deadline = None
        self.cipher_suite = cipher_suite
        self.protocol, self.role = protocol, role
        self.certificate_feature_offers = tuple(certificate_feature_offers)
        self.certificate_features = tuple(certificate_features)
        self.handshake_completed = True
        self.peer_authenticated = bool(peer_authenticated)
        self.enable_authenticators = enable_authenticators
        self.auth_share_secret = auth_share_secret if enable_authenticators else None
        self.peer_auth_share = peer_auth_share if enable_authenticators else b""
        self.local_capabilities, self.peer_capabilities = local_capabilities, peer_capabilities
        self.early_exporter_secret = early_exporter_secret
        self.psk_provenance = psk_provenance
        self.pake_identity = pake_identity
        self.selected_external_psk_identity = selected_external_psk_identity
        self.allowed_psk_modes = tuple(dict.fromkeys(allowed_psk_modes))
        self.bootstrap_binding = bootstrap_binding
        self.bootstrap_authorization = bootstrap_authorization
        self._authenticators = None
        self.suite = c.suite(cipher_suite)
        self.schedule = c.KeySchedule(c.hash_context(self.suite.hash_name,native_provider))
        self.native_provider = native_provider
        self.confidential = self.suite.confidential
        from .optional_controls import Heartbeat
        if (heartbeat_local_mode is None) != (heartbeat_peer_mode is None):
            raise ValueError("heartbeat requires both negotiated modes")
        self._heartbeat = (None if heartbeat_local_mode is None else Heartbeat(
            heartbeat_local_mode, heartbeat_peer_mode,
            receive_limit=receive_record_limit, send_limit=send_record_limit))
        self._heartbeat_future = None
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
        self.certificate_type, self.certificate_extensions = certificate_type, certificate_extensions
        self.credential_expires_at = credential_expires_at
        self.cache_types, self.cached_request_templates = tuple(cache_types), tuple(cached_request_templates)
        self.peer_cached_objects = tuple(peer_cached_objects)
        self.client_request_templates = tuple(client_request_templates)
        self.resumed, self.early_data_accepted = resumed, early_data_accepted
        self.post_handshake = bytearray()
        self.handshake_transcript = handshake_transcript
        self.client_credentials, self.client_auth_validator = client_credentials, client_auth_validator
        self.client_credential_candidates = tuple(client_credential_candidates) or ((client_credentials,) if client_credentials else ())
        self.client_credential_policy, self.client_certificate_type = client_credential_policy, client_certificate_type
        self.client_auth_offers = tuple(client_auth_offers)
        self.peer_post_handshake_auth, self.local_post_handshake_auth = peer_post_handshake_auth, local_post_handshake_auth
        self.authenticated_client = authenticated_client
        self.pending_client_auth = {}
        self._active_client_auth = None
        self._seen_auth_contexts = set()
        self._key_update_requested = False
        self._key_update_response_pending = False
        self._fatal_alert_done = None
        # Build owned record states last. Either constructor may fail, leaving
        # a partial channel reachable through a retained traceback.
        try:
            self.sender = c.RecordState(send_secret, "seal", cipher_suite, send_record_limit, provider=self.native_provider)
            self.receiver = c.RecordState(receive_secret, "open", cipher_suite, receive_record_limit, provider=self.native_provider)
        except BaseException:
            sender = getattr(self, "sender", None)
            if sender is not None:
                sender.close()
            self.auth_share_secret = None
            self.exporter_secret = self.resumption_secret = self.early_exporter_secret = None
            raise
        self.wire.write_guard = self._check_write_open

    def _check_write_open(self):
        if self.closed or self.sent_close or self.read_cancelled:
            raise _WriteStopped("connection is closing")

    def _clear_auth(self):
        for access in getattr(self, "_exporter_accesses", ()):
            access.close()
        self._exporter_accesses = ()
        self.auth_share_secret = None
        if self._heartbeat is not None:
            self._heartbeat.cancel()
        if self._heartbeat_future is not None and not self._heartbeat_future.done():
            self._heartbeat_future.cancel()
        self._heartbeat_future = None
        if self._authenticators is not None:
            self._authenticators.close()
        pending, self.pending_client_auth = self.pending_client_auth, {}
        self._active_client_auth = None
        for state in pending.values():
            state["private"] = None
            if not state["future"].done():
                state["future"].cancel()

    def _clear_connection_secrets(self, *, keep_sender=False):
        """Release connection-owned secret references, not shared provisioning.

        An interrupted read retains only the sending state needed to flush an
        authenticated close_notify. Python cannot guarantee physical erasure.
        """
        self._key_update_response_pending = False
        self._clear_auth()
        self.receiver.close()
        if not keep_sender:
            self.sender.close()
        self.exporter_secret = self.resumption_secret = self.early_exporter_secret = None
        self.client_credentials = self.client_credential_policy = self.client_auth_validator = None
        self.client_credential_candidates = ()
        self.ticket_cache = self.native_provider = self.schedule = self._authenticators = None
        self.post_handshake.clear()
        self.handshake_transcript = b""

    @protocol_boundary
    async def request_client_auth(self, *, required=False, max_pending=128,
                                  certificate_authorities=None, oid_filters=None,
                                  certificate_algorithms=None, delegation_signature_algorithms=None,
                                  certificate_evidence_extensions=None):
        """Return a Future completed by recv(); application must keep reading.

        max_pending is a local memory budget, not a TLS protocol maximum.
        Canceling the Future aborts the connection, consuming its private state.
        """
        if (self.protocol == b"h2" or not self.peer_post_handshake_auth
                or self.client_auth_validator is None and self.client_credential_policy is None
                or not self.handshake_transcript or self.closed or self.read_cancelled
                or self.received_close or self.sent_close):
            raise ProtocolError("post-handshake client authentication is unavailable")
        if max_pending < 1 or len(self.pending_client_auth) >= max_pending:
            raise ProtocolError("local pending authentication budget")
        context = os.urandom(32)
        while context in self.pending_client_auth:
            context = os.urandom(32)
        private = X25519PrivateKey.generate()
        request_offers = dict(self.client_auth_offers)
        if certificate_evidence_extensions is not None:
            evidence_offers = _client_evidence_offers(certificate_evidence_extensions,
                self.client_credential_policy, (self.client_certificate_type,))
            request_offers.pop(5, None)
            request_offers.update(evidence_offers)
        signature_provider = getattr(self.client_credential_policy, "signature_provider", None) or self.native_provider
        if certificate_algorithms is not None:
            if self.client_certificate_type != 0:
                raise ValueError("certificate signature policy requires X.509 credentials")
            algorithms = _signature_preferences(certificate_algorithms, signature_provider)
            request_offers[50] = m._vec(b"".join(value.to_bytes(2, "big") for value in algorithms), 2)
        if delegation_signature_algorithms is not None:
            if 34 not in request_offers:
                raise ValueError("delegation signature policy requires an enabled delegation verifier")
            algorithms = _signature_preferences(delegation_signature_algorithms, signature_provider)
            request_offers[0xff04] = m._vec(b"".join(value.to_bytes(2, "big") for value in algorithms), 2)
        if certificate_authorities is not None:
            request_offers.pop(47, None)
            if certificate_authorities:
                request_offers[47] = encode_certificate_authorities(certificate_authorities)
        if oid_filters is not None:
            request_offers[48] = encode_oid_filters(oid_filters)
        request = m.certificate_request(context, c.public_bytes(private),
            algorithms=(m._u16_list(request_offers[50]) if 50 in request_offers else
                        supported_certificate_algorithms(self.native_provider)) if self.client_certificate_type == 0 else (),
            extra_extensions=tuple(pair for pair in request_offers.items() if pair[0] != 50))
        offers = dict(m.parse_certificate_request(request[4:], details=True)[3])
        if 2 in self.cache_types and (2, request_template_hash(_request_extension_block(request))) in self.peer_cached_objects:
            request = m.frame(252, cached_request_body(context, _request_extension_block(request), c.public_bytes(private)))
        future = asyncio.get_running_loop().create_future()
        state = {"private": private, "future": future, "required": required,
                 "transcript": bytearray(self.handshake_transcript + request),
                 "stage": "certificate", "chain": [], "key": None, "context": context,
                 "offers": offers, "metadata": ()}
        future.add_done_callback(lambda done: self.abort() if done.cancelled() and not self.closed else None)
        self.pending_client_auth[context] = state
        try:
            await self.send_handshake(request)
        except _WriteStopped:
            raise
        except BaseException:
            self.abort()
            raise
        return future

    async def _answer_client_auth(self, request):
        if not self.local_post_handshake_auth:
            raise ProtocolError("unsolicited post-handshake client-auth request", alert=10)
        context, share, algorithms, request_extensions = _decode_request(request,
            cache_enabled=2 in self.cache_types, templates=self.cached_request_templates)
        if not context or context in self._seen_auth_contexts:
            raise ProtocolError("empty or repeated post-handshake client-auth context", alert=47)
        if len(self._seen_auth_contexts) >= 4096:
            raise ProtocolError("local client-auth context budget exceeded")
        self._seen_auth_contexts.add(context)
        pool = ((self.client_credentials,) if self.client_credentials else ()) + self.client_credential_candidates
        candidates = preferred_credentials((value for value in pool
            if value.credential_type == self.client_certificate_type), request_extensions,
            role="client", signature_provider=self.native_provider)
        credential = candidates[0] if candidates else None
        transcript = bytearray(self.handshake_transcript + request)
        async with self.send_lock:
            try:
                for message in _client_auth_messages(credential, context, share,
                                                     algorithms, self.exporter_secret, transcript,
                                                     request_extensions=request_extensions.items(),
                                                     hash_name=self.schedule.hash_name, signature_provider=self.native_provider):
                    await self.wire.send_frame(message, self.sender)
                await self.wire.send_frame(m.frame(20, self.schedule.finished(self.sender.secret, bytes(transcript))), self.sender)
            except BaseException:
                self.abort()
                raise

    async def _receive_client_auth(self, frame):
        kind, body = m.decode_frame(frame)
        if not self.pending_client_auth:
            raise ProtocolError("unsolicited client authentication response", alert=10)
        if kind in (11, 25):
            if self._active_client_auth is not None:
                raise ProtocolError("interleaved client authentication response", alert=10)
            parsed_body = decompress_certificate(body, _compression_offer(dict(self.client_auth_offers)[27])) if kind == 25 and 27 in dict(self.client_auth_offers) else body
            if kind == 25 and 27 not in dict(self.client_auth_offers):
                raise ProtocolError("unoffered client certificate compression", alert=47)
            context = m._Reader(parsed_body).vector(1)
            state = self.pending_client_auth.get(context)
            if state is None:
                raise ProtocolError("unknown client authentication context", alert=47)
            if state["stage"] != "certificate":
                raise ProtocolError("unexpected client authentication certificate", alert=10)
            state["chain"], state["metadata"] = m.parse_certificate(parsed_body, context=context, allow_empty=True, details=True)
            _check_credential_extension_offers(state["metadata"], state["offers"])
            state["transcript"].extend(frame)
            self._active_client_auth = state
            if state["chain"]:
                _check_peer_filters(state["chain"], self.client_certificate_type, state["offers"])
                if self.client_credential_policy is not None:
                    state["key"] = _resolve_credential(state["chain"], state["metadata"], role="client",
                        credential_type=self.client_certificate_type, policy=self.client_credential_policy,
                        offers=state["offers"].items(), negotiated_extensions=_certificate_feature_state(
                            state["offers"].items(), certificate_message=frame[0],
                            certificate_metadata=state["metadata"], authenticated_by_mac=True)).public_key
                else:
                    if self.client_certificate_type != 0 or any(state["metadata"]):
                        raise ProtocolError("extended client credentials require an explicit policy")
                    _check_certificate_offer(state["chain"], m._u16_list(state["offers"][50]), self.native_provider)
                    state["key"] = await _validate_client(self.client_auth_validator, state["chain"])
                state["stage"] = "proof"
            else:
                state["stage"] = "finished"
            return
        state = self._active_client_auth
        if state is None:
            raise ProtocolError("unsolicited client authentication proof", alert=10)
        if kind == 15 and state["stage"] == "proof":
            expected = self.schedule.client_proof(self.exporter_secret, state["private"],
                                     c.public_bytes(state["key"]), bytes(state["transcript"]))
            if body[:2] != b"\xfe\x01" or not hmac.compare_digest(expected, body[4:]):
                raise ProtocolError("client MAC verification failed", alert=51)
            state["transcript"].extend(frame)
            state["stage"] = "finished"
        elif kind == 20 and state["stage"] == "finished":
            if not self.schedule.verify_finished(self.receiver.secret, bytes(state["transcript"]), body):
                raise ProtocolError("post-handshake client Finished failed", alert=51)
            if state["required"] and not state["chain"]:
                raise ProtocolError("client certificate required", alert=116)
            self.authenticated_client = tuple(state["chain"]) if state["chain"] else None
            del self.pending_client_auth[state["context"]]
            self._active_client_auth = None
            state["private"] = None
            if not state["future"].done():
                state["future"].set_result(self.authenticated_client)
        else:
            raise ProtocolError("unexpected client authentication message", alert=10)

    def exporter(self, label, context=b"", length=32):
        if self.exporter_secret is None:
            raise ProtocolError("exporter unavailable")
        return self.schedule.exporter(self.exporter_secret, label, context, length)

    def early_exporter(self, label, context=b"", length=32):
        """Early exporter is replayable, and never implies fresh peer authentication."""
        if self.early_exporter_secret is None:
            raise ProtocolError("early exporter unavailable")
        return self.schedule.exporter(self.early_exporter_secret, label, context, length)

    def authenticators(self):
        from .application_auth import AuthenticatorManager
        if not self.enable_authenticators:
            raise ProtocolError("application authenticators were not enabled")
        if self._authenticators is None:
            self._authenticators = AuthenticatorManager(self)
        return self._authenticators

    def channel_binding(self):
        return self.exporter("EXPORTER-Channel-Binding", b"", 32)

    async def _send_heartbeat_locked(self, content):
        # One complete heartbeat per record, never a handshake-type24 frame.
        self._check_write_open()
        await self._flush_key_update_response_locked()
        if (self.sender.sequence >= c.MAX_RECORDS - 1
                or self.sender.content_bytes + len(content) + 5 > c.MAX_CONTENT_BYTES):
            await self._key_update_locked(False)
        self._check_write_open()
        self.wire.writer.write(self.sender.seal(content, 24))
        await self.wire.writer.drain()

    async def request_heartbeat(self, payload=None, *, padding=16):
        """Return a Future completed by recv(); the application keeps reading.

        The application controls frequency and timeout. Cancelling the future
        abandons the probe without destroying a healthy TCP connection. No
        automatic timer/retransmission runs and no heartbeat uses early keys.
        """
        async with self.send_lock:
            if (self._heartbeat is None or not self.handshake_completed or self.closed
                    or self.sent_close or self.received_close or self.read_cancelled):
                raise ProtocolError("heartbeat unavailable", alert=10)
            content = self._heartbeat.request(payload, padding=padding)
            future = asyncio.get_running_loop().create_future()
            self._heartbeat_future = future
            def cancelled(done):
                if done.cancelled() and self._heartbeat_future is done:
                    self._heartbeat.cancel()
                    self._heartbeat_future = None
            future.add_done_callback(cancelled)
            try:
                await self._send_heartbeat_locked(content)
            except _WriteStopped:
                raise
            except BaseException:
                self.abort()
                raise
            return future

    async def _receive_heartbeat(self, content):
        if self._heartbeat is None:
            raise ProtocolError("unnegotiated heartbeat", alert=10)
        response = self._heartbeat.receive(content)
        if response is not None and not self.sent_close:
            async with self.send_lock:
                await self._send_heartbeat_locked(response)
        future = self._heartbeat_future
        if self._heartbeat.matched_response is not None and future is not None:
            self._heartbeat_future = None
            if not future.done():
                future.set_result(self._heartbeat.matched_response)

    async def send_handshake(self, message):
        async with self.send_lock:
            self._check_write_open()
            try:
                await self.wire.send_frame(message, self.sender)
            except _WriteStopped:
                raise
            except BaseException:
                self.abort()
                raise

    async def key_update(self, request_peer=False):
        async with self.send_lock:
            if self.closed or self.sent_close or self.read_cancelled:
                raise ProtocolError("connection is closing")
            if request_peer and self._key_update_requested:
                raise ProtocolError("a peer key update is already pending")
            if self.sender.epoch >= c.MAX_SEND_EPOCH:
                raise ProtocolError("sending key-update epoch exhausted", alert=80)
            try:
                await self._key_update_locked(bool(request_peer))
            except BaseException:
                self.abort()
                raise

    async def _key_update_locked(self, request_peer):
        # Check before emitting a record: announcing an epoch we cannot enter
        # would desynchronize the peer. The caller owns send_lock.
        if self.sender.epoch >= c.MAX_SEND_EPOCH:
            raise ProtocolError("sending key-update epoch exhausted", alert=80)
        self._check_write_open()
        if request_peer:
            if self._key_update_requested:
                raise ProtocolError("a peer key update is already pending")
            # drain() can yield to a simultaneous peer response; record the
            # request before yielding so that response can clear it safely.
            self._key_update_requested = True
        else:
            # Commit the response before drain can yield to another request.
            # A later request then remains pending for a later response.
            self._key_update_response_pending = False
        try:
            await self.wire.send_frame(m.frame(24, bytes((int(request_peer),))), self.sender)
            self.sender.update()
        except BaseException:
            # The peer may already have consumed the KeyUpdate even if our
            # drain was interrupted. Do not retain an ambiguous sending epoch.
            self.abort()
            raise

    async def _flush_key_update_response_locked(self):
        while self._key_update_response_pending:
            if self.sender.epoch >= c.MAX_SEND_EPOCH:
                self._key_update_response_pending = False
            else:
                await self._key_update_locked(False)

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
            if frame[0] not in (4, 11, 13, 15, 20, 24, 25, 252):
                raise ProtocolError("unexpected post-handshake message", alert=10)
            kind, body = m.decode_frame(frame)
            if self._active_client_auth is not None and kind not in (15, 20):
                raise ProtocolError("interleaved client authentication response", alert=10)
            if kind == 24:
                if self.post_handshake:
                    raise ProtocolError("KeyUpdate must end its record", alert=10)
                self.receiver.update()
                self._key_update_requested = False
                if body == b"\x01" and self.sender.epoch < c.MAX_SEND_EPOCH:
                    self._key_update_response_pending = True
                    # A concurrent upload owns send_lock across drain(). Do
                    # not stall the receive stream behind it: that writer must
                    # service this flag before its next application record.
                    if not self.send_lock.locked():
                        async with self.send_lock:
                            await self._flush_key_update_response_locked()
            elif kind in (13, 252):
                await self._answer_client_auth(frame)
            elif kind in (11, 15, 20, 25):
                await self._receive_client_auth(frame)
            elif kind == 4 and self.resumption_secret is not None and self.name:
                identity, nonce, lifetime, age_add, limit = m.parse_new_session_ticket(body)
                if self.ticket_cache is not None:
                    self.ticket_cache.put(SessionTicket(identity,
                        self.schedule.label_expand(self.resumption_secret, "resumption", nonce, self.suite.hash_length),
                        self.name, self.protocol, time.monotonic(), lifetime,
                        age_add, limit, context=self.context,
                        certificate_chain=self.certificate_chain,
                        cipher_suite=({0xc0b0: 0x1301, 0xc0b1: 0x1302, 0xc0b2: 0x1304, 0xc0b3: 0x1302}.get(self.cipher_suite, self.cipher_suite)
                                      if self.pake_identity else self.cipher_suite),
                        certificate_type=self.certificate_type, certificate_extensions=self.certificate_extensions,
                        client_certificate_type=self.client_certificate_type,
                        external_psk_identity=self.selected_external_psk_identity,
                        pake_identity=self.pake_identity,
                        credential_expires_at=self.credential_expires_at,
                        allowed_psk_modes=self.allowed_psk_modes,
                        certificate_feature_offers=self.certificate_feature_offers,
                        certificate_features=self.certificate_features,
                        record_size_limit=self.sender.record_limit))
            else:
                raise ProtocolError("unexpected post-handshake message", alert=10)

    def abort(self):
        self.closed = True
        self._clear_connection_secrets()
        transport = self.wire.writer.transport
        # A completed close can detach the transport from its event loop.
        # is_closing() alone is insufficient: close() can still be waiting
        # for a peer to read buffered output, which must be discarded here.
        if transport.is_closing() and transport.get_write_buffer_size() == 0:
            return
        transport.abort()

    @protocol_boundary
    async def recv(self):
        async with self.receive_lock:
            if self.received_close:
                return None
            if self.closed or self.read_cancelled:
                raise ProtocolError("connection is closed")
            try:
                while True:
                    content, kind = await self.wire.read_record(self.receiver)
                    if kind == 21:
                        if len(content) != 2:
                            raise ProtocolError("malformed alert", alert=50)
                        if content[1] not in (0, 90):
                            raise PeerClosed("peer fatal alert", alert=content[1])
                    if kind == 22:
                        await self._post_handshake(content)
                        continue
                    if self.post_handshake:
                        raise ProtocolError("interleaved fragmented handshake", alert=10)
                    if self._active_client_auth is not None and (kind != 21 or content[1] == 90):
                        raise ProtocolError("interleaved client authentication response", alert=10)
                    if kind == 24:
                        await self._receive_heartbeat(content)
                        continue
                    if kind == 23:
                        return content
                    if kind == 21 and len(content) == 2 and content[1] == 0:
                        self.received_close = True
                        self._clear_auth()
                        self.receiver.close()
                        return None
                    if kind == 21 and len(content) == 2 and content[1] == 90:
                        continue  # user_canceled does not terminate the connection.
                    raise ProtocolError("peer alert or unexpected post-handshake message")
            except asyncio.CancelledError:
                # A partial record cannot be resumed, but the independent send
                # direction may still send close_notify during relay cleanup.
                self.read_cancelled = True
                # Authentication cannot continue without this receive stream.
                # Do not retain verifier scalars/futures after interruption.
                if self.pending_client_auth:
                    self.abort()
                else:
                    self._clear_connection_secrets(keep_sender=True)
                raise
            except ProtocolError as error:
                # Seal the connection before awaiting its writer. Otherwise an
                # upload blocked in drain can keep emitting application or
                # fragmented handshake records after this fatal condition.
                self.closed = True
                self._clear_connection_secrets(keep_sender=True)
                if not isinstance(error, PeerClosed):
                    self._fatal_alert_done = asyncio.Event()
                try:
                    if isinstance(error, PeerClosed):
                        self.abort()  # A peer fatal alert needs no response.
                    else:
                        async with asyncio.timeout(0.5):
                            async with self.send_lock:
                                await self.wire.fatal(error, self.sender)
                except (OSError, TimeoutError):
                    self.abort()
                except BaseException:
                    self.abort()
                    raise
                finally:
                    self.closed = True
                    self._clear_connection_secrets()
                    if self._fatal_alert_done is not None:
                        self._fatal_alert_done.set()
                raise
            except BaseException:
                self.abort()
                raise

    async def send(self, content):
        async with self.send_lock:
            self._check_write_open()
            try:
                maximum = min(16384, self.sender.record_limit - 1)
                chunks = (content[i:i + maximum] for i in range(0, len(content), maximum))
                for chunk in chunks:
                    self._check_write_open()
                    await self._flush_key_update_response_locked()
                    if (self.sender.sequence >= c.MAX_RECORDS - 1
                            or self.sender.content_bytes + len(chunk) + 5 > c.MAX_CONTENT_BYTES):
                        await self._key_update_locked(False)
                    self._check_write_open()
                    self.wire.writer.write(self.sender.seal(chunk, 23))
                    await self.wire.writer.drain()
            except _WriteStopped:
                # recv() may still need this sending epoch for a local fatal
                # alert. Do not abort it merely because its write gate closed.
                raise
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
            # A local fatal reader may be waiting for this method's drain/lock.
            # After releasing it, let that reader emit its alert in the current
            # epoch before normal close destroys the last sending state.
            if self._fatal_alert_done is not None and not self._fatal_alert_done.is_set():
                try:
                    async with asyncio.timeout(1):
                        await self._fatal_alert_done.wait()
                except BaseException:
                    self.abort()
                    raise
            # Preserve queued close_notify on the normal path; force-abort only
            # if flushing/closing does not finish within the bounded deadline.
            self.closed = True
            self._clear_connection_secrets()
            self.wire.writer.close()
            try:
                async with asyncio.timeout(1):
                    await self.wire.writer.wait_closed()
            except (OSError, TimeoutError):
                self.abort()
            except asyncio.CancelledError:
                self.abort()
                raise


def handshake_keys(root, transcript, hash_name=None):
    schedule = c.KeySchedule(c.secret_hash(root, hash_name))
    return (schedule.derive_secret(root, "c hs traffic", transcript.snapshot()),
            schedule.derive_secret(root, "s hs traffic", transcript.snapshot()))


def application_keys(root, transcript, hash_name=None):
    schedule = c.KeySchedule(c.secret_hash(root, hash_name))
    master = schedule.master_secret(root)
    return (schedule.derive_secret(master, "c ap traffic", transcript.snapshot()),
            schedule.derive_secret(master, "s ap traffic", transcript.snapshot()))


def check_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("handshake timeout must be finite and positive")


def _record_limit(value):
    if value is None:
        return 16385
    if type(value) is not int or not 64 <= value <= 16385:
        raise ValueError("record_size_limit must be between 64 and 16385")
    return value


def _peer_record_limit(value, *, server=False):
    if len(value) != 2:
        raise ProtocolError("malformed record_size_limit", alert=50)
    if not 64 <= int.from_bytes(value, "big") <= (65535 if server else 16385):
        raise ProtocolError("invalid record_size_limit", alert=47)
    return min(16385, int.from_bytes(value, "big"))


def _fragment_limit(value):
    if type(value) is not int or value not in (1, 2, 3, 4):
        raise ValueError("max_fragment_length must be 1, 2, 3 or 4")
    return (1 << (8 + value)) + 1


def _peer_fragment_limit(value):
    if len(value) != 1:
        raise ProtocolError("malformed max_fragment_length", alert=50)
    if value[0] not in (1, 2, 3, 4):
        raise ProtocolError("invalid max_fragment_length", alert=47)
    return _fragment_limit(value[0])


def _check_certificate_offer(chain, offered, signature_provider=None, signature_issuers=(), *, require_match=True):
    if not offered:
        raise ProtocolError("missing signature_algorithms_cert", alert=109)
    matches = True
    for index, der in enumerate(chain):
        cert = x509.load_der_x509_certificate(der)
        if index == len(chain) - 1 and cert.subject == cert.issuer:
            try:
                if certificate_extensions(cert).get_extension_for_class(x509.BasicConstraints).value.ca:
                    scheme=certificate_signature_scheme(cert, cert)
                    if 0x0708 <= scheme <= 0x070f:
                        verify_public_signature(certificate_public_key(cert, signature_provider=signature_provider),
                                                scheme, cert.signature, cert.tbs_certificate_bytes,
                                                sm2_identifier=SM2_CERTIFICATE_IDENTIFIER,
                                                gost_certificate_encoding=True)
                    else:
                        cert.verify_directly_issued_by(cert)
                    continue  # Self-signed CA; actual anchor trust is checked separately.
            except (ValueError, x509.ExtensionNotFound):
                pass
        issuer = (x509.load_der_x509_certificate(chain[index+1]) if index + 1 < len(chain) else
                  find_certificate_issuer(cert, signature_issuers, signature_provider=signature_provider))
        scheme = certificate_signature_scheme(cert, issuer)
        if scheme not in offered:
            matches = False
    if require_match and not matches:
        raise ProtocolError("certificate signature was not offered")
    return matches


def _retry_psks_unchanged(first, second, hash_name="sha256", *, known_hashes=None):
    """Retain known compatible PSKs without guessing the hash of opaque identities.

    Different KDFs can have the same binder length. Unknown identities may be
    removed because their incompatibility cannot be determined by this server.
    Retained identities still preserve order and binder size; no additions are
    allowed. The selected identity and its binder are checked separately.
    """
    known_hashes = known_hashes or {}
    cursor = 0
    for identity, _, binder in first.psk_offers:
        if cursor < len(second.psk_offers) and second.psk_offers[cursor][0] == identity:
            if len(second.psk_offers[cursor][2]) != len(binder):
                return False
            cursor += 1
        elif known_hashes.get(identity) == hash_name:
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


def _credential_extensions(credentials):
    metadata = [tuple(value) for value in credentials.entry_extensions] if credentials.entry_extensions else [()] * len(credentials.chain_der)
    if credentials.delegation:
        if not metadata or 34 in dict(metadata[0]):
            raise ProtocolError("ambiguous local delegated credential")
        metadata[0] += ((34, credentials.delegation),)
    return tuple(metadata)


def _compression_offer(value):
    reader = m._Reader(value)
    encoded = reader.vector(1); reader.end()
    if not encoded or len(encoded) % 2:
        raise ProtocolError("invalid certificate compression offer", alert=50)
    result = tuple(int.from_bytes(encoded[i:i+2], "big") for i in range(0, len(encoded), 2))
    if len(set(result)) != len(result):
        raise ProtocolError("duplicate certificate compression algorithm", alert=47)
    return result


def _credential_frame(credentials, *, context=b"", offer_extensions=(), role="server",
                      compression_algorithms=(1, 2, 3), cached=False, signature_provider=None):
    if credentials is None:
        return m.certificate([], context=context, allow_empty=True)
    offered = dict(offer_extensions)
    metadata = _credential_extensions(credentials)
    if any(17 in dict(pairs) for pairs in metadata):
        raise ProtocolError("status_request_v2 is forbidden in CertificateEntry")
    if 5 in offered:
        from .status_request import parse_status_request, response_matches_request
        from .credential_evidence import _status_response
        request = parse_status_request(offered[5], certificate_request=role == "client")
        metadata = tuple(tuple((kind, value) for kind, value in pairs
                               if kind != 5 or response_matches_request(_status_response(value), request))
                         for pairs in metadata)
    else:
        # A provisioned staple is reusable credential metadata, not permission
        # to send an unsolicited CertificateEntry extension to this peer.
        metadata = tuple(tuple(pair for pair in pairs if pair[0] != 5) for pairs in metadata)
    if any(59 in dict(pairs) for pairs in metadata):
        from .dnssec_credentials import DNSSECWireEvidence
        if role != "server" or any(59 in dict(pairs) for pairs in metadata[1:]):
            raise ProtocolError("DNSSEC evidence is only allowed on a server end entity")
        binding = credentials.dnssec_service
        if (not isinstance(binding, tuple) or len(binding) != 2 or
                type(binding[1]) is not int or not 1 <= binding[1] <= 65535):
            raise ProtocolError("local DNSSEC evidence requires a logical service binding")
        name = m.validate_name(binding[0])
        offered_name = m.parse_server_name(offered[0]) if 0 in offered else ""
        DNSSECWireEvidence.parse(dict(metadata[0])[59])
        if (offered_name != name or offered.get(59) != binding[1].to_bytes(2, "big")):
            # RFC9102: do not return an unrelated chain for an unsupported
            # name/port, including a peer which did not request this extension.
            metadata = tuple(tuple(pair for pair in pairs if pair[0] != 59) for pairs in metadata)
    if credentials.credential_type == 0:
        _check_certificate_offer(credentials.chain_der, m._u16_list(offered[50]) if 50 in offered else (), signature_provider,
                                 credentials.signature_issuers)
        grant = dict(metadata[0]).get(34)
        if grant is not None:
            if 34 not in offered or 0xff04 not in offered:
                raise ProtocolError("peer did not offer delegated credentials")
            key, _ = validate_delegation(credentials.chain_der[0], grant, role=role,
                grant_algorithms=m._u16_list(offered[0xff04]), delegated_schemes=m._u16_list(offered[34]),
                signature_provider=signature_provider)
        else:
            key = x509.load_der_x509_certificate(credentials.chain_der[0]).public_key()
    elif credentials.credential_type == 2:
        if (len(credentials.chain_der) != 1 or
                any(kind != 59 for pairs in metadata for kind, _ in pairs)):
            raise ProtocolError("invalid local raw-key credential")
        key = parse_x25519_spki(credentials.chain_der[0])
    elif credentials.credential_type == 3:
        from .its_credentials import ITSServicePolicy
        policy = getattr(credentials, "its_policy", None)
        if len(credentials.chain_der) != 1 or any(metadata) or not isinstance(policy, ITSServicePolicy):
            raise ProtocolError("local ITS grant requires one entry and an explicit service policy")
        key, _, _ = policy.authorize(credentials.chain_der[0], role=role, identity=policy.identity)
    else:
        raise ProtocolError("unsupported local credential representation")
    if c.public_bytes(key) != c.public_bytes(credentials.private_key):
        raise ProtocolError("local credential does not match its private key")
    for pairs in metadata:
        if set(dict(pairs)) - set(offered):
            raise ProtocolError("local credential contains unoffered evidence")
    message = m.certificate(credentials.chain_der, context=context, entry_extensions=metadata)
    if cached:
        if role != "server":
            raise ProtocolError("client certificate references are not negotiated")
        blocks = [b"".join(m.extension(kind, value) for kind, value in pairs) for pairs in metadata]
        message = m.frame(253, cached_certificate_body(credentials.chain_der, blocks,
                          credential_type=credentials.credential_type, context=context))
    if 27 in offered:
        algorithm = next((value for value in _compression_offer(offered[27]) if value in compression_algorithms), None)
        if algorithm is not None:
            message = m.frame(25, compress_certificate(message[4:], algorithm))
    return message


def _decode_credential(message, *, context=b"", allow_empty=False, offered_compression=(),
                        cached=False, snapshots=(), credential_type=0):
    body = decompress_certificate(message[4:], offered_compression) if message[0] == 25 else message[4:]
    if cached:
        if message[0] not in (25, 253):
            raise ProtocolError("selected cached certificate requires a reference")
        material, blocks = resolve_cached_certificate(body, snapshots,
            credential_type=credential_type, expected_context=context)
        return list(material), tuple(tuple(m.extensions(block, context="CE").items()) for block in blocks)
    if message[0] not in (11, 25):
        raise ProtocolError("unselected cached certificate reference")
    return m.parse_certificate(body, context=context, allow_empty=allow_empty, details=True)


def _cache_offer(data):
    outer = m._Reader(data); reader = m._Reader(outer.vector(2)); outer.end()
    result = []
    while reader.position < len(reader.data):
        kind, value = reader.take(1)[0], reader.vector(1)
        # RFC7924's CachedObject hash vector is nonempty even for an unknown
        # object type. Ignore unsupported semantics only after valid framing.
        if not value:
            raise ProtocolError("empty cached object hash", alert=50)
        if kind in (1, 2) and len(value) != 32 or (kind, value) in result:
            raise ProtocolError("invalid cached object offer", alert=47)
        result.append((kind, value))
    if not result:
        raise ProtocolError("empty cached object offer", alert=50)
    return tuple(result)


def _request_extension_block(request):
    reader = m._Reader(request[4:]); reader.vector(1)
    result = reader.vector(2); reader.end()
    return result


def _decode_request(request, *, cache_enabled=False, templates=()):
    if request[0] == 252:
        if not cache_enabled:
            raise ProtocolError("unselected cached certificate request", alert=10)
        context, block = resolve_cached_request(request[4:], templates)
        body = m._vec(context, 1) + m._vec(block, 2)
    else:
        body = request[4:]
    return m.parse_certificate_request(body, details=True)


def _check_credential_extension_offers(metadata, offers):
    from .credential_evidence import EvidenceEnvelopeError, check_evidence_envelope
    # This is a TLS wire rule, independent of credential trust policy. Keep it
    # at the handshake boundary: exported authenticators use resolve_peer too,
    # but their application framing must not manufacture a TLS fatal alert.
    offered = dict(offers)
    for index, pairs in enumerate(metadata):
        for kind, value in pairs:
            if kind not in offered:
                raise ProtocolError("unsolicited CertificateEntry extension", alert=10 if kind == 34 else 110)
            if kind == 34 and index != 0:
                raise ProtocolError("delegated credential is not on the leaf", alert=47)
            try:
                check_evidence_envelope(kind, value)
            except EvidenceEnvelopeError as exc:
                raise ProtocolError(str(exc), alert=47 if exc.invalid_value else 50) from exc


def _resolve_credential(chain, metadata, *, role, credential_type, policy, offers,
                        negotiated_extensions=(), feature_offers=None):
    offered = dict(offers)
    _check_credential_extension_offers(metadata, offered)
    if 5 in offered:
        from .status_request import parse_status_request, response_matches_request
        from .credential_evidence import _status_response
        request = parse_status_request(offered[5], certificate_request=role == "client")
        for pairs in metadata:
            if 5 in dict(pairs) and not response_matches_request(_status_response(dict(pairs)[5]), request):
                raise ProtocolError("OCSP evidence does not match the actual request")
    return resolve_peer(chain, credential_type, role, policy=policy,
        certificate_algorithms=m._u16_list(offered[50]) if 50 in offered else (),
        grant_algorithms=m._u16_list(offered[0xff04]) if 0xff04 in offered else (),
        delegated_schemes=m._u16_list(offered[34]) if 34 in offered else (),
        entry_extensions=metadata, offered_extensions=tuple(offered),
        negotiated_extensions=negotiated_extensions, feature_offers=feature_offers)


def _certificate_feature_state(offers, selections=(), *, certificate_message=None,
                               certificate_metadata=(), authenticated_by_mac=False):
    """Satisfaction is a selection or a checked message, never just an offer.

    Certificate-algorithm and delegation requirements are checked while
    resolving the credential. The MAC is verified before accepting this state.
    Unilateral hints/capabilities (e.g. CA hints and PHA) are not server echoes.
    """
    offered = dict(offers)
    satisfied = set(selections).intersection(offered)
    if 50 in offered:
        satisfied.add(50)
    if 41 in satisfied and 45 in offered:
        satisfied.add(45)
    if authenticated_by_mac and 0xff02 in offered:
        satisfied.add(0xff02)
    if authenticated_by_mac and 0xff03 in offered:
        satisfied.add(0xff03)
    if certificate_message == 25 and 27 in offered:
        satisfied.add(27)
    if certificate_metadata and 34 in dict(certificate_metadata[0]) and 0xff04 in offered:
        satisfied.add(0xff04)
    return tuple(sorted(satisfied))


def _check_lab_features(chain, offers, satisfied):
    # The legacy lab trust path also obeys wire feature requirements.
    from .tls_features import certificate_features
    if certificate_features(x509.load_der_x509_certificate(chain[0])).intersection(dict(offers)) - set(satisfied):
        raise ProtocolError("an offered mandatory TLS Feature was not satisfied")


def _policy_context(policy):
    if policy is None:
        return b""
    if not isinstance(policy, CredentialPolicy):
        raise ValueError("credential policy must be explicit")
    fields = [root.public_bytes(serialization.Encoding.DER) for root in policy.trust_roots]
    fields += [value.role.encode() + b"\x00" + value.identity.encode() + b"\x00" + value.spki
               for value in policy.raw_public_keys]
    fields += [str(value).encode() for value in (policy.peer_name, policy.revocation_policy,
               policy.now, policy.max_delegated_lifetime_seconds, policy.require_delegation,
               id(policy.authorize_client), id(policy.evidence_validator), id(policy.dane_policy), id(policy.signature_provider))]
    if getattr(policy, "its_policy", None) is not None:
        fields.append(policy.its_policy.context())
    return c.digest(b"".join(len(value).to_bytes(4, "big") + value for value in fields))


def _certificate_types(value):
    reader = m._Reader(value); result = tuple(reader.vector(1)); reader.end()
    if not result or len(set(result)) != len(result):
        raise ProtocolError("invalid certificate type offer", alert=50)
    return result


def _client_auth_messages(credentials, context, share, algorithms, exporter_secret, transcript,
                          *, request_extensions=None, hash_name=None, signature_provider=None):
    offers = request_extensions if request_extensions is not None else ((50, m._vec(b"".join(x.to_bytes(2,"big") for x in algorithms),2)),)
    if credentials is not None and not match_credentials(credentials, offers):
        credentials = None
    chain = credentials.chain_der if credentials is not None else []
    if chain:
        if c.public_bytes(credentials.private_key) == share:
            raise ProtocolError("client proof and verifier keys must be independent")
    cert = _credential_frame(credentials, context=context, offer_extensions=offers, role="client",
                             signature_provider=signature_provider)
    transcript.extend(cert)
    result = [cert]
    if chain:
        cv = m.certificate_verify(c.client_proof(exporter_secret, credentials.private_key,
                                 share, bytes(transcript), hash_name), client=True)
        transcript.extend(cv)
        result.append(cv)
    return result


def _check_peer_filters(chain, credential_type, offers):
    if not match_credentials(SimpleNamespace(chain_der=chain, credential_type=credential_type), offers):
        raise ProtocolError("client certificate does not satisfy requested OID filters", alert=43)


def _signature_preferences(values, provider):
    """Explicit verifier capability policy; certificate and grant lists are independent."""
    supported = supported_certificate_algorithms(provider)
    if values is None:
        return supported
    values = tuple(values)
    if (not values or len(values) > 32767 or len(set(values)) != len(values)
            or any(type(value) is not int or value not in supported for value in values)):
        raise ValueError("invalid certificate/grant signature preference list")
    return values


def _client_evidence_offers(values, policy, certificate_types):
    """Validate this implementation's explicit client-evidence request profile.

    CertificateRequest status_request is empty, unlike ClientHello. Client CT
    needs an independently specified application profile and is not inferred
    from the corresponding server-certificate request encodings.
    """
    try:
        pairs = tuple(values)
        valid = all(len(pair) == 2 and type(pair[0]) is int and pair[0] == 5
                    and type(pair[1]) is bytes and pair[1] == b"" for pair in pairs)
    except (TypeError, ValueError):
        raise ValueError("client certificate evidence requires empty status_request offers") from None
    if not valid or len(pairs) > 1:
        raise ValueError("client certificate evidence requires one empty status_request offer")
    if pairs and (tuple(certificate_types) != (0,) or not isinstance(policy, CredentialPolicy)
                  or policy.evidence_validator is None):
        raise ValueError("client OCSP requests require an X.509 credential evidence validator")
    return tuple((kind, value) for kind, value in pairs)


@handshake_boundary
async def server_handshake(reader, writer, credentials, server_name, timeout=10, *,
                           ticket_store=None, max_early_data=0, on_early_data=None,
                           client_auth_validator=None, require_client_auth=False,
                           cipher_suites=(0x1301, 0x1302, 0x1303, 0x1304, 0x1305),
                           application_protocols=(APPLICATION_PROTOCOL,), diagnostics=None,
                           enable_authenticators=False, external_psks=(), psk_modes=(1, 0),
                           external_early_replay=None, record_size_limit=None,
                           client_credential_policy=None, client_certificate_types=(0,),
                           certificate_compression=(1, 2, 3), allow_non_confidential=False,
                           bootstrap_binding=None, heartbeat_mode=None,
                           ticket_count_limit=1, signaling=None,
                           on_early_exporter=None, on_exporter=None,
                           pinning=None, pinning_port=343,
                           require_server_name=True, require_alpn=True,
                           client_certificate_authorities=(), client_oid_filters=(),
                           server_credential_candidates=(), native_provider=None, supported_groups=None,
                           retry_cookie_policy=None, client_certificate_algorithms=None,
                           client_delegation_signature_algorithms=None,
                           client_certificate_evidence_extensions=()):
    check_timeout(timeout)
    client_evidence_offers = _client_evidence_offers(client_certificate_evidence_extensions,
        client_credential_policy, client_certificate_types)
    from .retry_cookie import RetryCookiePolicy, validate_retry_cookie
    if retry_cookie_policy is not None and not isinstance(retry_cookie_policy, RetryCookiePolicy):
        raise ValueError("explicit RetryCookiePolicy required")
    if any(c.suite(value).password_authenticated for value in cipher_suites):
        raise ValueError("PWD suites require the explicit pake_handshake.server policy API")
    m.validate_service_identity(server_name)
    if m.is_ip_identity(server_name):
        require_server_name = False  # IP reference identity must not appear in SNI.
    if require_client_auth and client_auth_validator is None and client_credential_policy is None and bootstrap_binding is None:
        raise ValueError("required client authentication needs an explicit trust validator")
    bootstrap_bindings = ()
    if bootstrap_binding is not None:
        from .bootstrap_credentials import current_bootstrap_bindings
        bootstrap_bindings = current_bootstrap_bindings(bootstrap_binding, service=server_name)
        bootstrap_binding = bootstrap_bindings[0]
    if 3 in client_certificate_types and getattr(client_credential_policy, "its_policy", None) is None:
        raise ValueError("ITS client authentication requires an explicit ITS service policy")
    wire = Wire(reader, writer)
    wire.deadline = asyncio.get_running_loop().time() + timeout
    transcript = Transcript()
    sender = None
    exporter_accesses = []
    local_limit = _record_limit(record_size_limit)
    bootstrap_valid = False
    signature_provider = getattr(client_credential_policy, "signature_provider", None) or native_provider
    certificate_algorithms = _signature_preferences(client_certificate_algorithms, signature_provider)
    grant_algorithms = _signature_preferences(client_delegation_signature_algorithms, signature_provider)
    from .gost_provider import GOSTProvider
    enabled_groups = tuple(value for value in c.GROUP_LENGTHS if (value != 41 or native_provider is not None)
                           and (not 34 <= value <= 40 or isinstance(native_provider,GOSTProvider)))
    if supported_groups is not None:
        if (not supported_groups or any(type(value) is not int or value not in enabled_groups for value in supported_groups)
                or len(set(supported_groups)) != len(supported_groups)):
            raise ValueError("invalid explicit server group policy")
        enabled_groups = tuple(supported_groups)
    if any(c.suite(value).hash_name == "streebog256" for value in cipher_suites) and not isinstance(native_provider,GOSTProvider):
        raise ValueError("GOST suites require an explicit GOST provider")
    if native_provider is None and any(c.suite(value).hash_name == "sm3" for value in cipher_suites):
        raise ValueError("SM cipher suites require an explicitly selected native provider")
    secrets = HandshakeSecrets()
    try:
        async with asyncio.timeout(timeout):
            if await wire.exact(len(c.PREFACE)) != c.PREFACE:
                raise ProtocolError("not the TLS 2.0 experimental protocol")
            bootstrap_valid = True
            ch = await wire.receive_frame(1, boundary=True)
            initial_ch = ch
            hello = m.parse_client_hello(ch[4:], enabled_groups=enabled_groups)
            selected_id = next((value for value in cipher_suites if value in hello.cipher_suites), None)
            selected = c.suite(selected_id)
            schedule = c.KeySchedule(c.hash_context(selected.hash_name,native_provider))
            if not selected.confidential and allow_non_confidential is not True:
                raise ProtocolError("non-confidential operation was not explicitly enabled")
            if not selected.confidential and 33 in hello.extensions:
                raise ProtocolError("combined PSK requires confidentiality")
            ext_values = dict(hello.extension_values)
            if 32 in ext_values:
                from .pinning import parse_client_extension
                parse_client_extension(ext_values[32])
                if hello.psk_offers or 33 in ext_values or hello.early_data:
                    raise ProtocolError("pinning requires a fresh credential handshake", alert=47)
            cache_offer = _cache_offer(ext_values[25]) if 25 in ext_values else ()
            offered_server_types = _certificate_types(ext_values[20]) if 20 in ext_values else (0,)
            candidates = ((credentials,) if credentials is not None else ()) + tuple(server_credential_candidates)
            candidates = preferred_credentials((value for value in candidates
                if value.credential_type in offered_server_types), ext_values,
                role="server" if 50 in ext_values else None, signature_provider=native_provider)
            credentials = candidates[0] if candidates else None
            server_credential_type = credentials.credential_type if credentials else 0
            client_credential_type = next((value for value in client_certificate_types
                if value in (_certificate_types(ext_values[19]) if 19 in ext_values else (0,))), None)
            request_client_auth = client_auth_validator is not None or client_credential_policy is not None
            client_auth_offers = ((50, m._vec(b"".join(value.to_bytes(2,"big") for value in certificate_algorithms), 2)),)
            if client_certificate_authorities:
                client_auth_offers += ((47, encode_certificate_authorities(client_certificate_authorities)),)
            if client_oid_filters:
                client_auth_offers += ((48, encode_oid_filters(client_oid_filters)),)
            if client_credential_policy is not None and client_credential_type == 0:
                client_auth_offers += ((34, b"\x00\x02\xfe\x01"),
                    (0xff04, m._vec(b"".join(value.to_bytes(2,"big") for value in grant_algorithms), 2)))
            if certificate_compression:
                client_auth_offers += ((27, m._vec(b"".join(value.to_bytes(2,"big") for value in certificate_compression),1)),)
            client_auth_offers += client_evidence_offers
            send_limit = _peer_record_limit(ext_values[28], server=True) if 28 in ext_values else 16385
            receive_limit = local_limit if 28 in ext_values else 16385
            mfl = _peer_fragment_limit(ext_values[1]) if 1 in ext_values and 28 not in ext_values else None
            if mfl is not None:
                send_limit = receive_limit = mfl
            initial_controls = server_controls(ext_values, heartbeat=heartbeat_mode,
                ticket_limit=ticket_count_limit, tickets_enabled=ticket_store is not None and 45 in hello.extensions,
                signaling=signaling)
            wire.allow_ccs = True
            if 44 in hello.extensions:
                raise ProtocolError("unsolicited cookie in initial ClientHello", alert=47)
            protocol = next((value for value in application_protocols if value in hello.protocols), b"")
            if hello.name != server_name and (hello.name or require_server_name):
                raise ProtocolError("unsupported service identity", alert=112)
            if not protocol and (require_alpn or application_protocols and hello.protocols):
                raise ProtocolError("no application protocol", alert=120)
            provisioned = tuple(external_psks)
            bootstrap_scoped_psks = {}
            if bootstrap_binding is not None:
                from .bootstrap_credentials import bootstrap_binding_fingerprint, resolve_bootstrap_identity
                from .psk import bootstrap_public_key_psk
                bootstrap_scoped_psks = {value.spki: tuple(bootstrap_public_key_psk(value.spki[12:], server_name,
                    target_hash=name, protocol=protocol) for name in value.target_hashes) for value in bootstrap_bindings}
                provisioned = tuple(psk for values in bootstrap_scoped_psks.values() for psk in values)
                request_client_auth, require_client_auth = True, True
                client_credential_type = 2 if 2 in (_certificate_types(ext_values[19]) if 19 in ext_values else ()) else None
            if any(not isinstance(value, ExternalPSK) for value in provisioned):
                raise ValueError("external_psks requires explicit ExternalPSK provisioning")
            external = next((value for identity, _, _ in hello.psk_offers for value in provisioned
                if value.identity == identity and value.name == server_name and value.protocol == protocol
                and value.hash_name == selected.hash_name and value.combined == (33 in hello.extensions)
                and c.suite(value.cipher_suite).confidential == selected.confidential), None)
            ticket_context_base = (b"".join(credentials.chain_der if credentials else ())
                + bytes((request_client_auth, require_client_auth, server_credential_type, bool(allow_non_confidential)))
                + (b"" if bootstrap_bindings else _policy_context(client_credential_policy))
                + initial_controls.signaling_context
                + repr(_credential_extensions(credentials) if credentials else ()).encode()
                + repr(client_auth_offers).encode())
            def ticket_scope(binding=None):
                scoped = bootstrap_scoped_psks[binding.spki] if binding is not None else provisioned
                return c.digest(ticket_context_base
                    + (bootstrap_binding_fingerprint(binding) if binding is not None else b"")
                    + b"".join(value.policy_digest() for value in scoped))
            ticket_context = ticket_scope()
            def lookup_ticket(identity):
                for binding in bootstrap_bindings or (None,):
                    candidate = ticket_store.lookup(identity, server_name, protocol, ticket_scope(binding))
                    if candidate is not None:
                        if binding is not None:
                            resolved, _ = resolve_bootstrap_identity(candidate.external_psk_identity,
                                bootstrap_bindings, service=server_name)
                            if resolved != binding:
                                raise ProtocolError("bootstrap ticket scope differs from its selected BSK")
                        return candidate
                return None
            resumable = None
            if ticket_store is not None and external is None and 33 not in hello.extensions:
                for identity, _, _ in hello.psk_offers:
                    value = lookup_ticket(identity)
                    if (value is not None and c.suite(value.cipher_suite).hash_name == selected.hash_name
                            and c.suite(value.cipher_suite).confidential == selected.confidential
                            and set(value.allowed_psk_modes).intersection(hello.psk_modes, psk_modes)):
                        resumable = value
                        break
            selected_psk = external or resumable
            if selected_psk is not None:
                selected_offer = next(offer for offer in hello.psk_offers if offer[0] == selected_psk.identity)
                if len(selected_offer[2]) != selected.hash_length:
                    raise ProtocolError("selected PSK binder has the wrong hash length", alert=51)
            selectable_modes = set(hello.psk_modes).intersection(psk_modes,
                resumable.allowed_psk_modes if resumable else (0, 1))
            psk_only = bool((resumable or external and not external.combined)
                            and 0 in selectable_modes
                            and (not hello.group or 1 not in selectable_modes))
            sent_ccs = False
            if not hello.group and not psk_only:
                raise ProtocolError("no acceptable PSK-only selection or DHE share")
            retry_group = hello.group if not hello.B and not psk_only else 0
            retried = bool(retry_group or retry_cookie_policy is not None)
            if retried:
                known_psk_hashes = {}
                for identity, _, _ in hello.psk_offers:
                    hashes = {value.hash_name for value in provisioned
                              if value.identity == identity and value.name == server_name
                              and value.protocol == protocol}
                    candidate = lookup_ticket(identity) if ticket_store is not None else None
                    if candidate is not None:
                        hashes.add(c.suite(candidate.cipher_suite).hash_name)
                    if len(hashes) == 1:
                        known_psk_hashes[identity] = hashes.pop()
                retry_cookie = (retry_cookie_policy.issue(writer, ch, selected_id, retry_group)
                                if retry_cookie_policy is not None else b"")
                hrr = m.server_hello(b"", bytes(32), session_id=hello.session_id,
                                     group=retry_group, retry=True, cipher_suite=selected_id,
                                     cookie=retry_cookie)
                await wire.send_frame(hrr)
                if hello.session_id:
                    await wire.send_ccs()
                    sent_ccs = True
                transcript.retry(ch, hrr, schedule.hash_name)
                discarded = 0
                while True:
                    record = await wire.raw_record()
                    if record[0] == 20:
                        if record[5:] == b"\x01":
                            continue
                        raise ProtocolError("invalid dummy ChangeCipherSpec after retry", alert=10)
                    if record[0] == 21:
                        fragment = record[5:]
                        if len(fragment) != 2:
                            raise ProtocolError("malformed alert", alert=50)
                        if fragment[1] == 90:
                            continue
                        raise PeerClosed("peer closed or aborted the retry", alert=fragment[1])
                    if record[0] == 22:
                        wire.pending.extend(record[5:]); break
                    discarded += len(record)
                    if not hello.early_data or record[0] != 23:
                        raise ProtocolError("unexpected record after retry", alert=10)
                    if discarded > 1048576:
                        raise ProtocolError("rejected early data discard limit after retry")
                ch2 = await wire.receive_frame(1, boundary=True)
                second = m.parse_client_hello(ch2[4:], enabled_groups=enabled_groups, password_authenticated=False)
                validate_retry_cookie(retry_cookie_policy, dict(second.extension_values), retry_cookie,
                                      writer, ch, selected_id, retry_group)
                mutable = {21, 41, 42, 44, 51}
                stable = lambda h: {k: v for k, v in h.extension_values if k not in mutable}
                if (second.fixed_hello != hello.fixed_hello or stable(second) != stable(hello)
                        or second.early_data
                        or not _retry_psks_unchanged(hello, second, selected.hash_name,
                                                   known_hashes=known_psk_hashes)
                        or (retry_group and (not second.B or second.group != retry_group
                                             or second.share_groups != (retry_group,)))
                        or (not retry_group and dict(second.extension_values).get(51)
                            != dict(hello.extension_values).get(51))):
                    raise ProtocolError("ClientHello changed forbidden fields after retry", alert=47)
                ch, hello = ch2, second
            static_public = c.public_bytes(credentials.private_key) if credentials else b""
            if static_public and static_public in (hello.A, c.traffic_auth_component(hello.group, hello.B)):
                raise ProtocolError("non-independent key shares")
            ticket, selected_identity, psk_age, psk_binder = external, 0, 0, b""
            if external is not None:
                selected_offer = next(((index, offer) for index, offer in enumerate(hello.psk_offers)
                    if offer[0] == external.identity), None)
                if selected_offer is None:
                    raise ProtocolError("selected PSK was removed after retry", alert=47)
                selected_identity, (_, psk_age, psk_binder) = selected_offer
            if ticket_store is not None and ticket is None and 33 not in hello.extensions:
                for index, (identity, age, proof) in enumerate(hello.psk_offers):
                    candidate = lookup_ticket(identity)
                    if (candidate is not None and c.suite(candidate.cipher_suite).hash_name == selected.hash_name
                            and c.suite(candidate.cipher_suite).confidential == selected.confidential
                            and set(candidate.allowed_psk_modes).intersection(hello.psk_modes, psk_modes)):
                        ticket, selected_identity, psk_age, psk_binder = candidate, index, age, proof
                        break
            if ticket is not None and not hmac.compare_digest(
                    c.binder(ticket.psk, transcript.snapshot() + ch[:-hello.binder_vector_size],
                             hash_name=schedule.hash_name,
                             kind=external.binder_kind if external is not None else "res"), psk_binder):
                raise ProtocolError("PSK binder verification failed", alert=51)
            selected_external_identity = external.identity if external is not None else ticket.external_psk_identity if ticket else b""
            if bootstrap_binding is not None:
                # Scope and current inventory are checked before ANY authorized
                # early callback, client identity, or successor ticket can exist.
                bootstrap_binding, _ = resolve_bootstrap_identity(selected_external_identity,
                    bootstrap_bindings, service=server_name)
                ticket_context = ticket_scope(bootstrap_binding)
                if ticket is None:
                    raise ProtocolError("bootstrap authentication requires its provisioned PSK")
            if ticket is not None:
                # A ticket may expire while the client answers HRR, causing
                # the final lookup to choose a different offered identity.
                # Check that identity's authority, not the pre-HRR candidate's
                # modes. Do not change a DHE/group decision committed by HRR.
                final_modes = set(hello.psk_modes).intersection(psk_modes,
                    (0, 1) if external is not None else ticket.allowed_psk_modes)
                if (0 if psk_only else 1) not in final_modes:
                    raise ProtocolError("no mutually supported PSK key exchange mode")
            combined = bool(external and external.combined)
            credential_auth = ticket is None or combined
            authenticated_client = None
            if ticket is not None and external is None and request_client_auth:
                if ticket.client_certificate_chain:
                    try:
                        if bootstrap_binding is not None:
                            if tuple(ticket.client_certificate_chain) != (bootstrap_binding.spki,) or ticket.client_certificate_type != 2:
                                raise ProtocolError("resumed bootstrap identity differs from provisioned BSK")
                        elif client_credential_policy is not None:
                            _resolve_credential(ticket.client_certificate_chain, ticket.client_certificate_extensions,
                                role="client", credential_type=ticket.client_certificate_type,
                                policy=client_credential_policy, offers=client_auth_offers,
                                negotiated_extensions=_certificate_feature_state(client_auth_offers,
                                    certificate_metadata=ticket.client_certificate_extensions))
                        else:
                            await _validate_client(client_auth_validator, ticket.client_certificate_chain)
                        authenticated_client = tuple(ticket.client_certificate_chain)
                    except (ProtocolError, ValueError):
                        ticket = None
                elif require_client_auth:
                    ticket = None
                credential_auth = ticket is None
            if bootstrap_binding is not None and ticket is None:
                raise ProtocolError("bootstrap ticket is no longer authorized")
            if ticket is None and psk_only:
                raise ProtocolError("PSK-only identity is no longer authorized")
            if external is not None and not combined and require_client_auth:
                raise ProtocolError("external PSK-only authentication does not satisfy required client credentials")
            successor_modes = tuple(mode for mode in dict.fromkeys(hello.psk_modes)
                if mode in (0, 1) and (external is not None or ticket is None
                                      or mode in ticket.allowed_psk_modes))
            replay_ok = False
            if ticket is not None and hello.early_data and selected_identity == 0:
                if external is None:
                    replay_ok = ticket_store.consume_early(ticket, psk_age)
                elif external_early_replay is not None and ticket.max_early_data:
                    # Explicit deployment replay store must atomically reject
                    # reuse across workers AND restarts for the PSK's lifetime.
                    # Nonselected binders have not been authenticated and may
                    # change without changing this client's replay identity.
                    replay_ok = external_early_replay(external,
                        c.digest(ch[:-hello.binder_vector_size], schedule.hash_name))
                    if inspect.isawaitable(replay_ok):
                        replay_ok = await replay_ok
            accepted = bool(ticket is not None and hello.early_data and max_early_data
                and selected_identity == 0 and on_early_data is not None
                and ticket.cipher_suite == selected_id
                and replay_ok and not combined)
            if credential_auth:
                if credentials is None:
                    raise ProtocolError("server credentials are required for this authentication mode")
                if len(hello.A) != 32:
                    raise ProtocolError("credential authentication requires auth_share", alert=109)
                if server_credential_type not in offered_server_types:
                    raise ProtocolError("server credential type was not offered", alert=43)
            if bootstrap_binding is not None and external is not None:
                from .bootstrap_credentials import require_bootstrap_flight
                require_bootstrap_flight(combined=combined, fresh_key_share=bool(hello.B) and not psk_only,
                    initial_early_data=hello.early_data, client_credential_type=client_credential_type,
                    client_request_present=request_client_auth)
            transcript.add(ch)
            ephemeral_public, traffic_shared = (b"", bytes(selected.hash_length)) if psk_only else c.traffic_server(hello.group, hello.B, provider=native_provider)
            if c.traffic_auth_component(hello.group, ephemeral_public) and c.traffic_auth_component(hello.group, ephemeral_public) in (
                    hello.A, c.traffic_auth_component(hello.group, hello.B), static_public):
                raise ProtocolError("non-independent key shares")
            # Reject both zero agreements before sending a server flight.
            traffic_root = c.handshake_secret(traffic_shared,
                                              ticket.psk if ticket else None, schedule.hash_name)
            auth_shared = c.dh(credentials.private_key, hello.A) if credential_auth else None
            sh = m.server_hello(ephemeral_public, os.urandom(32),
                                session_id=hello.session_id, resumed=ticket is not None,
                                group=0 if psk_only else hello.group, selected_identity=selected_identity,
                                cipher_suite=selected_id, combined_psk=combined)
            transcript.add(sh)
            pinning_transcript = transcript.snapshot()
            client_secret, server_secret = handshake_keys(traffic_root, transcript, schedule.hash_name)
            emit_diagnostic(diagnostics, "TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET", hello.random, client_secret)
            emit_diagnostic(diagnostics, "TLS20_SERVER_HANDSHAKE_TRAFFIC_SECRET", hello.random, server_secret)
            receiver = secrets.record(client_secret, "open", selected_id, receive_limit, provider=native_provider)
            sender = secrets.record(server_secret, "seal", selected_id, send_limit, provider=native_provider)
            await wire.send_frame(sh)
            if hello.session_id and not sent_ccs:
                await wire.send_ccs()
            ee_extra = ((28, receive_limit.to_bytes(2, "big")),) if 28 in ext_values else ()
            if mfl is not None and 28 not in ext_values:
                ee_extra += ((1, ext_values[1]),)
            controls = server_controls(dict(hello.extension_values), heartbeat=heartbeat_mode,
                ticket_limit=ticket_count_limit, tickets_enabled=ticket_store is not None and 45 in hello.extensions,
                resumed=ticket is not None and external is None, signaling=signaling)
            ee_extra += controls.extensions
            if 32 in ext_values and pinning is not None:
                effective_spki = credentials.private_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                ee_extra += ((32, pinning.respond(ext_values[32], server_name, pinning_port,
                    traffic_root, pinning_transcript, effective_spki, hash_name=schedule.hash_name)),)
            cache_selected = []
            if credential_auth and server_credential_type in (0, 2) and (1, material_hash(credentials.chain_der, server_credential_type)) in cache_offer:
                cache_selected.append(1)
            if request_client_auth:
                request_probe = m.certificate_request(b"", bytes(32),
                    algorithms=certificate_algorithms if client_credential_type == 0 else (),
                    extra_extensions=tuple(pair for pair in client_auth_offers if pair[0] != 50))
                if (2, request_template_hash(_request_extension_block(request_probe))) in cache_offer:
                    cache_selected.append(2)
            if cache_selected:
                ee_extra += ((25, m._vec(bytes(cache_selected), 2)),)
            if credential_auth and 20 in ext_values:
                ee_extra += ((20, bytes((server_credential_type,))),)
            if credential_auth and request_client_auth:
                if client_credential_type is None:
                    raise ProtocolError("no acceptable client credential type", alert=43)
                if 19 in ext_values:
                    ee_extra += ((19, bytes((client_credential_type,))),)
            messages = [m.encrypted_extensions(protocol, early_data=accepted, extra_extensions=ee_extra,
                                                acknowledge_name=bool(hello.name))]
            client_auth_private = None
            if credential_auth and request_client_auth:
                client_auth_private = X25519PrivateKey.generate()
                if c.public_bytes(client_auth_private) in (static_public, ephemeral_public, hello.A, hello.B):
                    raise ProtocolError("client verifier key must be independent")
                client_request = m.certificate_request(b"", c.public_bytes(client_auth_private),
                    algorithms=certificate_algorithms if client_credential_type == 0 else (),
                    extra_extensions=tuple(pair for pair in client_auth_offers if pair[0] != 50))
                if 2 in cache_selected:
                    client_request = m.frame(252, cached_request_body(b"", _request_extension_block(client_request), c.public_bytes(client_auth_private)))
                messages.append(client_request)
            if credential_auth:
                messages.append(_credential_frame(credentials, offer_extensions=hello.extension_values,
                                                   compression_algorithms=certificate_compression, cached=1 in cache_selected,
                                                   signature_provider=native_provider))
            for message in messages:
                transcript.add(message)
                await wire.send_frame(message, sender)
            if credential_auth:
                auth_root = schedule.authentication_root(traffic_root, auth_shared, transcript.snapshot())
                cv = m.certificate_verify(schedule.server_proof(auth_root, transcript.snapshot()))
                transcript.add(cv)
                await wire.send_frame(cv, sender)
            sf = m.frame(20, schedule.finished(server_secret, transcript.snapshot()))
            transcript.add(sf)
            await wire.send_frame(sf, sender)
            client_app, server_app = application_keys(traffic_root, transcript, schedule.hash_name)
            # Sending ServerFinished transitions our write epoch immediately,
            # including alerts emitted while waiting for ClientFinished.
            sender = secrets.record(server_app, "seal", selected_id, send_limit, provider=native_provider)
            exporter = schedule.derive_secret(schedule.master_secret(traffic_root), "exp master", transcript.snapshot())
            emit_diagnostic(diagnostics, "TLS20_CLIENT_TRAFFIC_SECRET_0", hello.random, client_app)
            emit_diagnostic(diagnostics, "TLS20_SERVER_TRAFFIC_SECRET_0", hello.random, server_app)
            emit_diagnostic(diagnostics, "TLS20_EXPORTER_SECRET", hello.random, exporter)
            await expose_exporter(on_exporter, exporter, exporter_accesses,
                                  stage="server-finished", role="server", hash_name=schedule.hash_name)
            early_exporter = None
            # The API revokes early-exporter access on HRR, like its client.
            # CH2 may remove incompatible PSKs: its identity zero must never
            # be substituted for CH1's early PSK when deriving over CH1.
            if ticket is not None and selected_identity == 0 and not retried:
                early_root = c.extract(bytes(selected.hash_length), ticket.psk, schedule.hash_name)
                early_exporter = schedule.derive_secret(early_root, "e exp master", c.PREFACE + initial_ch)
                emit_diagnostic(diagnostics, "TLS20_EARLY_EXPORTER_SECRET", hello.random, early_exporter)
                await expose_exporter(on_early_exporter, early_exporter, exporter_accesses,
                                      stage="early", role="server", hash_name=schedule.hash_name)
            if hello.early_data:
                early_receiver = (secrets.record(schedule.derive_secret(c.extract(bytes(selected.hash_length), ticket.psk, schedule.hash_name),
                    "c e traffic", c.PREFACE + ch), "open", selected_id, ticket.record_size_limit, provider=native_provider) if accepted else None)
                if early_receiver is not None:
                    emit_diagnostic(diagnostics, "TLS20_CLIENT_EARLY_TRAFFIC_SECRET", hello.random, early_receiver.secret)
                total, discarded = 0, 0
                while True:
                    record = await wire.raw_record()
                    if record[0] == 20 and record[5:] == b"\x01":
                        continue
                    if accepted:
                        if bootstrap_binding is not None:
                            current_bootstrap_bindings(bootstrap_binding, service=server_name)
                        content, kind = early_receiver.open(record)
                        if kind == 21:
                            wire.process_alert(content)
                            continue
                        if kind == 22:
                            wire.pending.extend(content)
                            eoed = await wire.receive_frame(5, early_receiver, boundary=True)
                            transcript.add(eoed)
                            await on_early_data(b"")
                            break
                        if kind != 23:
                            raise ProtocolError("early epoch carries only application data", alert=10)
                        total += len(content)
                        if total > min(max_early_data, ticket.max_early_data):
                            raise ProtocolError("early data limit exceeded")
                        if content:
                            await on_early_data(content)
                    else:
                        result = receiver.try_open(record)
                        if result is not None:
                            content, kind = result
                            if kind == 21:
                                wire.process_alert(content)
                                # Authentication commits to the handshake
                                # epoch even for advisory user_canceled. Never
                                # discard subsequent decryption failures.
                                break
                            if kind != 22 or not content:
                                raise ProtocolError("expected authenticated handshake after early data", alert=10)
                            wire.pending.extend(content)
                            break
                        discarded += len(record)
                        if record[0] != 23 or discarded > 1048576:
                            raise ProtocolError("rejected early data discard limit")
            client_chain = list(authenticated_client or [])
            client_metadata = ticket.client_certificate_extensions if ticket is not None and external is None else ()
            if authenticated_client:
                client_credential_type = ticket.client_certificate_type
            if client_auth_private is not None:
                cert = await wire.receive_frame((11, 25), receiver)
                client_chain, client_metadata = _decode_credential(cert, allow_empty=True,
                                                                  offered_compression=certificate_compression)
                _check_credential_extension_offers(client_metadata, client_auth_offers)
                transcript.add(cert)
                if client_chain:
                    _check_peer_filters(client_chain, client_credential_type, client_auth_offers)
                    if bootstrap_binding is not None:
                        if client_credential_type != 2 or tuple(client_chain) != (bootstrap_binding.spki,) or any(client_metadata):
                            raise ProtocolError("bootstrap client credential differs from selected BSK")
                        key = parse_x25519_spki(bootstrap_binding.spki)
                    elif client_credential_policy is not None:
                        key = _resolve_credential(client_chain, client_metadata, role="client",
                            credential_type=client_credential_type, policy=client_credential_policy,
                            offers=client_auth_offers, negotiated_extensions=_certificate_feature_state(
                                client_auth_offers, certificate_message=cert[0],
                                certificate_metadata=client_metadata, authenticated_by_mac=True)).public_key
                    else:
                        if client_credential_type != 0 or any(client_metadata):
                            raise ProtocolError("extended client credentials require an explicit policy")
                        _check_certificate_offer(client_chain, certificate_algorithms, native_provider)
                        key = await _validate_client(client_auth_validator, client_chain)
                    cv = await wire.receive_frame(15, receiver)
                    expected = schedule.client_proof(exporter, client_auth_private,
                                             c.public_bytes(key), transcript.snapshot())
                    if cv[4:6] != b"\xfe\x01" or not hmac.compare_digest(expected, cv[8:]):
                        raise ProtocolError("initial client MAC verification failed", alert=51)
                    transcript.add(cv)
            cf = await wire.receive_frame(20, receiver, boundary=True)
            if not schedule.verify_finished(client_secret, transcript.snapshot(), cf[4:]):
                raise ProtocolError("client Finished verification failed", alert=51)
            transcript.add(cf)
            if require_client_auth and not client_chain:
                raise ProtocolError("client certificate required", alert=116)
            bootstrap_authorization = None
            if bootstrap_binding is not None:
                current_bootstrap_bindings(bootstrap_binding, service=server_name)
                if external is not None:
                    from .bootstrap_credentials import authorize_bootstrap_client
                    bootstrap_authorization = authorize_bootstrap_client(bootstrap_binding, client_chain,
                        credential_type=client_credential_type, client_mac_verified=client_auth_private is not None,
                        client_finished_verified=True)
                else:
                    bootstrap_authorization = {"profile": "tls20-pok", "scope": bootstrap_binding.scope,
                        "service": bootstrap_binding.service, "trust_mode": bootstrap_binding.trust_mode,
                        "bsk": bootstrap_binding.spki, "fresh_client_possession": False}
            authenticated_client = tuple(client_chain) if client_chain else None
            client_auth_private = None
            if bootstrap_binding is not None and client_credential_policy is not None:
                from dataclasses import replace
                client_credential_policy = replace(client_credential_policy,
                    raw_public_keys=tuple(value for value in client_credential_policy.raw_public_keys
                        if value.spki == bootstrap_binding.spki))
            wire.check_deadline()
            channel = SecureChannel(wire, server_app, client_app, exporter_secret=exporter,
                resumed=ticket is not None and external is None, early_data_accepted=accepted,
                handshake_transcript=transcript.snapshot(), client_auth_validator=client_auth_validator,
                peer_post_handshake_auth=49 in hello.extensions and protocol != b"h2"
                    and (external is None or combined), authenticated_client=authenticated_client,
                cipher_suite=selected_id, protocol=protocol, role="server", enable_authenticators=enable_authenticators,
                peer_auth_share=hello.A, peer_capabilities=hello.extension_values,
                early_exporter_secret=early_exporter,
                psk_provenance=external.binder_kind if external else "res" if ticket else "credential",
                receive_record_limit=receive_limit, send_record_limit=send_limit,
                cache_types=cache_selected, peer_cached_objects=cache_offer,
                client_credential_policy=client_credential_policy,
                client_certificate_type=client_credential_type or 0, client_auth_offers=client_auth_offers,
                selected_external_psk_identity=selected_external_identity,
                allowed_psk_modes=successor_modes,
                bootstrap_binding=bootstrap_binding, bootstrap_authorization=bootstrap_authorization,
                heartbeat_local_mode=controls.heartbeat_local_mode, heartbeat_peer_mode=controls.heartbeat_peer_mode,
                native_provider=native_provider)
            secrets.establish(channel)
            channel.peer_authenticated = bool(ticket is not None or authenticated_client)
            channel.expected_ticket_count = controls.expected_tickets
            for access in exporter_accesses:
                access.complete(peer_authenticated=bool(ticket is not None or authenticated_client))
            channel._exporter_accesses = tuple(exporter_accesses)
            sender = channel.sender
            if ticket_store is not None and 45 in hello.extensions and successor_modes:
                resumption = schedule.derive_secret(schedule.master_secret(traffic_root), "res master", transcript.snapshot())
                count = controls.expected_tickets if controls.expected_tickets is not None else 1
                for _ in range(count):
                    message = ticket_store.issue(resumption, server_name, protocol,
                        max_early_data if on_early_data is not None else 0, ticket_context, client_chain,
                        cipher_suite=selected_id, client_certificate_type=client_credential_type or 0,
                        client_certificate_extensions=client_metadata, external_psk_identity=selected_external_identity,
                        allowed_psk_modes=successor_modes,
                         record_size_limit=receive_limit,
                        native_provider=native_provider)
                    if message is not None:
                        await channel.send_handshake(message)
            return secrets.release(channel)
    except ProtocolError as error:
        for access in exporter_accesses:
            access.close()
        if bootstrap_valid:
            await wire.fatal(error, sender)
        else:
            writer.transport.abort()
        raise
    except BaseException:
        for access in exporter_accesses:
            access.close()
        writer.transport.abort()
        raise
    finally:
        secrets.close()


@handshake_boundary
async def client_handshake(reader, writer, server_name, trust_roots, *, revocation_policy, timeout=10,
                           ticket_cache=None, early_data=b"", cache_context=b"",
                           traffic_group=0x001d, force_retry=False, client_credentials=None,
                           post_handshake_auth=False, cipher_suites=(0x1301,),
                           application_protocols=(APPLICATION_PROTOCOL,), diagnostics=None,
                           enable_authenticators=False, external_psk=None, psk_modes=(1,),
                           record_size_limit=None, credential_policy=None,
                           server_certificate_types=(0,), certificate_compression=(),
                           delegated_credentials=False, certificate_evidence_extensions=(),
                           allow_non_confidential=False, cached_certificates=(), cached_requests=(),
                           bootstrap_binding=None, normal_httpps=True, max_fragment_length=None,
                           heartbeat_mode=None, ticket_request=None, signaling=None,
                           external_psks=(), on_early_exporter=None, on_exporter=None,
                           pinning_cache=None, pinning_port=343,
                           send_server_name=True, require_alpn=True,
                           allow_unauthenticated_server=False,
                           client_credential_candidates=(), server_certificate_authorities=(), native_provider=None,
                           supported_groups=None, password_credential=None,
                           server_certificate_algorithms=None, server_delegation_signature_algorithms=None):
    check_timeout(timeout)
    mixed_password = password_credential is not None
    if mixed_password:
        from .pake import PasswordCredential
        from .pake_native import GROUPS as PASSWORD_GROUPS
        if (not isinstance(password_credential, PasswordCredential) or password_credential.service != server_name
                or not any(c.suite(value).password_authenticated for value in cipher_suites)
                or not any(not c.suite(value).password_authenticated for value in cipher_suites)
                or external_psk is not None or external_psks or bootstrap_binding is not None or pinning_cache is not None
                or allow_unauthenticated_server):
            raise ValueError("mixed password/credential negotiation requires independent explicit authentication policies")
    elif any(c.suite(value).password_authenticated for value in cipher_suites):
        raise ValueError("PWD suites require the explicit pake_handshake.client credential API")
    m.validate_service_identity(server_name)
    if m.is_ip_identity(server_name):
        send_server_name = False
    wire = Wire(reader, writer)
    wire.deadline = asyncio.get_running_loop().time() + timeout
    transcript = Transcript()
    sender = None
    exporter_accesses = []
    local_limit = _record_limit(record_size_limit)
    signature_provider = getattr(credential_policy, "signature_provider", None) or native_provider
    certificate_algorithms = _signature_preferences(server_certificate_algorithms, signature_provider)
    grant_algorithms = _signature_preferences(server_delegation_signature_algorithms, signature_provider)
    if native_provider is None and (traffic_group == 41 or any(c.suite(value).hash_name == "sm3" for value in cipher_suites)):
        raise ValueError("SM cipher suites and groups require an explicitly selected native provider")
    from .gost_provider import GOSTProvider
    if (34 <= traffic_group <= 40 or any(c.suite(value).hash_name == "streebog256" for value in cipher_suites)) and not isinstance(native_provider,GOSTProvider):
        raise ValueError("GOST suites/groups require an explicit GOST provider")
    enabled_groups = tuple(value for value in c.GROUP_LENGTHS if (value != 41 or native_provider is not None)
                           and (not 34 <= value <= 40 or isinstance(native_provider,GOSTProvider)))
    if supported_groups is not None:
        if (not supported_groups or traffic_group not in supported_groups
                or any(type(value) is not int or value not in enabled_groups for value in supported_groups)
                or len(set(supported_groups)) != len(supported_groups)):
            raise ValueError("invalid explicit client group policy")
        enabled_groups = tuple(supported_groups)
    credential_candidates = ((client_credentials,) if client_credentials is not None else ()) + tuple(client_credential_candidates)
    bootstrap_bindings = ()
    if bootstrap_binding is not None:
        from .bootstrap_credentials import current_bootstrap_bindings
        bootstrap_bindings = current_bootstrap_bindings(bootstrap_binding, service=server_name)
        bootstrap_binding = bootstrap_bindings[0]
    offered_client_types = tuple(dict.fromkeys(value.credential_type for value in credential_candidates)) or (0,)
    if max_fragment_length is not None:
        _fragment_limit(max_fragment_length)
    if credential_policy is None and revocation_policy != "lab-offline":
        credential_policy = CredentialPolicy(trust_roots=tuple(trust_roots), peer_name=server_name,
                                             revocation_policy=revocation_policy, signature_provider=native_provider)
    if credential_policy is not None and credential_policy.peer_name != server_name:
        raise ValueError("credential policy must be bound to the requested service")
    if 3 in server_certificate_types and getattr(credential_policy, "its_policy", None) is None:
        raise ValueError("ITS server credentials require an explicit ITS service policy")
    if credential_policy is not None and credential_policy.dane_policy is not None:
        from .dnssec_credentials import DANEPolicy
        policy = credential_policy.dane_policy
        if not isinstance(policy, DANEPolicy) or type(policy.port) is not int or not 1 <= policy.port <= 65535:
            raise ValueError("DNSSEC credential policy requires a valid logical service port")
        if not send_server_name or m.is_ip_identity(server_name):
            raise ValueError("DNSSEC credentials require the intended DNS SNI name")
        expected = policy.port.to_bytes(2, "big")
        supplied = dict(certificate_evidence_extensions).get(59)
        if supplied is not None and supplied != expected:
            raise ValueError("DNSSEC offer differs from the credential policy's logical service port")
        if supplied is None:
            certificate_evidence_extensions = (*certificate_evidence_extensions, (59, expected))
    unauthenticated = allow_unauthenticated_server is True
    if unauthenticated and (normal_httpps or bootstrap_binding is not None or delegated_credentials
            or certificate_evidence_extensions or pinning_cache is not None or external_psk is not None or external_psks
            or early_data or enable_authenticators):
        raise ValueError("unauthenticated operation requires a separately selected generic credential profile")
    provisioning_trust = any(value.trust_mode == "provisioning-trust" for value in bootstrap_bindings)
    if (any(value != 0 for value in server_certificate_types) or delegated_credentials) and credential_policy is None and not provisioning_trust and not unauthenticated:
        raise ValueError("extended credentials require an explicit credential policy")
    if not application_protocols and require_alpn:
        raise ValueError("required ALPN needs an application protocol offer")
    protocol = application_protocols[0] if application_protocols else b""
    if external_psk is not None and external_psks:
        raise ValueError("use external_psk or external_psks, not both")
    provisioned_psks = (external_psk,) if external_psk is not None else tuple(external_psks)
    if pinning_cache is not None and (provisioned_psks or early_data or bootstrap_binding is not None):
        raise ValueError("pinning requires a fresh credential-only handshake")
    pin_attempt = pinning_cache.begin(server_name, pinning_port) if pinning_cache is not None else None
    if any(not isinstance(value, ExternalPSK) or value.name != server_name
            or value.protocol not in application_protocols and not (not value.protocol and not require_alpn)
            for value in provisioned_psks):
        raise ValueError("external PSK is not provisioned for this service")
    if len({value.identity for value in provisioned_psks}) != len(provisioned_psks):
        raise ValueError("duplicate provisioned PSK identity")
    if len({value.combined for value in provisioned_psks}) > 1:
        raise ValueError("combined and plain PSK profiles require distinct attempts")
    bootstrap_offer_bindings = {}
    if bootstrap_binding is not None:
        from .bootstrap_credentials import bootstrap_binding_fingerprint, resolve_bootstrap_identity
        if not provisioned_psks:
            raise ValueError("bootstrap client requires its imported PSK")
        for value in provisioned_psks:
            binding, imported = resolve_bootstrap_identity(value.identity, bootstrap_bindings, service=server_name)
            if (not value.combined or value.binder_kind != "imp" or value.hash_name != imported.hash_name
                    or not hmac.compare_digest(value.psk, imported.psk)):
                raise ValueError("bootstrap client requires its exact imported PSK")
            bootstrap_offer_bindings[value.identity] = binding
        for binding in bootstrap_bindings:
            candidates = tuple(value for value in credential_candidates if value.credential_type == 2
                and tuple(value.chain_der) == (binding.spki,))
            if len(candidates) != 1 or not isinstance(candidates[0].private_key, X25519PrivateKey):
                raise ValueError("bootstrap client requires the exact provisioned RPK")
            if candidates[0].private_key.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo) != binding.spki:
                raise ValueError("bootstrap private key differs from the provisioned BSK")
        if provisioning_trust and normal_httpps:
            raise ValueError("provisioning trust is not normal authenticated HTTPPS")
    def client_ticket_context(binding=None, selected_protocol=None):
        scoped_psks = (tuple(value for value in provisioned_psks
            if bootstrap_offer_bindings.get(value.identity) == binding) if binding is not None else provisioned_psks)
        if binding is not None and selected_protocol is not None:
            from dataclasses import replace
            scoped_psks = tuple(replace(value, protocol=selected_protocol) for value in scoped_psks)
        scoped_candidates = (tuple(value for value in credential_candidates
            if value.credential_type == 2 and tuple(value.chain_der) == (binding.spki,))
            if binding is not None else credential_candidates)
        cache_fields = (b"".join(root.public_bytes(serialization.Encoding.DER) for root in trust_roots),
                    revocation_policy.encode("ascii"), cache_context,
                    b"" if binding is not None else (b"\x01" + c.digest(b"".join(client_credentials.chain_der)) if client_credentials else b"\x00"),
                    b"" if binding is not None else (repr((client_credentials.credential_type, _credential_extensions(client_credentials))).encode() if client_credentials else b""),
                    repr(tuple((value.credential_type, value.chain_der, _credential_extensions(value))
                               for value in scoped_candidates)).encode(),
                    b"".join(value.policy_digest() for value in scoped_psks), _policy_context(credential_policy),
                    bootstrap_binding_fingerprint(binding) if binding is not None else b"",
                    password_credential.context() if mixed_password else b"",
                    signaling.context() if signaling is not None else b"",
                    repr((certificate_algorithms, grant_algorithms)).encode(),
                    bytes(server_certificate_types), bytes((bool(delegated_credentials), bool(allow_non_confidential))))
        return c.digest(b"TLS20 client ticket context\x00" + b"".join(
            len(field).to_bytes(4, "big") + field for field in cache_fields))
    roots_hash = client_ticket_context()
    ticket = None
    if ticket_cache and pin_attempt is None and not unauthenticated:
        scopes = ((binding, candidate_protocol) for binding in bootstrap_bindings
                  for candidate_protocol in application_protocols) if bootstrap_bindings else ((None, protocol),)
        for binding, candidate_protocol in scopes:
            ticket = ticket_cache.take(server_name, candidate_protocol,
                client_ticket_context(binding, candidate_protocol))
            if ticket is not None:
                if binding is not None:
                    resolved, _ = resolve_bootstrap_identity(ticket.external_psk_identity, bootstrap_bindings, service=server_name)
                    if resolved != binding or ticket.external_psk_identity not in bootstrap_offer_bindings:
                        raise ProtocolError("bootstrap ticket scope differs from its selected BSK")
                    bootstrap_binding = binding
                    provisioning_trust = binding.trust_mode == "provisioning-trust"
                protocol = candidate_protocol
                roots_hash = client_ticket_context(binding, protocol)
                break
    # Changing a local offer is not authority to widen a cached ticket's modes.
    # With no overlap, retry normal authentication without sending early bytes.
    if ticket is not None and not set(psk_modes).intersection(ticket.allowed_psk_modes):
        ticket = None
    if (ticket is not None and credential_policy is not None and credential_policy.dane_policy is not None
            and ticket.credential_expires_at is None):
        ticket = None  # Missing original DNS TTL is not authority for cached early data.
    credential_expires_at = ticket.credential_expires_at if ticket is not None else None
    traffic_private = None
    secrets = HandshakeSecrets()
    try:
        async with asyncio.timeout(timeout):
            if ticket is not None and mixed_password and ticket.pake_identity:
                if ticket.pake_identity != password_credential.identity:
                    ticket = None
                else:
                    from .pake_handshake import client as password_client
                    ticket_cache.put(ticket)
                    authenticator_offers = list(certificate_evidence_extensions)
                    if delegated_credentials:
                        authenticator_offers += [(34, b"\x00\x02\xfe\x00"),
                            (0xff04,m._vec(b"".join(value.to_bytes(2,"big") for value in grant_algorithms),2))]
                    return await password_client(reader,writer,password_credential,timeout=timeout,
                        application_protocols=application_protocols,
                        cipher_suites=tuple(value for value in cipher_suites if c.suite(value).password_authenticated),
                        groups=tuple(value for value in enabled_groups if value in PASSWORD_GROUPS),
                        ticket_cache=ticket_cache,early_data=early_data,record_size_limit=record_size_limit,
                        max_fragment_length=max_fragment_length,
                        heartbeat_mode=heartbeat_mode,ticket_request=ticket_request,signaling=signaling,
                        send_server_name=send_server_name,require_alpn=require_alpn,diagnostics=diagnostics,
                        on_exporter=on_exporter,on_early_exporter=on_early_exporter,_ticket_context=roots_hash,
                        enable_authenticators=enable_authenticators,
                        authenticator_extensions=tuple(authenticator_offers) if enable_authenticators else (),
                        authenticator_certificate_algorithms=certificate_algorithms)
            offered_suites = tuple(c.suite(value) for value in cipher_suites)
            if any(not value.confidential for value in offered_suites) and allow_non_confidential is not True:
                raise ProtocolError("non-confidential operation was not explicitly enabled")
            if any(value.combined for value in provisioned_psks) and any(not value.confidential for value in offered_suites):
                raise ProtocolError("combined PSK requires confidentiality")
            if not offered_suites:
                raise ProtocolError("empty cipher offer")
            if ticket and not any(value.hash_name == c.suite(ticket.cipher_suite).hash_name for value in offered_suites):
                ticket = None
            client_extra = []
            if pin_attempt is not None:
                client_extra.append((32, pin_attempt.extension))
            client_extra.extend(client_controls(heartbeat=heartbeat_mode, tickets=ticket_request, signaling=signaling))
            if max_fragment_length is not None:
                client_extra.append((1, bytes((max_fragment_length,))))
            if record_size_limit is not None:
                client_extra.append((28, local_limit.to_bytes(2, "big")))
            if server_certificate_types != (0,):
                client_extra.append((20, m._vec(bytes(server_certificate_types), 1)))
            if credential_candidates:
                client_extra.append((19, m._vec(bytes(offered_client_types), 1)))
            if server_certificate_authorities:
                client_extra.append((47, encode_certificate_authorities(server_certificate_authorities)))
            if certificate_compression:
                client_extra.append((27, m._vec(b"".join(value.to_bytes(2,"big") for value in certificate_compression),1)))
            if delegated_credentials:
                client_extra += [(34, b"\x00\x02\xfe\x00"),
                    (0xff04, m._vec(b"".join(value.to_bytes(2,"big") for value in grant_algorithms),2))]
            client_extra.extend(certificate_evidence_extensions)
            snapshots = tuple((kind, tuple(bytes(value) for value in material)) for kind, material in cached_certificates)
            request_snapshots = tuple(bytes(value) for value in cached_requests)
            cache_objects = tuple((1, material_hash(material, kind)) for kind, material in snapshots)
            cache_objects += tuple((2, request_template_hash(value)) for value in request_snapshots)
            if cache_objects:
                encoded_cache = m._vec(b"".join(bytes((kind,)) + m._vec(value, 1) for kind, value in cache_objects), 2)
                _cache_offer(encoded_cache)
                client_extra.append((25, encoded_cache))
            credential_offers = ((50, m._vec(b"".join(value.to_bytes(2,"big") for value in certificate_algorithms),2)), *client_extra)
            if ticket and ticket.certificate_chain:
                try:
                    if provisioning_trust:
                        from .bootstrap_credentials import provisioning_server_key
                        provisioning_server_key(ticket.certificate_chain, ticket.certificate_type,
                            binding=bootstrap_binding, entry_extensions=ticket.certificate_extensions, normal_httpps=normal_httpps)
                    elif credential_policy is not None:
                        cached_credential = _resolve_credential(ticket.certificate_chain, ticket.certificate_extensions,
                            role="server", credential_type=ticket.certificate_type,
                            policy=credential_policy, offers=credential_offers,
                            feature_offers=set(ticket.certificate_feature_offers) | (set(dict(credential_offers)) & {5, 18, 52}),
                            negotiated_extensions=ticket.certificate_features)
                        if cached_credential.expires_at is not None:
                            refreshed_expiry = cached_credential.expires_at.timestamp()
                            credential_expires_at = (min(credential_expires_at, refreshed_expiry)
                                if credential_expires_at is not None else refreshed_expiry)
                    else:
                        validate_chain(ticket.certificate_chain, trust_roots, server_name, revocation_policy)
                        _check_lab_features(ticket.certificate_chain,
                            tuple(pair for pair in credential_offers if pair[0] in (5, 18, 52)), ())
                except ProtocolError:
                    # Stale authentication state is not authority to resume.
                    # A normal full handshake can validate a renewed credential.
                    ticket = None
            elif ticket and not provisioned_psks:
                ticket = None
            if ticket is not None:
                psk_modes = tuple(mode for mode in psk_modes if mode in ticket.allowed_psk_modes)
            offered_psks = (ticket,) if ticket else tuple(value for value in provisioned_psks
                if any(candidate.hash_name == value.hash_name and candidate.confidential == c.suite(value.cipher_suite).confidential
                       for candidate in offered_suites))
            if provisioned_psks and not offered_psks:
                raise ProtocolError("no provisioned PSK compatible with offered suites")
            external = offered_psks[0] if ticket is None and offered_psks else None
            if external is not None:
                ticket = external
                protocol = external.protocol
            combined = bool(external and external.combined)
            if combined and 1 not in psk_modes:
                raise ProtocolError("a fresh combined PSK exchange requires the DHE mode")
            psk_only = bool(ticket and not combined and tuple(psk_modes) == (0,))
            if mixed_password and ticket is None:
                client_extra.append(password_credential.name_extension())
                force_retry = True
            if psk_only and force_retry:
                raise ValueError("PSK-only exchange has no DHE retry")
            wire.check_deadline()
            offer_early = bool(ticket and ticket.cipher_suite in cipher_suites and early_data
                               and len(early_data) <= ticket.max_early_data)
            auth_private = X25519PrivateKey.generate()
            traffic_private, traffic_public = (None, b"") if psk_only else secrets.traffic_key(traffic_group, provider=native_provider)
            auth_public = c.public_bytes(auth_private)
            if auth_public == c.traffic_auth_component(traffic_group, traffic_public):
                raise ProtocolError("non-independent key shares")
            if any(c.public_bytes(value.private_key) in (auth_public, c.traffic_auth_component(traffic_group, traffic_public))
                    for value in credential_candidates):
                raise ProtocolError("client credential key must be independent of ephemeral keys")
            random = os.urandom(32)
            psk_hash = c.hash_context(c.suite(ticket.cipher_suite).hash_name,native_provider) if ticket else None
            psk_length = c.suite(ticket.cipher_suite).hash_length if ticket else 0
            options = {"early_data": offer_early}
            options.update(group=0 if psk_only else traffic_group, empty_share=force_retry,
                           post_handshake_auth=post_handshake_auth,
                           cipher_suites=cipher_suites, psk_modes=psk_modes, combined_psk=combined,
                           protocol=application_protocols, certificate_algorithms=certificate_algorithms,
                           supported_groups=enabled_groups)
            options["extra_extensions"] = tuple(client_extra)
            def bound_hello(prefix):
                placeholders = tuple((value.identity, value.obfuscated_age(), bytes(c.suite(value.cipher_suite).hash_length))
                                     for value in offered_psks)
                options["psk_offers"] = placeholders
                message = m.client_hello(auth_public, traffic_public, server_name if send_server_name else "", random, **options)
                if placeholders:
                    truncated = prefix + message[:-(2 + sum(1 + len(proof) for _, _, proof in placeholders))]
                    options["psk_offers"] = tuple((identity, age, c.binder(value.psk, truncated,
                        hash_name=c.hash_context(c.suite(value.cipher_suite).hash_name,native_provider),
                        kind=value.binder_kind if isinstance(value, ExternalPSK) else "res"))
                        for value, (identity, age, _) in zip(offered_psks, placeholders))
                    message = m.client_hello(auth_public, traffic_public, server_name if send_server_name else "", random, **options)
                return message
            ch = bound_hello(c.PREFACE)
            if (offer_early and external is None and ticket.certificate_type == 0
                    and ticket.certificate_chain):
                from .tls_features import certificate_features
                required = certificate_features(x509.load_der_x509_certificate(ticket.certificate_chain[0]))
                offered = m.parse_client_hello(ch[4:], password_authenticated=False).extensions
                if required.intersection(offered) - {5, 18, 25, 27, 52, 0xff02}:
                    # Current SH/EE requirements cannot be assumed from a
                    # predecessor. Do not release bytes before checking them.
                    offer_early = options["early_data"] = False
                    ch = bound_hello(c.PREFACE)
            transcript.add(ch)
            writer.write(c.PREFACE)
            await wire.send_frame(ch)
            wire.allow_ccs = True
            early_exporter = None
            if ticket:
                early_root = c.extract(bytes(psk_length), ticket.psk, psk_hash)
                early_exporter = c.derive_secret(early_root, "e exp master", transcript.snapshot(), psk_hash)
                emit_diagnostic(diagnostics, "TLS20_EARLY_EXPORTER_SECRET", random, early_exporter)
                await expose_exporter(on_early_exporter, early_exporter, exporter_accesses,
                                      stage="early", role="client", hash_name=psk_hash)
            if offer_early:
                early_sender = secrets.record(c.derive_secret(early_root,
                    "c e traffic", transcript.snapshot(), psk_hash), "seal", ticket.cipher_suite,
                    ticket.record_size_limit, provider=native_provider)
                emit_diagnostic(diagnostics, "TLS20_CLIENT_EARLY_TRAFFIC_SECRET", random, early_sender.secret)
                early_chunk = min(16384, ticket.record_size_limit - 1)
                for offset in range(0, len(early_data), early_chunk):
                    if bootstrap_binding is not None:
                        current_bootstrap_bindings(bootstrap_binding, service=server_name)
                    writer.write(early_sender.seal(early_data[offset:offset+early_chunk], 23))
                await writer.drain()
            sh = await wire.receive_frame(2, boundary=True)
            ephemeral_public, sid, resumed, group, retry, cookie, selected_id = m.parse_server_hello(sh[4:], with_suite=True)
            retried = retry
            retry_features = (44,) if retry and cookie else ()
            if selected_id not in cipher_suites:
                raise ProtocolError("unoffered server cipher suite", alert=47)
            selected = c.suite(selected_id)
            schedule = c.KeySchedule(c.hash_context(selected.hash_name,native_provider))
            if selected.password_authenticated:
                if not mixed_password or not retry or resumed or ticket is not None:
                    raise ProtocolError("unsolicited password authentication selection")
                from .pake_handshake import client as password_client
                return await password_client(reader,writer,password_credential,timeout=timeout,
                    application_protocols=application_protocols,cipher_suites=cipher_suites,
                    groups=tuple(value for value in enabled_groups if value in PASSWORD_GROUPS),
                    ticket_cache=ticket_cache,record_size_limit=record_size_limit,
                    max_fragment_length=max_fragment_length,
                    heartbeat_mode=heartbeat_mode,ticket_request=ticket_request,signaling=signaling,
                    send_server_name=send_server_name,require_alpn=require_alpn,diagnostics=diagnostics,
                    on_exporter=on_exporter,on_early_exporter=on_early_exporter,
                    _first_flight=(wire,ch,sh),_ticket_context=roots_hash,
                    enable_authenticators=enable_authenticators,_auth_share_secret=auth_private)
            if retry:
                if group and (psk_only or group not in enabled_groups):
                    raise ProtocolError("unoffered HelloRetryRequest group", alert=47)
                if sid or (group and not force_retry and group == traffic_group) or (not group and not cookie):
                    raise ProtocolError("useless HelloRetryRequest", alert=47)
                # Connection-scoped API policy, not a prohibition on deriving
                # early exporters in every protocol that uses HRR. Revoke now,
                # before an awaited CH2/ServerHello can expose a stale handle.
                early_exporter = None
                for access in exporter_accesses:
                    if access.stage == "early":
                        access.close()
                transcript.retry(ch, sh, schedule.hash_name)
                if group:
                    secrets.close_key(traffic_private)
                    traffic_private, traffic_public = secrets.traffic_key(group, provider=native_provider)
                    traffic_group = group
                options.update(group=0 if psk_only else traffic_group,
                               empty_share=force_retry if not group else False,
                               early_data=False, cookie=cookie)
                offered_psks = tuple(value for value in offered_psks if c.suite(value.cipher_suite).hash_name == selected.hash_name)
                ch = bound_hello(transcript.snapshot())
                transcript.add(ch)
                await wire.send_frame(ch)
                offer_early = False
                sh = await wire.receive_frame(2, boundary=True)
                ephemeral_public, sid, resumed, group, retry, cookie, final_suite = m.parse_server_hello(
                    sh[4:], with_suite=True, after_retry=True)
                if retry:
                    raise ProtocolError("second HelloRetryRequest", alert=10)
                if final_suite != selected_id:
                    raise ProtocolError("cipher suite changed after retry", alert=47)
            selection_extensions = m.server_hello_extensions(sh[4:])
            psk_index = int.from_bytes(selection_extensions[41], "big") if resumed else None
            if sid:
                raise ProtocolError("server did not echo the legacy session id", alert=47)
            if resumed and not offered_psks:
                raise ProtocolError("unsolicited PSK selection", alert=110)
            if resumed and psk_index >= len(offered_psks):
                raise ProtocolError("PSK selection is outside the offered identities", alert=47)
            if resumed:
                ticket = offered_psks[psk_index]
                external = ticket if isinstance(ticket, ExternalPSK) else None
            if not resumed or psk_index != 0 or retried:
                early_exporter = None
                for access in exporter_accesses:
                    if access.stage == "early":
                        access.close()
            selected_combined = 33 in selection_extensions
            if selected_combined != (combined and resumed):
                raise ProtocolError("combined PSK authentication selection mismatch")
            if provisioned_psks and not resumed:
                # An explicitly provisioned external PSK is not permission to
                # silently fall back to a credential-only identity, including
                # when the declined offer was its descendant session ticket.
                raise ProtocolError("server declined the required provisioned PSK")
            selected_external_identity = external.identity if external is not None else ticket.external_psk_identity if resumed else b""
            if bootstrap_binding is not None:
                if selected_external_identity not in bootstrap_offer_bindings:
                    raise ProtocolError("bootstrap PSK lineage changed")
                bootstrap_binding, _ = resolve_bootstrap_identity(selected_external_identity,
                    bootstrap_bindings, service=server_name)
                provisioning_trust = bootstrap_binding.trust_mode == "provisioning-trust"
                roots_hash = client_ticket_context(bootstrap_binding, protocol)
            if resumed and c.suite(ticket.cipher_suite).hash_name != selected.hash_name:
                raise ProtocolError("PSK is incompatible with selected hash", alert=47)
            if resumed and c.suite(ticket.cipher_suite).confidential != selected.confidential:
                raise ProtocolError("PSK confidentiality policy cannot change")
            if (not group and (not resumed or 0 not in psk_modes)) or (group and 1 not in psk_modes and resumed):
                raise ProtocolError("unoffered PSK key exchange mode", alert=47)
            if group and group != traffic_group:
                raise ProtocolError("server selected an unoffered share", alert=47)
            if c.traffic_auth_component(group, ephemeral_public) and c.traffic_auth_component(group, ephemeral_public) in (
                    auth_public, c.traffic_auth_component(traffic_group, traffic_public)):
                raise ProtocolError("non-independent key shares")
            transcript.add(sh)
            pinning_transcript = transcript.snapshot()
            traffic_root = c.handshake_secret(c.traffic_dh(traffic_private, group, ephemeral_public, provider=native_provider)
                                              if group else bytes(selected.hash_length),
                                              ticket.psk if resumed else None, schedule.hash_name)
            client_secret, server_secret = handshake_keys(traffic_root, transcript, schedule.hash_name)
            emit_diagnostic(diagnostics, "TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET", random, client_secret)
            emit_diagnostic(diagnostics, "TLS20_SERVER_HANDSHAKE_TRAFFIC_SECRET", random, server_secret)
            sender = secrets.record(client_secret, "seal", selected_id, provider=native_provider)
            # Until EE confirms RSL, an unaware server may legally use the
            # protocol limit. Retain the largest decrypted record so an EE
            # that accepts RSL can also be checked retroactively, padding and
            # fragments included, before any credential/application processing.
            receiver = secrets.record(server_secret, "open", selected_id, provider=native_provider)
            ee = await wire.receive_frame(8, receiver)
            accepted, protocol, selected_extensions = m.parse_encrypted_extensions(ee[4:], application_protocols,
                                    offered_early=offer_early, with_extensions=True,
                                    offered_name=send_server_name, require_alpn=require_alpn,
                                    allowed_extensions=((10,) if options["group"] else ()) + tuple(
                                        kind for kind, _ in client_extra if kind in (1, 15, 19, 20, 25, 28, 32, 55, 56, 58)))
            send_limit = _peer_record_limit(selected_extensions[28]) if 28 in selected_extensions else 16385
            receive_limit = local_limit if 28 in selected_extensions else 16385
            if 1 in selected_extensions:
                fragment_limit = _peer_fragment_limit(selected_extensions[1])
                if 28 in selected_extensions or max_fragment_length is None or selected_extensions[1] != bytes((max_fragment_length,)):
                    raise ProtocolError("invalid maximum fragment selection", alert=47)
                send_limit = receive_limit = fragment_limit
            if receiver.max_opened_plaintext > receive_limit:
                raise ProtocolError("EncryptedExtensions record exceeds negotiated limit", alert=22)
            sender.record_limit, receiver.record_limit = send_limit, receive_limit
            controls = client_control_selection(selected_extensions, heartbeat=heartbeat_mode,
                                                 tickets=ticket_request, signaling=signaling)
            cache_selected = ()
            if 25 in selected_extensions:
                reader_cache = m._Reader(selected_extensions[25]); cache_selected = tuple(reader_cache.vector(2)); reader_cache.end()
                if (not cache_selected or len(set(cache_selected)) != len(cache_selected)
                        or any(kind not in {value[0] for value in cache_objects} for kind in cache_selected)
                        or 1 in cache_selected and resumed and not selected_combined):
                    raise ProtocolError("invalid cached object selection", alert=47)
            certificate_type = selected_extensions.get(20, b"\x00")
            if len(certificate_type) != 1:
                raise ProtocolError("malformed server credential type", alert=50)
            if (not resumed or selected_combined) and certificate_type[0] not in server_certificate_types:
                raise ProtocolError("unoffered server credential type", alert=47)
            certificate_type = certificate_type[0]
            client_type = selected_extensions.get(19, b"\x00")
            if len(client_type) != 1:
                raise ProtocolError("malformed client credential type", alert=50)
            if 19 in selected_extensions and client_type[0] not in offered_client_types:
                raise ProtocolError("unoffered client credential type", alert=47)
            if resumed and external is None:
                client_type = bytes((ticket.client_certificate_type,))
            if bootstrap_binding is not None and external is not None:
                # The imported bootstrap identity is TLS-protocol separated;
                # the explicit application offer authorizes its fresh ALPN.
                # Descendant tickets retain one exact negotiated ALPN.
                from dataclasses import replace
                external = replace(external, protocol=protocol)
                ticket = external
            if resumed and ticket.protocol != protocol:
                raise ProtocolError("PSK application protocol binding mismatch")
            if bootstrap_binding is not None:
                roots_hash = client_ticket_context(bootstrap_binding, protocol)
            if accepted and (not resumed or psk_index != 0 or ticket.cipher_suite != selected_id):
                raise ProtocolError("early data requires selected PSK", alert=47)
            transcript.add(ee)
            # Use the final, serialized ClientHello (including HRR changes),
            # not the subset of extras assembled for certificate evidence.
            credential_offers = m.parse_client_hello(ch[4:], password_authenticated=False).extension_values
            feature_selections = set(selection_extensions) | set(selected_extensions) | set(retry_features)
            chain_der = ticket.certificate_chain if resumed else []
            certificate_metadata = ticket.certificate_extensions if resumed and external is None else ()
            if resumed and external is None:
                certificate_type = ticket.certificate_type
            client_auth_request = None
            learned_requests = []
            certificate_features = _certificate_feature_state(credential_offers, feature_selections,
                certificate_metadata=certificate_metadata)
            if resumed and external is None and not selected_combined and chain_der:
                # No new Certificate/MAC flight is carried by this PSK
                # resumption of an authenticated credential lineage. Its
                # cached-info, compression and auth-share requirements are
                # redundant (RFC7633 §4), not missing fresh authentication.
                redundant = {25, 27, 0xff02}.intersection(dict(credential_offers))
                certificate_features = tuple(sorted(set(certificate_features) | redundant))
                if credential_policy is not None:
                    _resolve_credential(chain_der, certificate_metadata, role="server",
                        credential_type=certificate_type, policy=credential_policy, offers=credential_offers,
                        negotiated_extensions=certificate_features)
                elif not provisioning_trust:
                    _check_lab_features(chain_der, credential_offers, certificate_features)
            if not resumed or selected_combined:
                cert = await wire.receive_frame((11, 13, 25, 252, 253), receiver)
                if cert[0] in (13, 252):
                    client_auth_request = _decode_request(cert, cache_enabled=2 in cache_selected, templates=request_snapshots)
                    learned_requests.append(b"".join(m.extension(kind, value) for kind, value in client_auth_request[3].items()))
                    if client_auth_request[0]:
                        raise ProtocolError("initial certificate request context must be empty")
                    transcript.add(cert)
                    cert = await wire.receive_frame((11, 25, 253), receiver)
                chain_der, certificate_metadata = _decode_credential(cert, offered_compression=certificate_compression,
                    cached=1 in cache_selected, snapshots=snapshots, credential_type=certificate_type)
                _check_credential_extension_offers(certificate_metadata, credential_offers)
                certificate_features = _certificate_feature_state(credential_offers, feature_selections,
                    certificate_message=cert[0], certificate_metadata=certificate_metadata,
                    authenticated_by_mac=True)
                if unauthenticated:
                    if certificate_type not in (0, 2) or any(certificate_metadata):
                        raise ProtocolError("unauthenticated operation cannot claim delegated or auxiliary credential authority")
                    if certificate_type == 2:
                        if len(chain_der) != 1:
                            raise ProtocolError("raw public key credential must have one entry")
                        static_key = parse_x25519_spki(chain_der[0])
                    else:
                        try:
                            static_key = x509.load_der_x509_certificate(chain_der[0]).public_key()
                        except (ValueError, IndexError) as error:
                            raise ProtocolError("malformed unauthenticated X.509 key") from error
                        c.public_bytes(static_key)  # Structural X25519 requirement, not trust.
                elif provisioning_trust:
                    from .bootstrap_credentials import provisioning_server_key
                    static_key = provisioning_server_key(chain_der, certificate_type,
                        binding=bootstrap_binding, entry_extensions=certificate_metadata, normal_httpps=normal_httpps).public_key
                elif credential_policy is not None:
                    authorized = _resolve_credential(chain_der, certificate_metadata, role="server",
                        credential_type=certificate_type, policy=credential_policy, offers=credential_offers,
                        negotiated_extensions=certificate_features)
                    static_key = authorized.public_key
                    credential_expires_at = authorized.expires_at.timestamp() if authorized.expires_at is not None else None
                else:
                    if certificate_type != 0 or any(certificate_metadata):
                        raise ProtocolError("extended server credentials require an explicit policy")
                    _check_certificate_offer(chain_der, certificate_algorithms, native_provider)
                    static_key = validate_chain(chain_der, trust_roots, server_name, revocation_policy)
                    _check_lab_features(chain_der, credential_offers, certificate_features)
                wire.check_deadline()
                static_public = c.public_bytes(static_key)
                if static_public in (auth_public, c.traffic_auth_component(traffic_group, traffic_public),
                                      c.traffic_auth_component(group, ephemeral_public)):
                    raise ProtocolError("non-independent certified key")
                transcript.add(cert)
                auth_root = schedule.authentication_root(traffic_root, c.dh(auth_private, static_public), transcript.snapshot())
                cv = await wire.receive_frame(15, receiver)
                if cv[4:6] != b"\xfe\x00" or not schedule.verify_proof(auth_root, transcript.snapshot(), cv[8:]):
                    raise ProtocolError("server authentication verification failed", alert=51)
                transcript.add(cv)
            sf = await wire.receive_frame(20, receiver, boundary=True)
            if not schedule.verify_finished(server_secret, transcript.snapshot(), sf[4:]):
                raise ProtocolError("server Finished verification failed", alert=51)
            transcript.add(sf)
            if pin_attempt is not None:
                effective_spki = static_key.public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                pin_attempt.verify(selected_extensions.get(32), traffic_root, pinning_transcript,
                                   effective_spki, authenticated=True, hash_name=schedule.hash_name)
            client_app, server_app = application_keys(traffic_root, transcript, schedule.hash_name)
            exporter = schedule.derive_secret(schedule.master_secret(traffic_root), "exp master", transcript.snapshot())
            emit_diagnostic(diagnostics, "TLS20_CLIENT_TRAFFIC_SECRET_0", random, client_app)
            emit_diagnostic(diagnostics, "TLS20_SERVER_TRAFFIC_SECRET_0", random, server_app)
            emit_diagnostic(diagnostics, "TLS20_EXPORTER_SECRET", random, exporter)
            await expose_exporter(on_exporter, exporter, exporter_accesses,
                stage="server-finished", role="client", peer_authenticated=not unauthenticated, hash_name=schedule.hash_name)
            if bootstrap_binding is not None and selected_combined:
                from .bootstrap_credentials import bootstrap_client_material
                bootstrap_client_material(bootstrap_binding, server_mac_verified=True,
                    server_finished_verified=True, combined=selected_combined, fresh_key_share=bool(group),
                    initial_early_data=offer_early, client_credential_type=client_type[0],
                    client_request_present=client_auth_request is not None)
            if bootstrap_binding is not None:
                current_bootstrap_bindings(bootstrap_binding, service=server_name)
                candidates = tuple(value for value in credential_candidates if value.credential_type == 2
                    and tuple(value.chain_der) == (bootstrap_binding.spki,))
                if len(candidates) != 1:
                    raise ProtocolError("bootstrap client credential changed before release")
                client_credentials = candidates[0]
                credential_candidates = candidates
            if accepted:
                eoed = m.frame(5, b"")
                await wire.send_frame(eoed, early_sender)
                transcript.add(eoed)
            if client_auth_request is not None:
                context, share, algorithms, request_extensions = client_auth_request
                candidates = preferred_credentials((value for value in (
                    (client_credentials,) if bootstrap_binding is not None else credential_candidates)
                    if value.credential_type == client_type[0]), request_extensions,
                    role="client", signature_provider=native_provider)
                client_credentials = candidates[0] if candidates else None
                messages = _client_auth_messages(client_credentials, context, share,
                    algorithms, exporter, transcript.data, request_extensions=request_extensions.items(),
                    hash_name=schedule.hash_name, signature_provider=native_provider)
                for message in messages:
                    await wire.send_frame(message, sender)
            cf = m.frame(20, schedule.finished(client_secret, transcript.snapshot()))
            await wire.send_frame(cf, sender)
            sender = secrets.record(client_app, "seal", selected_id, send_limit, provider=native_provider)
            if pin_attempt is not None:
                pin_attempt.commit()
            transcript.add(cf)
            wire.check_deadline()
            bootstrap_authorization = None
            if bootstrap_binding is not None:
                bootstrap_authorization = {"profile": "tls20-pok", "scope": bootstrap_binding.scope,
                    "service": bootstrap_binding.service, "trust_mode": bootstrap_binding.trust_mode,
                    "bsk": bootstrap_binding.spki, "fresh_client_possession": selected_combined,
                    "peer_authorization_confirmed": False}
            ticket_feature_offers = ()
            if certificate_type == 0 and chain_der:
                from .tls_features import certificate_features as required_certificate_features
                ticket_feature_offers = tuple(sorted(required_certificate_features(
                    x509.load_der_x509_certificate(chain_der[0])).intersection(dict(credential_offers))))
            channel = SecureChannel(wire, client_app, server_app, exporter_secret=exporter,
                resumption_secret=schedule.derive_secret(schedule.master_secret(traffic_root), "res master", transcript.snapshot()),
                ticket_cache=None if unauthenticated else ticket_cache, name=server_name, context=roots_hash, certificate_chain=chain_der,
                resumed=resumed and external is None, early_data_accepted=accepted, handshake_transcript=transcript.snapshot(),
                client_credentials=client_credentials, local_post_handshake_auth=post_handshake_auth
                    and protocol != b"h2" and (external is None or selected_combined),
                cipher_suite=selected_id, protocol=protocol, role="client", enable_authenticators=enable_authenticators,
                auth_share_secret=auth_private, local_capabilities=m.parse_client_hello(ch[4:],password_authenticated=False).extension_values,
                early_exporter_secret=early_exporter if resumed else None,
                psk_provenance="unauthenticated" if unauthenticated else external.binder_kind if external else "res" if resumed else "credential",
                receive_record_limit=receive_limit, send_record_limit=send_limit,
                certificate_type=certificate_type, certificate_extensions=certificate_metadata,
                cache_types=cache_selected, cached_request_templates=request_snapshots,
                client_request_templates=learned_requests, client_certificate_type=client_type[0],
                selected_external_psk_identity=selected_external_identity, bootstrap_binding=bootstrap_binding,
                bootstrap_authorization=bootstrap_authorization,
                credential_expires_at=credential_expires_at,
                certificate_feature_offers=ticket_feature_offers,
                certificate_features=tuple(value for value in certificate_features if value in ticket_feature_offers),
                allowed_psk_modes=tuple(mode for mode in psk_modes if mode in (0, 1)),
                heartbeat_local_mode=controls.heartbeat_local_mode, heartbeat_peer_mode=controls.heartbeat_peer_mode,
                peer_authenticated=not unauthenticated, native_provider=native_provider)
            secrets.establish(channel)
            channel.client_credential_candidates = credential_candidates
            channel.expected_ticket_count = controls.expected_tickets
            for access in exporter_accesses:
                access.complete(peer_authenticated=not unauthenticated)
            channel._exporter_accesses = tuple(exporter_accesses)
            return secrets.release(channel)
    except ProtocolError as error:
        for access in exporter_accesses:
            access.close()
        await wire.fatal(error, sender)
        raise
    except BaseException:
        for access in exporter_accesses:
            access.close()
        writer.transport.abort()
        raise
    finally:
        secrets.close()
