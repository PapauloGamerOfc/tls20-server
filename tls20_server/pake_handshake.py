"""Real RFC8492 password handshake and explicitly authorized successor PSKs.

The required-password endpoint has no certificate/external-PSK fallback. Native
commitments authenticate only the configured account and service. Fresh PWD
never sends credentials, client-auth requests or early application data.
"""

import asyncio
import hmac
import os

from . import crypto as c, messages as m
from .errors import ProtocolError
from .pake import PasswordCredential, PasswordServer, SUITES, RESUMPTION_SUITES, password_base
from .handshake_options import client_controls, server_controls, client_control_selection
from .diagnostics import emit as emit_diagnostic
from .exporter_access import expose as expose_exporter
from .pake_native import GROUPS


async def _native_work(operation, *, discard=None):
    """Keep slow FFC work off the event loop without abandoning native state.

    OpenSSL work cannot be interrupted safely. A cancelled handshake retains
    its admission slot until this bounded operation ends, consumes its result,
    and frees any newly returned state before propagating cancellation.
    """
    task = asyncio.create_task(asyncio.to_thread(operation))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        try:
            result = task.result()
            if discard is not None:
                discard(result)
        except Exception:
            pass
        raise


def _server_commit(provider, base, random, group, hash_name, peer):
    state = provider.create(base, random, group=group, hash_name=hash_name)
    try:
        return state.commit(), state.finish(peer)
    finally:
        state.close()


def _client_commit(provider, base, random, group, hash_name):
    state = provider.create(base, random, group=group, hash_name=hash_name)
    try:
        return state, state.commit()
    except BaseException:
        state.close()
        raise


async def _next_after_retry(wire, early):
    discarded = 0
    while True:
        record = await wire.raw_record()
        if record[0] == 20 and record[5:] == b"\x01":
            continue
        if record[0] == 21:
            wire.process_alert(record[5:])
            continue
        if record[0] == 22:
            wire.pending.extend(record[5:])
            return await wire.receive_frame(1, boundary=True)
        discarded += len(record)
        if not early or record[0] != 23 or discarded > 1048576:
            raise ProtocolError("unexpected record after PWD retry")


def _log(diagnostics, random, client, server, *, application=False):
    suffix = "TRAFFIC_SECRET_0" if application else "HANDSHAKE_TRAFFIC_SECRET"
    emit_diagnostic(diagnostics, "TLS20_CLIENT_" + suffix, random, client)
    emit_diagnostic(diagnostics, "TLS20_SERVER_" + suffix, random, server)


async def server(reader, writer, policy, *, timeout=10, application_protocols=(b"http/1.1",),
                 cipher_suites=SUITES, ticket_store=None, max_early_data=0, on_early_data=None,
                 record_size_limit=None, heartbeat_mode=None, ticket_count_limit=1, signaling=None,
                 require_server_name=True, require_alpn=True, diagnostics=None,
                 on_exporter=None, on_early_exporter=None, groups=tuple(GROUPS), enable_authenticators=False,
                 retry_cookie_policy=None):
    from .handshake import (Wire, Transcript, SecureChannel, check_timeout, handshake_keys, application_keys,
                            _record_limit, _peer_record_limit, _peer_fragment_limit, _retry_psks_unchanged)
    check_timeout(timeout)
    from .retry_cookie import RetryCookiePolicy, validate_retry_cookie
    if retry_cookie_policy is not None and not isinstance(retry_cookie_policy, RetryCookiePolicy):
        raise ValueError("explicit RetryCookiePolicy required")
    if not isinstance(policy, PasswordServer):
        raise ValueError("explicit password server policy required")
    if not cipher_suites or any(type(value) is not int or value not in SUITES for value in cipher_suites) or len(set(cipher_suites)) != len(cipher_suites):
        raise ValueError("invalid explicit password cipher-suite policy")
    if not groups or any(type(value) is not int or value not in GROUPS for value in groups) or len(set(groups)) != len(groups):
        raise ValueError("invalid explicit password group policy")
    wire, transcript = Wire(reader, writer), Transcript()
    wire.deadline = asyncio.get_running_loop().time() + timeout
    sender = state = None
    exporter_accesses = []
    acquired = bootstrap = False
    try:
        async with asyncio.timeout(timeout):
            if await wire.exact(len(c.PREFACE)) != c.PREFACE:
                raise ProtocolError("not TLS 2.0")
            bootstrap = True
            ch = await wire.receive_frame(1, boundary=True)
            hello = m.parse_client_hello(ch[4:]); initial_ch = ch
            ext = dict(hello.extension_values)
            if 32 in ext or 33 in ext or 44 in ext:
                raise ProtocolError("PWD mode cannot combine pinning, combined PSK or unsolicited cookies")
            if hello.name != policy.service and (hello.name or require_server_name and not m.is_ip_identity(policy.service)):
                raise ProtocolError("unsupported password service", alert=112)
            protocol = next((value for value in application_protocols if value in hello.protocols), b"")
            if not protocol and (require_alpn or application_protocols and hello.protocols):
                raise ProtocolError("no application protocol", alert=120)
            send_limit = _peer_record_limit(ext[28], server=True) if 28 in ext else 16385
            receive_limit = _record_limit(record_size_limit) if 28 in ext else 16385
            if 1 in ext and 28 not in ext:
                send_limit = receive_limit = _peer_fragment_limit(ext[1])
            context = policy.context(protocol) + (signaling.context() if signaling is not None else b"")
            ticket = None
            identity_index = 0
            pwd = bool({29, 30} & set(ext))
            if pwd:
                selected_id = next((value for value in cipher_suites if value in hello.cipher_suites and value in SUITES), None)
            else:
                if ticket_store is None or not hello.psk_offers:
                    raise ProtocolError("required password authentication is unavailable")
                successors = tuple(dict.fromkeys(RESUMPTION_SUITES[value] for value in cipher_suites))
                selected_id = None
                for index, (identity_bytes, age, binder) in enumerate(hello.psk_offers):
                    candidate = ticket_store.lookup(identity_bytes, policy.service, protocol, context)
                    if (candidate is None or not candidate.pake_identity
                            or not set(candidate.allowed_psk_modes).intersection(hello.psk_modes)):
                        continue
                    compatible = tuple(value for value in successors if value in hello.cipher_suites
                        and c.suite(value).hash_name == c.suite(candidate.cipher_suite).hash_name)
                    if compatible:
                        ticket, identity_index = candidate, index
                        selected_id = candidate.cipher_suite if candidate.cipher_suite in compatible else compatible[0]
                        break
                if ticket is None:
                    raise ProtocolError("password session is no longer authorized")
            if selected_id is None:
                raise ProtocolError("no acceptable password-mode cipher suite")
            selected, schedule = c.suite(selected_id), c.KeySchedule(c.suite(selected_id).hash_name)
            if ticket is not None and len(binder) != selected.hash_length:
                raise ProtocolError("password session binder has the wrong hash length", alert=51)
            wire.allow_ccs = True
            if pwd:
                identity, account, authorized = policy.acquire(ext); acquired = True
                group = next((value for value in groups if value in hello.share_groups),
                             next((value for value in groups if value in hello.groups), 0))
                if not group:
                    raise ProtocolError("no supported password group")
                # A selected PWD exchange rejects every PSK/early-data offer.
                # Salt or an empty/mixed CH requires exactly one useful HRR.
                retry = (account.salt is not None or not hello.B or hello.group != group
                         or hello.early_data or retry_cookie_policy is not None)
                if retry:
                    retry_cookie = (retry_cookie_policy.issue(writer, ch, selected_id, group)
                                    if retry_cookie_policy is not None else b"")
                    hrr = m.server_hello(b"", bytes(32), retry=True, group=group,
                        cipher_suite=selected_id, session_id=hello.session_id, password_salt=account.salt,
                        cookie=retry_cookie)
                    await wire.send_frame(hrr)
                    if hello.session_id:
                        await wire.send_ccs()
                    transcript.retry(ch, hrr, selected.hash_name)
                    ch2 = await _next_after_retry(wire, hello.early_data)
                    second = m.parse_client_hello(ch2[4:], enabled_groups=(group,), password_authenticated=True)
                    validate_retry_cookie(retry_cookie_policy, dict(second.extension_values), retry_cookie,
                                          writer, ch, selected_id, group)
                    mutable = {21, 41, 42, 44, 51}
                    stable = lambda value: {k: v for k, v in value.extension_values if k not in mutable}
                    if (second.fixed_hello != hello.fixed_hello or stable(second) != stable(hello)
                            or second.share_groups != (group,) or second.early_data
                            or not _retry_psks_unchanged(hello, second, selected.hash_name)):
                        raise ProtocolError("forbidden PWD retry mutation", alert=47)
                    ch, hello = ch2, second
                public, shared = await _native_work(lambda: _server_commit(policy.provider, account.base,
                    hello.random, group, selected.hash_name, hello.B))
            else:
                # Successor tickets use ordinary PSK/DHE, not PWD commitment
                # groups. Do not select groups that need an absent provider.
                ordinary_groups = tuple(value for value in c.GROUP_LENGTHS if not 34 <= value <= 41)
                hello = m.parse_client_hello(ch[4:], enabled_groups=ordinary_groups)
                allowed_modes = set(ticket.allowed_psk_modes).intersection(hello.psk_modes)
                use_dhe = 1 in allowed_modes and (bool(hello.B) or 0 not in allowed_modes)
                if use_dhe and not hello.group:
                    raise ProtocolError("password successor has no compatible traffic group")
                retry_group = hello.group if use_dhe and not hello.B else 0
                if retry_group or retry_cookie_policy is not None:
                    retry_cookie = (retry_cookie_policy.issue(writer, ch, selected_id, retry_group)
                                    if retry_cookie_policy is not None else b"")
                    hrr = m.server_hello(b"", bytes(32), retry=True, group=retry_group,
                        cipher_suite=selected_id, session_id=hello.session_id, cookie=retry_cookie)
                    await wire.send_frame(hrr)
                    if hello.session_id:
                        await wire.send_ccs()
                    transcript.retry(ch, hrr, selected.hash_name)
                    ch2 = await _next_after_retry(wire, hello.early_data)
                    second = m.parse_client_hello(ch2[4:],
                        enabled_groups=(retry_group,) if retry_group else ordinary_groups)
                    validate_retry_cookie(retry_cookie_policy, dict(second.extension_values), retry_cookie,
                                          writer, ch, selected_id, retry_group)
                    mutable = {21, 41, 42, 44} | ({51} if retry_group else set())
                    stable = lambda value: {k: v for k, v in value.extension_values if k not in mutable}
                    known_hashes = {identity: c.suite(known.cipher_suite).hash_name
                        for identity, _, _ in hello.psk_offers
                        if (known := ticket_store.lookup(identity, policy.service, protocol, context)) is not None}
                    if (second.fixed_hello != hello.fixed_hello or stable(second) != stable(hello)
                            or second.early_data or (retry_group and second.share_groups != (retry_group,))
                            or not _retry_psks_unchanged(hello, second, selected.hash_name,
                                known_hashes=known_hashes)):
                        raise ProtocolError("forbidden password resumption retry mutation", alert=47)
                    ch, hello = ch2, second
                    identity_index = next((index for index, offer in enumerate(hello.psk_offers)
                                          if offer[0] == ticket.identity), None)
                    if identity_index is None:
                        raise ProtocolError("selected password session was removed after retry", alert=47)
                    binder = hello.psk_offers[identity_index][2]
                if not hmac.compare_digest(c.binder(ticket.psk, transcript.snapshot() + ch[:-hello.binder_vector_size],
                            hash_name=selected.hash_name), binder):
                    raise ProtocolError("password session binder failed", alert=51)
                identity, authorized = ticket.pake_identity, policy.authorized(ticket.pake_identity)
                if not authorized:
                    raise ProtocolError("password session is no longer authorized")
                group = hello.group
                allowed_modes = set(ticket.allowed_psk_modes).intersection(hello.psk_modes)
                if 1 in allowed_modes and hello.B:
                    public, shared = c.traffic_server(group, hello.B)
                elif 0 in allowed_modes:
                    group, public, shared = 0, b"", bytes(selected.hash_length)
                else:
                    raise ProtocolError("password successor requires a compatible PSK mode")
            transcript.add(ch)
            root = c.handshake_secret(shared, ticket.psk if ticket else None, selected.hash_name)
            sh = m.server_hello(public, os.urandom(32), session_id=hello.session_id, cipher_suite=selected_id,
                                group=group, resumed=ticket is not None, selected_identity=identity_index)
            transcript.add(sh)
            client_secret, server_secret = handshake_keys(root, transcript, selected.hash_name)
            _log(diagnostics, hello.random, client_secret, server_secret)
            receiver = c.RecordState(client_secret, "open", selected_id, receive_limit)
            sender = c.RecordState(server_secret, "seal", selected_id, send_limit)
            await wire.send_frame(sh)
            if hello.session_id and (not pwd or not retry):
                await wire.send_ccs()
            accepted = bool(ticket and hello.early_data and identity_index == 0 and max_early_data
                            and on_early_data is not None and ticket.cipher_suite == selected_id
                            and ticket_store.consume_early(ticket, age))
            controls = server_controls(ext, heartbeat=heartbeat_mode, ticket_limit=ticket_count_limit,
                tickets_enabled=ticket_store is not None and 45 in ext, resumed=ticket is not None, signaling=signaling)
            extra = controls.extensions
            if 28 in ext:
                extra += ((28, receive_limit.to_bytes(2, "big")),)
            elif 1 in ext:
                extra += ((1, ext[1]),)
            ee = m.encrypted_extensions(protocol, early_data=accepted, extra_extensions=extra, acknowledge_name=bool(hello.name))
            transcript.add(ee);await wire.send_frame(ee, sender)
            sf = m.frame(20, schedule.finished(server_secret, transcript.snapshot()))
            transcript.add(sf);await wire.send_frame(sf, sender)
            client_app, server_app = application_keys(root, transcript, selected.hash_name)
            sender = c.RecordState(server_app, "seal", selected_id, send_limit)
            exporter = schedule.derive_secret(schedule.master_secret(root), "exp master", transcript.snapshot())
            _log(diagnostics, hello.random, client_app, server_app, application=True)
            emit_diagnostic(diagnostics, "TLS20_EXPORTER_SECRET", hello.random, exporter)
            await expose_exporter(on_exporter,exporter,exporter_accesses,stage="server-finished",
                role="server",hash_name=selected.hash_name)
            early_exporter = None
            if ticket and identity_index == 0:
                early_root = c.extract(bytes(selected.hash_length), ticket.psk, selected.hash_name)
                early_exporter = schedule.derive_secret(early_root, "e exp master", c.PREFACE + initial_ch)
                emit_diagnostic(diagnostics,"TLS20_EARLY_EXPORTER_SECRET",hello.random,early_exporter)
                await expose_exporter(on_early_exporter,early_exporter,exporter_accesses,stage="early",
                    role="server",hash_name=selected.hash_name)
            if ticket and hello.early_data:
                early_secret = schedule.derive_secret(early_root, "c e traffic", c.PREFACE + ch)
                early_receiver = c.RecordState(early_secret, "open", selected_id, ticket.record_size_limit) if accepted else None
                if accepted:
                    emit_diagnostic(diagnostics, "TLS20_CLIENT_EARLY_TRAFFIC_SECRET", hello.random, early_secret)
                total = discarded = 0
                while True:
                    record = await wire.raw_record()
                    if record[0] == 20 and record[5:] == b"\x01":
                        continue
                    if accepted:
                        content, kind = early_receiver.open(record)
                        if kind == 21:
                            wire.process_alert(content)
                            continue
                        if kind == 22:
                            wire.pending.extend(content)
                            eoed = await wire.receive_frame(5, early_receiver, boundary=True)
                            transcript.add(eoed);await on_early_data(b"");break
                        total += len(content)
                        if kind != 23 or total > min(max_early_data, ticket.max_early_data):
                            raise ProtocolError("invalid password session early data")
                        if content:
                            await on_early_data(content)
                    else:
                        opened = receiver.try_open(record)
                        if opened is not None:
                            content, kind = opened
                            if kind == 21:
                                wire.process_alert(content)
                                break  # Handshake epoch authenticated; no more early-data discard.
                            if kind != 22:
                                raise ProtocolError("unexpected post-early epoch")
                            wire.pending.extend(content);break
                        discarded += len(record)
                        if discarded > 1048576:
                            raise ProtocolError("rejected early data budget")
            cf = await wire.receive_frame(20, receiver, boundary=True)
            if not schedule.verify_finished(client_secret, transcript.snapshot(), cf[4:]) or not authorized or not policy.authorized(identity):
                raise ProtocolError("password authentication failed", alert=20)
            transcript.add(cf)
            successor_modes = tuple(mode for mode in dict.fromkeys(hello.psk_modes)
                if mode in (0, 1) and (ticket is None or mode in ticket.allowed_psk_modes))
            channel = SecureChannel(wire, server_app, client_app, exporter_secret=exporter,
                role="server", protocol=protocol, cipher_suite=selected_id, resumed=ticket is not None,
                early_data_accepted=accepted, early_exporter_secret=early_exporter,
                handshake_transcript=transcript.snapshot(), psk_provenance="pake", pake_identity=identity,
                allowed_psk_modes=successor_modes,
                enable_authenticators=enable_authenticators,peer_auth_share=hello.A,peer_capabilities=hello.extension_values,
                receive_record_limit=receive_limit, send_record_limit=send_limit,
                heartbeat_local_mode=controls.heartbeat_local_mode, heartbeat_peer_mode=controls.heartbeat_peer_mode)
            channel.password_permissions = policy.accounts[identity].permissions
            channel.peer_authenticated = True
            channel.expected_ticket_count = controls.expected_tickets
            for access in exporter_accesses:
                access.complete(peer_authenticated=True)
            channel._exporter_accesses = tuple(exporter_accesses)
            if ticket_store is not None and 45 in ext and successor_modes:
                resumption = schedule.derive_secret(schedule.master_secret(root), "res master", transcript.snapshot())
                ordinary_suite = RESUMPTION_SUITES.get(selected_id, selected_id)
                early_limit = max_early_data if on_early_data is not None and selected_id != 0xc0b3 else 0
                for _ in range(controls.expected_tickets if controls.expected_tickets is not None else 1):
                    message = ticket_store.issue(resumption, policy.service, protocol, early_limit, context,
                                                 cipher_suite=ordinary_suite, pake_identity=identity,
                                                 allowed_psk_modes=successor_modes, record_size_limit=receive_limit)
                    if message:
                        await channel.send_handshake(message)
            return channel
    except ProtocolError as error:
        for access in exporter_accesses:access.close()
        if bootstrap:
            await wire.fatal(error, sender)
        else:
            writer.transport.abort()
        raise
    except BaseException:
        for access in exporter_accesses:access.close()
        writer.transport.abort();raise
    finally:
        if state is not None:
            state.close()
        if acquired:
            policy.release()


async def client(reader, writer, credential, *, timeout=10, application_protocols=(b"http/1.1",),
                 cipher_suites=SUITES, groups=(23, 24, 25), ticket_cache=None, early_data=b"",
                 record_size_limit=None, heartbeat_mode=None, ticket_request=None, signaling=None, max_fragment_length=None,
                 send_server_name=True, require_alpn=True, diagnostics=None,
                 on_exporter=None, on_early_exporter=None,
                 enable_authenticators=False, authenticator_extensions=(), authenticator_certificate_algorithms=None,
                 _first_flight=None, _ticket_context=None, _auth_share_secret=None):
    from .handshake import (Wire, Transcript, SecureChannel, check_timeout, handshake_keys, application_keys,
                            _record_limit, _peer_record_limit, _fragment_limit, _peer_fragment_limit)
    check_timeout(timeout)
    if not isinstance(credential, PasswordCredential):
        raise ValueError("explicit password credentials required")
    if not cipher_suites or (not _first_flight and any(value not in SUITES for value in cipher_suites)) or not groups or any(value not in GROUPS for value in groups):
        raise ValueError("unsupported password suites/groups")
    wire, transcript = (_first_flight[0] if _first_flight else Wire(reader, writer)), Transcript()
    if not _first_flight:
        wire.deadline = asyncio.get_running_loop().time() + timeout
    sender = state = None
    auth_private = (_auth_share_secret or c.X25519PrivateKey.generate()) if enable_authenticators else None
    auth_public = c.public_bytes(auth_private) if auth_private is not None else b""
    exporter_accesses = []
    context = (_ticket_context if _ticket_context is not None else
               credential.context() + (signaling.context() if signaling is not None else b""))
    protocol = application_protocols[0] if application_protocols else b""
    ticket = ticket_cache.take(credential.service, protocol, context) if ticket_cache and not _first_flight else None
    if ticket is not None and 1 not in ticket.allowed_psk_modes:
        ticket = None  # This client profile offers only fresh-DHE resumption.
    permitted_successors = {RESUMPTION_SUITES[value] for value in cipher_suites if value in RESUMPTION_SUITES}
    if ticket is not None and (ticket.pake_identity != credential.identity or ticket.cipher_suite not in permitted_successors):
        ticket = None
    try:
        async with asyncio.timeout(timeout):
            extra = list(client_controls(heartbeat=heartbeat_mode, tickets=ticket_request, signaling=signaling))
            if authenticator_extensions and not enable_authenticators:
                raise ValueError("authenticator capabilities require explicit enablement")
            from .pki import supported_certificate_algorithms
            certificate_algorithms = (tuple(authenticator_certificate_algorithms)
                if authenticator_certificate_algorithms is not None else
                supported_certificate_algorithms(credential.provider.provider)) if enable_authenticators else ()
            extra.extend(authenticator_extensions)
            if record_size_limit is not None:
                extra.append((28, _record_limit(record_size_limit).to_bytes(2, "big")))
            if max_fragment_length is not None:
                _fragment_limit(max_fragment_length)
                extra.append((1,bytes((max_fragment_length,))))
            random = os.urandom(32)
            ordinary_private = early_sender = None
            early_exporter = None
            if ticket:
                offered_suites = (ticket.cipher_suite,)
                group = 29
                ordinary_private, public = c.traffic_key(group)
                kwargs = dict(group=group, supported_groups=(29,23), identity=ticket.identity,
                    age=ticket.obfuscated_age(), binder=bytes(c.suite(ticket.cipher_suite).hash_length),
                    early_data=bool(early_data and ticket.max_early_data), psk_modes=(1,))
            else:
                offered_suites = tuple(cipher_suites);group=groups[0];public=b""
                extra.append(credential.name_extension())
                kwargs = dict(group=group, supported_groups=tuple(groups), empty_share=True,
                              password_authenticated=True)
            name = credential.service if send_server_name and not m.is_ip_identity(credential.service) else ""
            def make_hello(public_share, **updates):
                if _first_flight:
                    initial = m.parse_client_hello(_first_flight[1][4:])
                    extensions = dict(initial.extension_values)
                    extensions[51] = m._vec(updates["group"].to_bytes(2,"big") + m._vec(public_share,2),2)
                    if updates.get("cookie"):
                        extensions[44] = m._vec(updates["cookie"],2)
                    return m.frame(1, initial.fixed_hello + m._vec(b"".join(m.extension(k,v) for k,v in extensions.items()),2))
                options = {**kwargs, **updates}
                return m.client_hello(auth_public, public_share, name, random, application_protocols,
                    cipher_suites=offered_suites, certificate_algorithms=certificate_algorithms, extra_extensions=extra, **options)
            ch = _first_flight[1] if _first_flight else make_hello(public)
            if _first_flight:
                initial = m.parse_client_hello(ch[4:])
                random = initial.random
                extra = list(initial.extension_values)
                offered_suites = initial.cipher_suites
            if ticket:
                size = c.suite(ticket.cipher_suite).hash_length
                proof = c.binder(ticket.psk, c.PREFACE+ch[:-(size+3)], hash_name=c.suite(ticket.cipher_suite).hash_name)
                ch = ch[:-size] + proof
            if not _first_flight:
                writer.write(c.PREFACE);await writer.drain();await wire.send_frame(ch);wire.allow_ccs=True
            if ticket:
                selected = c.suite(ticket.cipher_suite);schedule=c.KeySchedule(selected.hash_name)
                early_root = c.extract(bytes(selected.hash_length), ticket.psk, selected.hash_name)
                early_exporter = schedule.derive_secret(early_root,"e exp master",c.PREFACE+ch)
                emit_diagnostic(diagnostics,"TLS20_EARLY_EXPORTER_SECRET",random,early_exporter)
                await expose_exporter(on_early_exporter,early_exporter,exporter_accesses,stage="early",
                    role="client",hash_name=selected.hash_name)
            if ticket and kwargs["early_data"]:
                if len(early_data) > ticket.max_early_data:
                    raise ProtocolError("password session early data exceeds allowance")
                secret = schedule.derive_secret(early_root, "c e traffic", c.PREFACE+ch)
                emit_diagnostic(diagnostics, "TLS20_CLIENT_EARLY_TRAFFIC_SECRET", random, secret)
                early_sender = c.RecordState(secret,"seal",ticket.cipher_suite,ticket.record_size_limit)
                early_exporter = schedule.derive_secret(early_root,"e exp master",c.PREFACE+ch)
                for offset in range(0,len(early_data),min(16384,ticket.record_size_limit-1)):
                    writer.write(early_sender.seal(early_data[offset:offset+min(16384,ticket.record_size_limit-1)],23))
                    await writer.drain()
            sh = _first_flight[2] if _first_flight else await wire.receive_frame(2,boundary=True)
            public_peer,sid,resumed,selected_group,retry,cookie,selected_id=m.parse_server_hello(sh[4:],with_suite=True)
            if sid or selected_id not in offered_suites or cookie and not retry:
                raise ProtocolError("invalid password handshake selection")
            selected,schedule=c.suite(selected_id),c.KeySchedule(c.suite(selected_id).hash_name)
            if not ticket:
                if not retry or resumed or selected_group not in groups or selected_id not in SUITES:
                    raise ProtocolError("empty password share requires negotiated retry")
                extensions=m.server_hello_extensions(sh[4:])
                salt=extensions[31][2:] if 31 in extensions else None
                base=password_base(credential.username,credential.password,salt)
                state, public = await _native_work(lambda: _client_commit(credential.provider, base,
                    random, selected_group, selected.hash_name), discard=lambda result: result[0].close())
                transcript.retry(ch,sh,selected.hash_name)
                ch=make_hello(public,group=selected_group,empty_share=False,cookie=cookie)
                await wire.send_frame(ch)
                sh=await wire.receive_frame(2,boundary=True)
                public_peer,sid,resumed,final_group,retry,cookie,final_suite=m.parse_server_hello(sh[4:],with_suite=True)
                if sid or resumed or retry or cookie or final_group!=selected_group or final_suite!=selected_id:
                    raise ProtocolError("inconsistent password retry selection")
                shared=await _native_work(lambda: state.finish(public_peer));state=None
            else:
                if retry:
                    first = m.parse_client_hello(ch[4:])
                    if (resumed or selected_id != ticket.cipher_suite
                            or selected_group and (selected_group not in first.groups or selected_group in first.share_groups)
                            or not selected_group and not cookie):
                        raise ProtocolError("invalid password successor retry", alert=47)
                    transcript.retry(ch, sh, selected.hash_name)
                    kwargs["early_data"] = False
                    kwargs["cookie"] = cookie
                    kwargs["age"] = ticket.obfuscated_age()
                    if early_sender is not None:
                        early_sender.close()
                        early_sender = None
                    if selected_group:
                        group = selected_group
                        ordinary_private, public = c.traffic_key(group)
                        kwargs["group"] = group
                    ch = make_hello(public)
                    size = selected.hash_length
                    ch = ch[:-size] + c.binder(ticket.psk, transcript.snapshot() + ch[:-(size+3)],
                                               hash_name=selected.hash_name)
                    await wire.send_frame(ch)
                    sh = await wire.receive_frame(2, boundary=True)
                    public_peer,sid,resumed,selected_group,retry,cookie,final_suite=m.parse_server_hello(sh[4:],with_suite=True)
                    if sid or cookie or final_suite != selected_id:
                        raise ProtocolError("inconsistent password successor retry", alert=47)
                if retry or not resumed or selected_group!=group or int.from_bytes(m.server_hello_extensions(sh[4:]).get(41,b""),"big")!=0:
                    raise ProtocolError("password successor ticket was not selected; fresh connection required")
                shared=c.traffic_dh(ordinary_private,group,public_peer)
            transcript.add(ch);transcript.add(sh)
            root=c.handshake_secret(shared,ticket.psk if ticket else None,selected.hash_name)
            client_secret,server_secret=handshake_keys(root,transcript,selected.hash_name)
            _log(diagnostics,random,client_secret,server_secret)
            sender=c.RecordState(client_secret,"seal",selected_id)
            receiver=c.RecordState(server_secret,"open",selected_id)
            ee=await wire.receive_frame(8,receiver)
            accepted,protocol,chosen=m.parse_encrypted_extensions(ee[4:],application_protocols,
                offered_early=early_sender is not None,allowed_extensions=tuple(k for k,_ in extra if k in (1,15,28,55,56,58)),
                with_extensions=True,offered_name=bool(name),require_alpn=require_alpn)
            controls=client_control_selection(chosen,heartbeat=heartbeat_mode,tickets=ticket_request,signaling=signaling)
            send_limit=_peer_record_limit(chosen[28]) if 28 in chosen else 16385
            receive_limit=_record_limit(record_size_limit) if 28 in chosen else 16385
            if 1 in chosen:
                if 28 in chosen or chosen[1] != dict(extra).get(1):
                    raise ProtocolError("invalid password record-fragment selection",alert=47)
                send_limit=receive_limit=_peer_fragment_limit(chosen[1])
            if receiver.max_opened_plaintext>receive_limit:
                raise ProtocolError("password handshake record exceeds limit",alert=22)
            receiver.record_limit=receive_limit;sender.record_limit=send_limit
            transcript.add(ee)
            sf=await wire.receive_frame(20,receiver,boundary=True)
            if not schedule.verify_finished(server_secret,transcript.snapshot(),sf[4:]):
                raise ProtocolError("server password proof failed",alert=51)
            transcript.add(sf)
            client_app,server_app=application_keys(root,transcript,selected.hash_name)
            exporter=schedule.derive_secret(schedule.master_secret(root),"exp master",transcript.snapshot())
            _log(diagnostics,random,client_app,server_app,application=True)
            emit_diagnostic(diagnostics,"TLS20_EXPORTER_SECRET",random,exporter)
            await expose_exporter(on_exporter,exporter,exporter_accesses,stage="server-finished",
                role="client",peer_authenticated=True,hash_name=selected.hash_name)
            if accepted:
                eoed=m.frame(5,b"");await wire.send_frame(eoed,early_sender);transcript.add(eoed)
            cf=m.frame(20,schedule.finished(client_secret,transcript.snapshot()))
            await wire.send_frame(cf,sender);transcript.add(cf)
            channel = SecureChannel(wire,client_app,server_app,exporter_secret=exporter,
                resumption_secret=schedule.derive_secret(schedule.master_secret(root),"res master",transcript.snapshot()),
                ticket_cache=ticket_cache,name=credential.service,context=context,
                role="client",protocol=protocol,cipher_suite=selected_id,resumed=ticket is not None,
                early_data_accepted=accepted,early_exporter_secret=early_exporter,
                handshake_transcript=transcript.snapshot(),psk_provenance="pake",pake_identity=credential.identity,
                allowed_psk_modes=(1,),
                enable_authenticators=enable_authenticators,auth_share_secret=auth_private,
                local_capabilities=m.parse_client_hello(ch[4:],password_authenticated=ticket is None).extension_values,
                receive_record_limit=receive_limit,send_record_limit=send_limit,
                heartbeat_local_mode=controls.heartbeat_local_mode,heartbeat_peer_mode=controls.heartbeat_peer_mode)
            channel.peer_authenticated=True
            channel.expected_ticket_count=controls.expected_tickets
            for access in exporter_accesses:access.complete(peer_authenticated=True)
            channel._exporter_accesses=tuple(exporter_accesses)
            return channel
    except ProtocolError as error:
        for access in exporter_accesses:access.close()
        await wire.fatal(error,sender);raise
    except BaseException:
        for access in exporter_accesses:access.close()
        writer.transport.abort();raise
    finally:
        if state is not None:
            state.close()
