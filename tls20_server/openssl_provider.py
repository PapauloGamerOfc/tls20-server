"""Explicit optional OpenSSL 3.5+ provider using only its public C ABI.

No library is discovered or loaded by importing this module. The application
must supply an absolute, trusted native-library path. Each instance uses a
private library context and the default provider; it does not load OpenSSL
configuration or modify the process-wide context. The caller owns the native
dependency and its security updates. OpenSSL's portable SM4 implementation is
not guaranteed constant-time on every supported machine.
"""

from __future__ import annotations

import ctypes as ct
from pathlib import Path
import os
import functools
import threading
from contextlib import contextmanager

from cryptography.exceptions import InvalidTag

from .errors import ConfigurationError, ProtocolError
from .credential_limits import MAX_CERTIFICATES, MAX_CERT_DER, MAX_CERTIFICATE_BODY


P, I, Z, U = ct.c_void_p, ct.c_int, ct.c_size_t, ct.c_uint


def _buffer(value):
    return ct.create_string_buffer(value, max(1, len(value)))


def _wipe(value):
    ct.memset(ct.addressof(value), 0, ct.sizeof(value))


def _synchronized(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        provider = getattr(self, "provider", self)
        with provider._native_scope():
            return method(self, *args, **kwargs)
    return call


class NativeKey:
    """Opaque provider key; secret scalar operations never run in Python."""

    def __init__(self, provider, pointer):
        self.provider, self.pointer = provider, pointer
        provider._live_keys += 1

    @_synchronized
    def close(self):
        if self.pointer:
            self.provider.lib.EVP_PKEY_free(self.pointer)
            self.pointer = None
            self.provider._live_keys -= 1

    def __del__(self):
        self.close()


class OpenSSLProvider:
    def __init__(self, library_path):
        self._lock = threading.RLock()
        self._context = self._provider = None
        self._live_keys, self._ciphers = 0, {}
        path = Path(library_path)
        if not path.is_absolute() or not path.is_file():
            raise ConfigurationError("OpenSSL library must be an explicit existing absolute path")
        try:
            self.lib = ct.CDLL(str(path), **({"winmode": 0x100 | 0x1000} if os.name == "nt" else {}))
            self._bind()
            version = self.lib.OpenSSL_version_num()
            if not 0x30500000 <= version < 0x50000000:
                raise ConfigurationError("optional provider requires OpenSSL 3.5 or newer public ABI")
            self._context = self.lib.OSSL_LIB_CTX_new()
            if not self._context:
                raise ConfigurationError("could not create private OpenSSL context")
            with self._native_scope():
                self._provider = self.lib.OSSL_PROVIDER_load(self._context, b"default")
                if not self._provider:
                    raise ConfigurationError("OpenSSL default provider is unavailable")
                for name in ("SM4-GCM", "SM4-CCM"):
                    pointer = self.lib.EVP_CIPHER_fetch(self._context, name.encode(), b"provider=default")
                    if not pointer:
                        raise ConfigurationError("required optional SM4 cipher is unavailable")
                    self._ciphers[name] = pointer
        except (OSError, AttributeError) as exc:
            self.close()
            raise ConfigurationError("could not load the requested OpenSSL public ABI") from exc
        except BaseException:
            self.close()
            raise

    def _bind(self):
        declarations = {
            "OpenSSL_version_num": (ct.c_ulong, []), "ERR_clear_error": (None, []),
            "OSSL_LIB_CTX_new": (P, []), "OSSL_LIB_CTX_free": (None, [P]),
            "OPENSSL_thread_stop_ex": (None, [P]),
            "OSSL_PROVIDER_load": (P, [P, ct.c_char_p]), "OSSL_PROVIDER_unload": (I, [P]),
            "EVP_CIPHER_fetch": (P, [P, ct.c_char_p, ct.c_char_p]), "EVP_CIPHER_free": (None, [P]),
            "EVP_CIPHER_CTX_new": (P, []), "EVP_CIPHER_CTX_free": (None, [P]),
            "EVP_CIPHER_CTX_ctrl": (I, [P, I, I, P]),
            "EVP_EncryptInit_ex2": (I, [P, P, P, P, P]), "EVP_DecryptInit_ex2": (I, [P, P, P, P, P]),
            "EVP_EncryptUpdate": (I, [P, P, ct.POINTER(I), P, I]),
            "EVP_DecryptUpdate": (I, [P, P, ct.POINTER(I), P, I]),
            "EVP_EncryptFinal_ex": (I, [P, P, ct.POINTER(I)]),
            "EVP_DecryptFinal_ex": (I, [P, P, ct.POINTER(I)]),
            "EVP_PKEY_CTX_new_from_name": (P, [P, ct.c_char_p, ct.c_char_p]),
            "EVP_PKEY_CTX_new_from_pkey": (P, [P, P, ct.c_char_p]),
            "EVP_PKEY_CTX_free": (None, [P]), "EVP_PKEY_free": (None, [P]),
            "EVP_PKEY_keygen_init": (I, [P]), "EVP_PKEY_CTX_set_group_name": (I, [P, ct.c_char_p]),
            "EVP_PKEY_paramgen_init": (I, [P]), "EVP_PKEY_set1_encoded_public_key": (I, [P, P, Z]),
            "EVP_PKEY_generate": (I, [P, ct.POINTER(P)]),
            "EVP_PKEY_get_octet_string_param": (I, [P, ct.c_char_p, P, Z, ct.POINTER(Z)]),
            "EVP_PKEY_derive_init": (I, [P]), "EVP_PKEY_derive_set_peer": (I, [P, P]),
            "EVP_PKEY_derive": (I, [P, P, ct.POINTER(Z)]), "EVP_PKEY_public_check": (I, [P]),
            "EVP_PKEY_fromdata_init": (I, [P]), "EVP_PKEY_fromdata": (I, [P, ct.POINTER(P), I, P]),
            "OSSL_PARAM_BLD_new": (P, []), "OSSL_PARAM_BLD_free": (None, [P]),
            "OSSL_PARAM_BLD_push_utf8_string": (I, [P, ct.c_char_p, ct.c_char_p, Z]),
            "OSSL_PARAM_BLD_push_octet_string": (I, [P, ct.c_char_p, P, Z]),
            "OSSL_PARAM_BLD_to_param": (P, [P]), "OSSL_PARAM_free": (None, [P]),
            "d2i_PUBKEY_ex": (P, [ct.POINTER(P), ct.POINTER(P), ct.c_long, P, ct.c_char_p]),
            "EVP_PKEY_is_a": (I, [P, ct.c_char_p]), "EVP_MD_CTX_new": (P, []),
            "EVP_MD_CTX_free": (None, [P]),
            "EVP_Q_digest": (I, [P, ct.c_char_p, ct.c_char_p, P, Z, P, ct.POINTER(Z)]),
            "EVP_Q_mac": (P, [P, ct.c_char_p, ct.c_char_p, ct.c_char_p, P, P, Z, P, Z, P, Z, ct.POINTER(Z)]),
            "EVP_DigestVerifyInit_ex": (I, [P, ct.POINTER(P), ct.c_char_p, P, ct.c_char_p, P, P]),
            "EVP_DigestVerify": (I, [P, P, Z, P, Z]), "EVP_PKEY_CTX_set1_id": (I, [P, P, I]),
            "X509_new_ex": (P, [P, ct.c_char_p]),
            "X509_get_signature_nid": (I, [P]), "OBJ_txt2nid": (I, [ct.c_char_p]),
            "ASN1_OCTET_STRING_new": (P, []), "ASN1_OCTET_STRING_set": (I, [P, P, I]),
            "ASN1_OCTET_STRING_free": (None, [P]), "X509_set0_distinguishing_id": (None, [P, P]),
            "d2i_X509": (P, [ct.POINTER(P), ct.POINTER(P), ct.c_long]),
            "i2d_X509": (I, [P, ct.POINTER(P)]), "X509_free": (None, [P]),
            "X509_STORE_new": (P, []), "X509_STORE_free": (None, [P]),
            "X509_STORE_add_cert": (I, [P, P]),
            "X509_STORE_CTX_new_ex": (P, [P, ct.c_char_p]), "X509_STORE_CTX_free": (None, [P]),
            "X509_STORE_CTX_init": (I, [P, P, P, P]), "X509_STORE_CTX_set_purpose": (I, [P, I]),
            "X509_STORE_CTX_get0_param": (P, [P]), "X509_verify_cert": (I, [P]),
            "X509_STORE_CTX_get1_chain": (P, [P]), "X509_VERIFY_PARAM_set_flags": (I, [P, ct.c_ulong]),
            "X509_VERIFY_PARAM_set_time": (None, [P, ct.c_longlong if os.name == "nt" else ct.c_long]),
            "X509_VERIFY_PARAM_set1_host": (I, [P, ct.c_char_p, Z]),
            "X509_VERIFY_PARAM_set_hostflags": (None, [P, U]),
            "X509_VERIFY_PARAM_set_depth": (None, [P, I]),
            "X509_VERIFY_PARAM_set1_ip_asc": (I, [P, ct.c_char_p]),
            "OPENSSL_sk_new_null": (P, []), "OPENSSL_sk_push": (I, [P, P]),
            "OPENSSL_sk_num": (I, [P]), "OPENSSL_sk_value": (P, [P, I]),
            "OPENSSL_sk_free": (None, [P]),
        }
        for name, (restype, argtypes) in declarations.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = restype, argtypes

    def _ready(self):
        if not self._context:
            raise ProtocolError("optional native provider is closed")

    @contextmanager
    def _native_scope(self):
        """Detach this thread's OpenSSL state before releasing the context lock.

        OSSL_LIB_CTX_free only cleans its caller's thread-local resources. A
        persistent executor thread can outlive this provider; leaving its DRBG
        registered would access the freed context when that thread later exits.
        Nesting is deliberate: callbacks/key destruction must not clear native
        thread state while the enclosing EVP operation is still executing.
        """
        with self._lock:
            self._native_depth = getattr(self, "_native_depth", 0) + 1
            try:
                yield
            finally:
                self._native_depth -= 1
                if not self._native_depth and self._context:
                    self.lib.OPENSSL_thread_stop_ex(self._context)

    def _check(self, result, *, alert=40):
        if result != 1:
            self.lib.ERR_clear_error()
            raise ProtocolError("optional native cryptographic operation failed", alert=alert)

    @_synchronized
    def close(self):
        if self._live_keys:
            raise ProtocolError("cannot close optional provider while native keys are alive")
        if self._context:
            # Clean the closing thread while all provider implementations are
            # still loaded. Other threads detach before releasing this lock.
            self.lib.OPENSSL_thread_stop_ex(self._context)
        for pointer in self._ciphers.values():
            self.lib.EVP_CIPHER_free(pointer)
        self._ciphers.clear()
        if self._provider:
            self.lib.OSSL_PROVIDER_unload(self._provider)
            self._provider = None
        if self._context:
            self.lib.OSSL_LIB_CTX_free(self._context)
            self._context = None

    def __del__(self):
        self.close()

    @_synchronized
    def digest(self, name, data):
        """SM3 in this explicitly selected private context, not hashlib's SSL."""
        self._ready()
        if name != "sm3" or not isinstance(data, bytes) or len(data) > 16 << 20:
            raise ProtocolError("invalid optional SM3 digest input")
        source, output, count = _buffer(data), ct.create_string_buffer(32), Z()
        try:
            self._check(self.lib.EVP_Q_digest(self._context, b"SM3", b"provider=default",
                source, len(data), output, ct.byref(count)))
            if count.value != 32:
                raise ProtocolError("unexpected optional SM3 digest length")
            return output.raw
        finally:
            _wipe(source)
            _wipe(output)

    @_synchronized
    def hmac(self, name, key, data):
        self._ready()
        if name != "sm3" or not isinstance(key, bytes) or not isinstance(data, bytes) or len(key) > 1 << 20 or len(data) > 16 << 20:
            raise ProtocolError("invalid optional SM3 HMAC input")
        source, secret, output, count = _buffer(data), _buffer(key), ct.create_string_buffer(32), Z()
        try:
            if not self.lib.EVP_Q_mac(self._context, b"HMAC", b"provider=default", b"SM3", None,
                    secret, len(key), source, len(data), output, 32, ct.byref(count)) or count.value != 32:
                self.lib.ERR_clear_error()
                raise ProtocolError("optional native SM3 HMAC failed")
            return output.raw
        finally:
            for value in (source, secret, output):
                _wipe(value)

    @_synchronized
    def aead(self, name, key):
        self._ready()
        if name not in self._ciphers or not isinstance(key, bytes) or len(key) != 16:
            raise ProtocolError("invalid optional SM4 cipher or key")
        return _SM4(self, name, key)

    @_synchronized
    def generate_sm2(self):
        self._ready()
        context, pointer = self.lib.EVP_PKEY_CTX_new_from_name(self._context, b"EC", b"provider=default"), P()
        try:
            if not context:
                raise ProtocolError("native EC key context unavailable")
            self._check(self.lib.EVP_PKEY_keygen_init(context))
            self._check(self.lib.EVP_PKEY_CTX_set_group_name(context, b"SM2"))
            self._check(self.lib.EVP_PKEY_generate(context, ct.byref(pointer)))
            result, length = ct.create_string_buffer(65), Z()
            self._check(self.lib.EVP_PKEY_get_octet_string_param(pointer, b"pub", result, 65, ct.byref(length)))
            if length.value != 65 or result.raw[0] != 4:
                raise ProtocolError("unexpected native SM2 public key encoding")
            key = NativeKey(self, pointer.value)
            pointer = P()
            return key, result.raw
        finally:
            self.lib.EVP_PKEY_free(pointer)
            self.lib.EVP_PKEY_CTX_free(context)

    @_synchronized
    def exchange_sm2(self, private, public):
        self._ready()
        if not isinstance(private, NativeKey) or private.provider is not self or not private.pointer:
            raise ProtocolError("SM2 key belongs to another or closed provider")
        if not isinstance(public, bytes) or len(public) != 65 or public[0] != 4:
            raise ProtocolError("invalid curveSM2 public share", alert=47)
        importer = context = check = None
        peer, output = P(), ct.create_string_buffer(32)
        data = _buffer(public)
        try:
            importer = self.lib.EVP_PKEY_CTX_new_from_name(self._context, b"EC", b"provider=default")
            if not importer:
                raise ProtocolError("native public key context unavailable")
            # curveSM2 ECDH is generic EC, not the distinct SM2 signing or
            # key-agreement algorithm. Named-parameter generation preserves
            # that EC key type; the public setter performs point decoding.
            self._check(self.lib.EVP_PKEY_paramgen_init(importer))
            self._check(self.lib.EVP_PKEY_CTX_set_group_name(importer, b"SM2"))
            self._check(self.lib.EVP_PKEY_generate(importer, ct.byref(peer)))
            self._check(self.lib.EVP_PKEY_set1_encoded_public_key(peer, data, len(public)), alert=47)
            check = self.lib.EVP_PKEY_CTX_new_from_pkey(self._context, peer, b"provider=default")
            if not check:
                raise ProtocolError("native public key validation context unavailable")
            self._check(self.lib.EVP_PKEY_public_check(check), alert=47)
            context = self.lib.EVP_PKEY_CTX_new_from_pkey(self._context, private.pointer, b"provider=default")
            if not context:
                raise ProtocolError("native ECDH context unavailable")
            self._check(self.lib.EVP_PKEY_derive_init(context))
            self._check(self.lib.EVP_PKEY_derive_set_peer(context, peer))
            size = Z(32)
            self._check(self.lib.EVP_PKEY_derive(context, output, ct.byref(size)))
            if size.value != 32:
                raise ProtocolError("unexpected curveSM2 shared secret length")
            return output.raw
        finally:
            _wipe(output)
            self.lib.EVP_PKEY_CTX_free(context)
            self.lib.EVP_PKEY_CTX_free(check)
            self.lib.EVP_PKEY_free(peer)
            self.lib.EVP_PKEY_CTX_free(importer)

    @_synchronized
    def verify_sm2(self, spki_der, message, signature, identifier=b"1234567812345678"):
        self._ready()
        if (not 1 <= len(spki_der) <= 16384 or not 1 <= len(identifier) <= 8191
                or len(message) > 1 << 24 or not 8 <= len(signature) <= 80):
            raise ProtocolError("SM2 verification input bounds")
        data, sig, identity, encoded = map(_buffer, (message, signature, identifier, spki_der))
        cursor, key, md = P(ct.addressof(encoded)), None, None
        try:
            key = self.lib.d2i_PUBKEY_ex(None, ct.byref(cursor), len(spki_der), self._context, b"provider=default")
            if not key or cursor.value != ct.addressof(encoded) + len(spki_der) or self.lib.EVP_PKEY_is_a(key, b"SM2") != 1:
                raise ProtocolError("expected a complete SM2 public key")
            md, pctx = self.lib.EVP_MD_CTX_new(), P()
            if not md:
                raise ProtocolError("native digest context unavailable")
            self._check(self.lib.EVP_DigestVerifyInit_ex(md, ct.byref(pctx), b"SM3", self._context,
                                                      b"provider=default", key, None))
            self._check(self.lib.EVP_PKEY_CTX_set1_id(pctx, identity, len(identifier)))
            self._check(self.lib.EVP_DigestVerify(md, sig, len(signature), data, len(message)))
        finally:
            self.lib.EVP_MD_CTX_free(md)
            self.lib.EVP_PKEY_free(key)

    @_synchronized
    def verify_certificate_path(self, chain_der, roots_der, *, server_name=None, purpose="server", now=None,
                                partial_chain=False):
        """Return the native verifier's actual validated DER path, never a guess."""
        self._ready()
        if purpose not in ("server", "client") or not chain_der or not roots_der:
            raise ProtocolError("explicit native certificate path policy required")
        if (len(chain_der) > MAX_CERTIFICATES or len(roots_der) > 4096
                or 4 + sum(5 + len(der) for der in chain_der) > MAX_CERTIFICATE_BODY):
            raise ProtocolError("native certificate path resource budget")
        certificates, store, stack, context, path = [], None, None, None, None
        try:
            for der in (*chain_der, *roots_der):
                if not 1 <= len(der) <= MAX_CERT_DER:
                    raise ProtocolError("native certificate size budget")
                encoded = _buffer(der)
                cursor = P(ct.addressof(encoded))
                cert = P(self.lib.X509_new_ex(self._context, getattr(self, "certificate_properties", b"provider=default")))
                if not cert:
                    raise ProtocolError("native certificate allocation failed")
                result = self.lib.d2i_X509(ct.byref(cert), ct.byref(cursor), len(der))
                if not result or cursor.value != ct.addressof(encoded) + len(der):
                    self.lib.X509_free(cert)
                    raise ProtocolError("invalid complete DER certificate")
                certificates.append(cert.value)
                if self.lib.X509_get_signature_nid(cert) == self.lib.OBJ_txt2nid(b"1.2.156.10197.1.501"):
                    identity = self.lib.ASN1_OCTET_STRING_new()
                    if not identity:
                        raise ProtocolError("native SM2 identity allocation failed")
                    if self.lib.ASN1_OCTET_STRING_set(identity, b"1234567812345678", 16) != 1:
                        self.lib.ASN1_OCTET_STRING_free(identity)
                        raise ProtocolError("native SM2 identity allocation failed")
                    # Certificate identifier is independent of the OpenSSL
                    # version default. Do not apply it to EdDSA or other keys.
                    self.lib.X509_set0_distinguishing_id(cert, identity)
            store, stack = self.lib.X509_STORE_new(), self.lib.OPENSSL_sk_new_null()
            context = self.lib.X509_STORE_CTX_new_ex(self._context, getattr(self, "certificate_properties", b"provider=default"))
            if not store or not stack or not context:
                raise ProtocolError("native path validation allocation failed")
            for cert in certificates[len(chain_der):]:
                self._check(self.lib.X509_STORE_add_cert(store, cert))
            for cert in certificates[1:len(chain_der)]:
                if self.lib.OPENSSL_sk_push(stack, cert) <= 0:
                    raise ProtocolError("native untrusted path allocation failed")
            self._check(self.lib.X509_STORE_CTX_init(context, store, certificates[0], stack))
            # A specialized provider may supply a narrowly scoped signature
            # bridge; keep its C callback alive until native validation ends.
            verification_callback = (self._configure_certificate_verifier(context)
                if hasattr(self, "_configure_certificate_verifier") else None)
            self._check(self.lib.X509_STORE_CTX_set_purpose(context, 2 if purpose == "server" else 1))
            param = self.lib.X509_STORE_CTX_get0_param(context)
            # Depth counts intermediates, excluding the leaf and trust anchor.
            self.lib.X509_VERIFY_PARAM_set_depth(param, MAX_CERTIFICATES - 1)
            self.lib.X509_VERIFY_PARAM_set_hostflags(param, 0x4 | 0x20)  # No partial wildcard or CN fallback.
            self._check(self.lib.X509_VERIFY_PARAM_set_flags(param, 0x20 | 0x80 | 0x8000 | (0x80000 if partial_chain else 0)))
            if now is not None:
                seconds = int(now.timestamp()) if hasattr(now, "timestamp") else int(now)
                self.lib.X509_VERIFY_PARAM_set_time(param, seconds)
            if server_name:
                import ipaddress
                try:
                    ipaddress.ip_address(server_name)
                except ValueError:
                    self._check(self.lib.X509_VERIFY_PARAM_set1_host(param, server_name.encode("ascii"), 0))
                else:
                    self._check(self.lib.X509_VERIFY_PARAM_set1_ip_asc(param, server_name.encode("ascii")))
            self._check(self.lib.X509_verify_cert(context))
            path = self.lib.X509_STORE_CTX_get1_chain(context)
            if not path:
                raise ProtocolError("native verifier returned no authenticated path")
            if not 1 <= self.lib.OPENSSL_sk_num(path) <= MAX_CERTIFICATES + 1:
                raise ProtocolError("native verified path resource budget")
            result = []
            for index in range(self.lib.OPENSSL_sk_num(path)):
                cert = self.lib.OPENSSL_sk_value(path, index)
                length = self.lib.i2d_X509(cert, None)
                if not 0 < length <= MAX_CERT_DER:
                    raise ProtocolError("native verified certificate encoding failed")
                output = ct.create_string_buffer(length)
                cursor = P(ct.addressof(output))
                if self.lib.i2d_X509(cert, ct.byref(cursor)) != length:
                    raise ProtocolError("native verified certificate encoding failed")
                result.append(output.raw)
            if sum(map(len, result)) > MAX_CERTIFICATE_BODY + MAX_CERT_DER:
                raise ProtocolError("native verified path resource budget")
            return tuple(result)
        finally:
            if path:
                for index in range(self.lib.OPENSSL_sk_num(path)):
                    self.lib.X509_free(self.lib.OPENSSL_sk_value(path, index))
                self.lib.OPENSSL_sk_free(path)
            self.lib.X509_STORE_CTX_free(context)
            self.lib.OPENSSL_sk_free(stack)
            self.lib.X509_STORE_free(store)
            for cert in certificates:
                self.lib.X509_free(cert)


class _SM4:
    def __init__(self, provider, name, key):
        self.provider, self.name, self.key = provider, name, key

    def encrypt(self, nonce, plaintext, aad):
        return self._crypt(True, nonce, plaintext, aad)

    def decrypt(self, nonce, ciphertext, aad):
        return self._crypt(False, nonce, ciphertext, aad)

    @_synchronized
    def _crypt(self, encrypt, nonce, data, aad):
        self.provider._ready()
        if len(nonce) != 12 or len(data) > (1 << 24) - 1 or len(aad) > (1 << 24) - 1:
            raise ProtocolError("SM4 input length bounds")
        if not encrypt and len(data) < 16:
            raise InvalidTag
        content, tag = (data, bytes(16)) if encrypt else (data[:-16], data[-16:])
        keybuf, noncebuf, databuf, aadbuf, tagbuf = map(_buffer, (self.key, nonce, content, aad, tag))
        output, count = ct.create_string_buffer(len(content) + 16), I()
        lib, context = self.provider.lib, self.provider.lib.EVP_CIPHER_CTX_new()
        init = lib.EVP_EncryptInit_ex2 if encrypt else lib.EVP_DecryptInit_ex2
        update = lib.EVP_EncryptUpdate if encrypt else lib.EVP_DecryptUpdate
        final = lib.EVP_EncryptFinal_ex if encrypt else lib.EVP_DecryptFinal_ex
        ccm = self.name == "SM4-CCM"
        try:
            if not context:
                raise ProtocolError("native cipher context unavailable")
            self.provider._check(init(context, self.provider._ciphers[self.name], None, None, None))
            self.provider._check(lib.EVP_CIPHER_CTX_ctrl(context, 0x9, 12, None))
            if ccm:
                self.provider._check(lib.EVP_CIPHER_CTX_ctrl(context, 0x11, 16, None if encrypt else tagbuf))
            self.provider._check(init(context, None, keybuf, noncebuf, None))
            if ccm:
                self.provider._check(update(context, None, ct.byref(count), None, len(content)))
            if aad:
                self.provider._check(update(context, None, ct.byref(count), aadbuf, len(aad)))
            status = update(context, output, ct.byref(count), databuf, len(content))
            if status != 1:
                if not encrypt:
                    raise InvalidTag
                self.provider._check(status)
            length = count.value
            if not encrypt and not ccm:
                self.provider._check(lib.EVP_CIPHER_CTX_ctrl(context, 0x11, 16, tagbuf))
            status = final(context, ct.byref(output, length), ct.byref(count))
            if status != 1:
                if not encrypt:
                    raise InvalidTag
                self.provider._check(status)
            length += count.value
            if length != len(content):
                raise ProtocolError("unexpected authenticated SM4 output length")
            if encrypt:
                self.provider._check(lib.EVP_CIPHER_CTX_ctrl(context, 0x10, 16, tagbuf))
            return output.raw[:length] + (tagbuf.raw if encrypt else b"")
        finally:
            for value in (keybuf, databuf, output):
                _wipe(value)
            lib.EVP_CIPHER_CTX_free(context)
            lib.ERR_clear_error()
