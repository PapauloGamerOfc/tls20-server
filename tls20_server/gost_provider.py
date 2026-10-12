"""Explicit GOST provider bridge; no process-global provider/engine registration.

The caller supplies both an OpenSSL 3.5+ library and a compatible gost-engine
provider module. Only public EVP APIs are used. Secret arithmetic stays native.
Record users MUST apply RFC9367 TLSTREE and sequence limits, not just MGM.
"""

from __future__ import annotations

import ctypes as ct
from pathlib import Path
import threading

from cryptography.exceptions import InvalidTag

from .errors import ConfigurationError, ProtocolError
from .openssl_provider import OpenSSLProvider, NativeKey, P, I, Z, U, _buffer, _wipe, _synchronized


GROUPS = {
    34: (b"gost2012_256", b"TCA", 32), 35: (b"gost2012_256", b"TCB", 32),
    36: (b"gost2012_256", b"TCC", 32), 37: (b"gost2012_256", b"TCD", 32),
    38: (b"gost2012_512", b"A", 64), 39: (b"gost2012_512", b"B", 64),
    40: (b"gost2012_512", b"C", 64),
}
HASHES = {"streebog256": (b"md_gost12_256", 32), "streebog512": (b"md_gost12_512", 64)}
_KEY_OIDS = (bytes.fromhex("2a85030701010101"), bytes.fromhex("2a85030701010102"))
_CURVE_OIDS = {
    bytes.fromhex("2a85030701020101") + bytes([n]): 33 + n for n in range(1, 5)
} | {
    bytes.fromhex("2a85030701020102") + bytes([n]): 37 + n for n in range(1, 4)
} | {bytes.fromhex("2a8503020223") + bytes([n]): 34 + n for n in range(1, 4)}


def spki_group(spki):
    """Strict public encoding recognition, NOT a trust or point validator."""
    from .pki import _element, _children
    if not isinstance(spki, bytes) or not 1 <= len(spki) <= 8192:
        raise ProtocolError("GOST SPKI bounds")
    tag, body, end, _ = _element(spki)
    fields = _children(body)
    if tag != 0x30 or end != len(spki) or len(fields) != 2 or fields[0][0] != 0x30 or fields[1][0] != 3 or fields[1][1][:1] != b"\0":
        raise ProtocolError("invalid GOST SPKI framing")
    algorithm = _children(fields[0][1])
    if len(algorithm) != 2 or algorithm[0][0] != 6 or algorithm[0][1] not in _KEY_OIDS or algorithm[1][0] != 0x30:
        raise ProtocolError("unsupported GOST SPKI algorithm")
    parameters = _children(algorithm[1][1])
    if not 1 <= len(parameters) <= 2 or any(x[0] != 6 for x in parameters) or parameters[0][1] not in _CURVE_OIDS:
        raise ProtocolError("unsupported GOST curve parameters")
    group = _CURVE_OIDS[parameters[0][1]]
    width = GROUPS[group][2]
    legacy_curve = parameters[0][1].startswith(bytes.fromhex("2a8503020223"))
    if (legacy_curve and len(parameters) != 2) or (not legacy_curve and group in (35, 36, 37) and len(parameters) != 1):
        raise ProtocolError("GOST curve digest parameter presence violates RFC9215")
    if algorithm[0][1] != _KEY_OIDS[width == 64] or (len(parameters) == 2 and parameters[1][1] != bytes.fromhex("2a850307010102") + bytes([3 if width == 64 else 2])):
        raise ProtocolError("GOST key, curve and digest parameters disagree")
    encoded = fields[1][1][1:]
    tag, public, end, _ = _element(encoded)
    if tag != 4 or end != len(encoded) or len(public) != width * 2:
        raise ProtocolError("GOST public point OCTET STRING encoding")
    return group
# (cipher, block/tag/IV width, maximum sequence number, three TLSTREE masks).
SUITES = {
    0xc103: ("kuznyechik-mgm", 16, (1 << 64) - 1,
             (0xf800000000000000, 0xfffffff000000000, 0xffffffffffffe000)),
    0xc104: ("magma-mgm", 8, (1 << 64) - 1,
             (0xffe0000000000000, 0xffffffffc0000000, 0xffffffffffffff80)),
    0xc105: ("kuznyechik-mgm", 16, (1 << 42) - 1,
             (0xffffffffe0000000, 0xffffffffffff0000, 0xfffffffffffffff8)),
    0xc106: ("magma-mgm", 8, (1 << 39) - 1,
             (0xfffffffffc000000, 0xffffffffffffe000, 0xffffffffffffffff)),
}


class GOSTProvider(OpenSSLProvider):
    certificate_properties = None  # Only this instance's explicit providers.

    def __init__(self, library_path, module_path):
        self._gost_provider = None
        path = Path(module_path)
        if not path.is_absolute() or not path.is_file():
            # Establish the base destructor invariants even for invalid input.
            self._lock = threading.RLock()
            self._live_keys, self._ciphers = 0, {}
            self._context = self._provider = None
            raise ConfigurationError("GOST module must be an explicit existing absolute path")
        super().__init__(library_path)
        try:
            self._bind_gost()
            with self._native_scope():
                self._gost_provider = self.lib.OSSL_PROVIDER_load(self._context, str(path).encode())
                if not self._gost_provider:
                    raise ConfigurationError("could not load requested GOST provider into private context")
                for name in ("kuznyechik-mgm", "magma-mgm"):
                    pointer = self.lib.EVP_CIPHER_fetch(self._context, name.encode(), None)
                    if not pointer:
                        raise ConfigurationError("required GOST MGM cipher unavailable")
                    self._ciphers[name] = pointer
                # Fail construction when the module is loadable but incomplete.
                for name in HASHES:
                    self.digest(name, b"")
        except BaseException:
            self.close()
            raise

    def _bind_gost(self):
        declarations = {
            "EVP_Q_digest": (I, [P, ct.c_char_p, ct.c_char_p, P, Z, P, ct.POINTER(Z)]),
            "EVP_Q_mac": (P, [P, ct.c_char_p, ct.c_char_p, ct.c_char_p, P, P, Z, P, Z, P, Z, ct.POINTER(Z)]),
            "EVP_PKEY_get_utf8_string_param": (I, [P, ct.c_char_p, P, Z, ct.POINTER(Z)]),
            "i2d_PUBKEY": (I, [P, ct.POINTER(P)]),
            "EVP_DigestVerifyUpdate": (I, [P, P, Z]),
            "EVP_DigestVerifyFinal": (I, [P, P, Z]),
            "X509_STORE_CTX_set_verify_cb": (None, [P, P]),
            "X509_STORE_CTX_get_error": (I, [P]),
            "X509_STORE_CTX_set_error": (None, [P, I]),
            "X509_STORE_CTX_get_error_depth": (I, [P]),
            "X509_STORE_CTX_get_current_cert": (P, [P]),
            "X509_STORE_CTX_get0_chain": (P, [P]),
        }
        for name, (restype, argtypes) in declarations.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = restype, argtypes

    def _configure_certificate_verifier(self, context):
        """Bridge only stock OpenSSL's missing GOST ASN.1 digest dispatch.

        This is not a path validator or a trust callback. On error7 only, the
        actual candidate path's next issuer must verify the exact GOST signed
        certificate via the explicit native EVP implementation. Every other
        OpenSSL path/purpose/name/constraints error remains fatal.
        """
        from .pki import _load_pkix_der, certificate_public_key, certificate_signature_scheme, GOSTPublicKey

        def der(pointer):
            length = self.lib.i2d_X509(pointer, None)
            if not 1 <= length <= 1 << 20:
                raise ProtocolError("native certificate framing")
            output = ct.create_string_buffer(length)
            cursor = P(ct.addressof(output))
            if self.lib.i2d_X509(pointer, ct.byref(cursor)) != length:
                raise ProtocolError("native certificate serialization")
            return output.raw

        @ct.CFUNCTYPE(I, I, P)
        def verify(preverified, state):
            if preverified:
                return 1
            if self.lib.X509_STORE_CTX_get_error(state) != 7:
                return 0
            try:
                depth = self.lib.X509_STORE_CTX_get_error_depth(state)
                chain = self.lib.X509_STORE_CTX_get0_chain(state)
                if not chain or not 0 <= depth < self.lib.OPENSSL_sk_num(chain) - 1:
                    return 0
                current = self.lib.X509_STORE_CTX_get_current_cert(state)
                if current != self.lib.OPENSSL_sk_value(chain, depth):
                    return 0
                child = _load_pkix_der(der(current))
                if child.signature_algorithm_oid.dotted_string not in ("1.2.643.7.1.1.3.2", "1.2.643.7.1.1.3.3"):
                    return 0
                issuer = _load_pkix_der(der(self.lib.OPENSSL_sk_value(chain, depth + 1)))
                if child.issuer != issuer.subject:
                    return 0
                key = certificate_public_key(issuer, signature_provider=self)
                if not isinstance(key, GOSTPublicKey):
                    return 0
                self.verify_gost(key.spki_der, child.tbs_certificate_bytes, child.signature,
                                  certificate_signature_scheme(child, issuer), certificate_encoding=True)
                self.lib.X509_STORE_CTX_set_error(state, 0)
                self.lib.ERR_clear_error()
                return 1
            except Exception:
                return 0

        self.lib.X509_STORE_CTX_set_verify_cb(context, ct.cast(verify, P))
        return verify

    @_synchronized
    def close(self):
        if self._live_keys:
            raise ProtocolError("cannot close optional provider while native keys are alive")
        if self._context:
            self.lib.OPENSSL_thread_stop_ex(self._context)
        # Fetched cipher implementations must die before their provider unloads.
        for name in ("kuznyechik-mgm", "magma-mgm"):
            pointer = self._ciphers.pop(name, None)
            if pointer:
                self.lib.EVP_CIPHER_free(pointer)
        if self._gost_provider:
            self.lib.OSSL_PROVIDER_unload(self._gost_provider)
            self._gost_provider = None
        super().close()

    @_synchronized
    def digest(self, name, data):
        if name == "sm3":
            return super().digest(name, data)
        self._ready()
        if name not in HASHES or not isinstance(data, bytes) or len(data) > 16 << 20:
            raise ProtocolError("invalid GOST digest input")
        algorithm, width = HASHES[name]
        output, count = ct.create_string_buffer(width), Z()
        source = _buffer(data)
        try:
            self._check(self.lib.EVP_Q_digest(self._context, algorithm, None, source, len(data), output, ct.byref(count)))
            if count.value != width:
                raise ProtocolError("unexpected GOST digest length")
            return output.raw
        finally:
            _wipe(source)
            _wipe(output)

    @_synchronized
    def hmac(self, name, key, data):
        if name == "sm3":
            return super().hmac(name, key, data)
        self._ready()
        if name not in HASHES or not isinstance(key, bytes) or not isinstance(data, bytes) or len(key) > 1 << 20 or len(data) > 16 << 20:
            raise ProtocolError("invalid GOST HMAC input")
        algorithm, width = HASHES[name]
        source, secret, output, count = _buffer(data), _buffer(key), ct.create_string_buffer(width), Z()
        try:
            if not self.lib.EVP_Q_mac(self._context, b"HMAC", None, algorithm, None,
                                     secret, len(key), source, len(data), output, width, ct.byref(count)) or count.value != width:
                raise ProtocolError("native GOST HMAC failed")
            return output.raw
        finally:
            for value in (source, secret, output):
                _wipe(value)

    def tlstree(self, suite, root_key, sequence):
        if suite not in SUITES or not isinstance(sequence, int) or not 0 <= sequence <= SUITES[suite][2] or not isinstance(root_key, bytes) or len(root_key) != 32:
            raise ProtocolError("GOST TLSTREE suite, key or sequence limit")
        key = root_key
        for level, mask in enumerate(SUITES[suite][3], 1):
            key = self.hmac("streebog256", key, b"\x01level" + str(level).encode() + b"\0" +
                            (sequence & mask).to_bytes(8, "big") + b"\x01\x00")
        return key

    @_synchronized
    def aead(self, name, key):
        if name not in ("kuznyechik-mgm", "magma-mgm"):
            return super().aead(name, key)
        self._ready()
        if not isinstance(key, bytes) or len(key) != 32:
            raise ProtocolError("GOST MGM requires a 32-byte key")
        return _MGM(self, name, key)

    @_synchronized
    def record_cipher(self, suite, key):
        self._ready()
        if suite not in SUITES or not isinstance(key, bytes) or len(key) != 32:
            raise ProtocolError("invalid GOST record cipher")
        return _RecordCipher(self, suite, key)

    def _parameters(self, group, generate):
        if group not in GROUPS:
            raise ProtocolError("unsupported GOST group")
        name, curve, width = GROUPS[group]
        context, pointer = self.lib.EVP_PKEY_CTX_new_from_name(self._context, name, None), P()
        try:
            if not context:
                raise ProtocolError("GOST key context unavailable")
            self._check((self.lib.EVP_PKEY_keygen_init if generate else self.lib.EVP_PKEY_paramgen_init)(context))
            self._check(self.lib.EVP_PKEY_CTX_set_group_name(context, curve))
            self._check(self.lib.EVP_PKEY_generate(context, ct.byref(pointer)))
            result, pointer = pointer.value, P()
            return result, width
        finally:
            self.lib.EVP_PKEY_free(pointer)
            self.lib.EVP_PKEY_CTX_free(context)

    def _public(self, key, width):
        output, count = ct.create_string_buffer(2 * width), Z()
        self._check(self.lib.EVP_PKEY_get_octet_string_param(key, b"encoded-pub-key", output, 2 * width, ct.byref(count)))
        if count.value != 2 * width:
            raise ProtocolError("unexpected GOST public encoding")
        return output.raw

    @_synchronized
    def generate_gost(self, group):
        self._ready()
        pointer, width = self._parameters(group, True)
        try:
            public = self._public(pointer, width)
            result = NativeKey(self, pointer)
            result.group = group
            pointer = None
            return result, public
        finally:
            self.lib.EVP_PKEY_free(pointer)

    @_synchronized
    def exchange_gost(self, private, group, public):
        self._ready()
        if group not in GROUPS or not isinstance(private, NativeKey) or private.provider is not self or not private.pointer or getattr(private, "group", None) != group:
            raise ProtocolError("GOST private key group/provider mismatch")
        width = GROUPS[group][2]
        if not isinstance(public, bytes) or len(public) != 2 * width:
            raise ProtocolError("GOST public share length", alert=47)
        peer, context, check = None, None, None
        output, encoded = ct.create_string_buffer(width), _buffer(public)
        try:
            peer, _ = self._parameters(group, False)
            self._check(self.lib.EVP_PKEY_set1_encoded_public_key(peer, encoded, len(public)), alert=47)
            # Reject coordinate reductions/noncanonical wire encodings too.
            if self._public(peer, width) != public:
                raise ProtocolError("noncanonical GOST point", alert=47)
            check = self.lib.EVP_PKEY_CTX_new_from_pkey(self._context, peer, None)
            if not check:
                raise ProtocolError("GOST validation context unavailable")
            self._check(self.lib.EVP_PKEY_public_check(check), alert=47)
            context = self.lib.EVP_PKEY_CTX_new_from_pkey(self._context, private.pointer, None)
            if not context:
                raise ProtocolError("GOST exchange context unavailable")
            self._check(self.lib.EVP_PKEY_derive_init(context))
            self._check(self.lib.EVP_PKEY_derive_set_peer(context, peer))
            count = Z(width)
            self._check(self.lib.EVP_PKEY_derive(context, output, ct.byref(count)))
            if count.value != width:
                raise ProtocolError("unexpected GOST secret length")
            return output.raw
        finally:
            _wipe(output)
            self.lib.EVP_PKEY_CTX_free(check)
            self.lib.EVP_PKEY_CTX_free(context)
            self.lib.EVP_PKEY_free(peer)

    @_synchronized
    def verify_gost(self, spki, message, signature, scheme, *, certificate_encoding=False):
        self._ready()
        group = spki_group(spki)
        width = GROUPS[group][2]
        if scheme != 0x0709 + group - 34 or not isinstance(message, bytes) or len(message) > 1 << 20 or not isinstance(signature, bytes) or len(signature) != 2 * width:
            raise ProtocolError("GOST signature scheme/key/length mismatch")
        # X.509 uses s(big endian)||r(big endian); RFC9367 signed TLS
        # objects use r(little endian)||s(little endian). Never try both.
        encoded_signature = signature if certificate_encoding else signature[::-1]
        encoded, source, sig = map(_buffer, (spki, message, encoded_signature))
        cursor, key, context, check = P(ct.addressof(encoded)), None, None, None
        try:
            key = self.lib.d2i_PUBKEY_ex(None, ct.byref(cursor), len(spki), self._context, None)
            if not key or cursor.value != ct.addressof(encoded) + len(spki) or self.lib.EVP_PKEY_is_a(key, GROUPS[group][0]) != 1:
                raise ProtocolError("native GOST SPKI decoding failed")
            check = self.lib.EVP_PKEY_CTX_new_from_pkey(self._context, key, None)
            if not check:
                raise ProtocolError("native GOST validation context unavailable")
            self._check(self.lib.EVP_PKEY_public_check(check))
            context, pctx = self.lib.EVP_MD_CTX_new(), P()
            if not context:
                raise ProtocolError("native GOST signature context unavailable")
            self._check(self.lib.EVP_DigestVerifyInit_ex(context, ct.byref(pctx), HASHES["streebog512" if width == 64 else "streebog256"][0], self._context, None, key, None))
            self._check(self.lib.EVP_DigestVerifyUpdate(context, source, len(message)))
            self._check(self.lib.EVP_DigestVerifyFinal(context, sig, len(signature)))
        finally:
            self.lib.EVP_MD_CTX_free(context)
            self.lib.EVP_PKEY_CTX_free(check)
            self.lib.EVP_PKEY_free(key)


class _RecordCipher:
    """Per-direction/epoch TLSTREE cache; never shared between connections.

    The owning record layer enforces monotonic sequence numbers and performs
    KeyUpdate. This object also checks SNMAX before even deriving a key.
    """
    def __init__(self, provider, suite, key):
        self.provider, self.suite, self.root = provider, suite, key
        self.values, self.keys = [None] * 3, [None] * 3
        self.cipher = None

    def encrypt_record(self, sequence, nonce, data, aad):
        return self._crypt(True, sequence, nonce, data, aad)

    def decrypt_record(self, sequence, nonce, data, aad):
        return self._crypt(False, sequence, nonce, data, aad)

    @_synchronized
    def _crypt(self, encrypt, sequence, nonce, data, aad):
        self.provider._ready()
        name, width, maximum, masks = SUITES[self.suite]
        if not isinstance(sequence, int) or not 0 <= sequence <= maximum or not isinstance(nonce, bytes) or len(nonce) != width:
            raise ProtocolError("GOST record sequence/nonce limit")
        changed, key = False, self.root
        for index, mask in enumerate(masks):
            value = sequence & mask
            changed = changed or value != self.values[index]
            if changed:
                self.keys[index] = self.provider.hmac("streebog256", key,
                    b"\x01level" + str(index + 1).encode() + b"\0" + value.to_bytes(8, "big") + b"\x01\0")
                self.values[index] = value
            key = self.keys[index]
        if changed or self.cipher is None:
            self.cipher = self.provider.aead(name, key)
        nonce = bytes([nonce[0] & 0x7f]) + nonce[1:]
        return (self.cipher.encrypt if encrypt else self.cipher.decrypt)(nonce, data, aad)


class _MGM:
    def __init__(self, provider, name, key):
        self.provider, self.name, self.key = provider, name, key
        self.width = 16 if name == "kuznyechik-mgm" else 8

    def encrypt(self, nonce, plaintext, aad):
        return self._crypt(True, nonce, plaintext, aad)

    def decrypt(self, nonce, ciphertext, aad):
        return self._crypt(False, nonce, ciphertext, aad)

    @_synchronized
    def _crypt(self, encrypt, nonce, data, aad):
        self.provider._ready()
        if not all(isinstance(value, bytes) for value in (nonce, data, aad)) or len(nonce) != self.width or len(data) > (1 << 20) or len(aad) > (1 << 20):
            raise ProtocolError("MGM input bounds")
        if not encrypt and len(data) < self.width:
            raise InvalidTag
        if nonce[0] & 0x80:
            raise ProtocolError("raw MGM nonce top bit must be zero")
        content, tag = (data, bytes(self.width)) if encrypt else (data[:-self.width], data[-self.width:])
        lib, context = self.provider.lib, self.provider.lib.EVP_CIPHER_CTX_new()
        keybuf, noncebuf, databuf, aadbuf, tagbuf = map(_buffer, (self.key, nonce, content, aad, tag))
        output, count = ct.create_string_buffer(len(content) + 32), I()
        init = lib.EVP_EncryptInit_ex2 if encrypt else lib.EVP_DecryptInit_ex2
        update = lib.EVP_EncryptUpdate if encrypt else lib.EVP_DecryptUpdate
        final = lib.EVP_EncryptFinal_ex if encrypt else lib.EVP_DecryptFinal_ex
        try:
            if not context:
                raise ProtocolError("MGM context allocation failed")
            self.provider._check(init(context, self.provider._ciphers[self.name], keybuf, noncebuf, None))
            if aad:
                self.provider._check(update(context, None, ct.byref(count), aadbuf, len(aad)))
            self.provider._check(update(context, output, ct.byref(count), databuf, len(content)))
            length = count.value
            if not encrypt:
                self.provider._check(lib.EVP_CIPHER_CTX_ctrl(context, 0x11, self.width, tagbuf))
            status = final(context, ct.byref(output, length), ct.byref(count))
            if status != 1:
                if not encrypt:
                    raise InvalidTag
                self.provider._check(status)
            length += count.value
            if length != len(content):
                raise ProtocolError("MGM output length mismatch")
            if encrypt:
                self.provider._check(lib.EVP_CIPHER_CTX_ctrl(context, 0x10, self.width, tagbuf))
            return output.raw[:length] + (tagbuf.raw if encrypt else b"")
        finally:
            for value in (keybuf, databuf, output):
                _wipe(value)
            lib.EVP_CIPHER_CTX_free(context)
            lib.ERR_clear_error()
