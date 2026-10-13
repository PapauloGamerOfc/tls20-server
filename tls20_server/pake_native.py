"""Explicit optional native RFC8492 primitive, never Python secret group math.

The original MIT helper in native/pake.c is a separate local build. Its API
receives public OpenSSL function pointers from the explicitly selected provider.
No private ABI, executable discovery, runtime compilation or binary download is
performed. Python cannot guarantee erasure of caller-owned immutable bytes.
"""

import ctypes as ct
import os
from pathlib import Path

from .errors import ConfigurationError, ProtocolError
from .openssl_provider import OpenSSLProvider, _buffer, _wipe
from .secret_lifecycle import sync_protocol_boundary
from . import ffdhe


GROUPS = {23: (b"prime256v1", 32), 24: (b"secp384r1", 48), 25: (b"secp521r1", 66),
          **{group:(None,width) for group,width in ffdhe.SIZES.items()}}


class PakeProvider:
    def __init__(self, provider: OpenSSLProvider, helper_path, *, allow_test_only=False):
        if not isinstance(provider, OpenSSLProvider):
            raise ConfigurationError("PAKE requires an explicit OpenSSL provider")
        path = Path(helper_path)
        if not path.is_absolute() or not path.is_file():
            raise ConfigurationError("PAKE helper requires an explicit absolute existing path")
        self.provider = provider
        try:
            self.lib = ct.CDLL(str(path), **({"winmode": 0x100 | 0x1000} if os.name == "nt" else {}))
            self.lib.tls20_pwd_abi.restype = ct.c_uint
            abi = self.lib.tls20_pwd_abi()
            if abi != 1 and not (allow_test_only and abi == 0x80000001):
                raise ConfigurationError("unsupported or test-only PAKE native ABI")
            self.test_only = bool(abi & 0x80000000)
            self.lib.tls20_pwd_function_name.restype = ct.c_char_p
            self.lib.tls20_pwd_function_name.argtypes = [ct.c_size_t]
            addresses = []
            for index in range(256):
                name = self.lib.tls20_pwd_function_name(index)
                if name is None:
                    break
                addresses.append(ct.cast(getattr(provider.lib, name.decode("ascii")), ct.c_void_p).value)
            else:
                raise ConfigurationError("invalid PAKE native function table")
            self.functions = (ct.c_void_p * len(addresses))(*addresses)
            self.lib.tls20_pwd_new.restype = ct.c_void_p
            self.lib.tls20_pwd_new.argtypes = [ct.POINTER(ct.c_void_p), ct.c_size_t, ct.c_void_p, ct.c_int,
                                              ct.c_void_p, ct.c_void_p, ct.c_uint]
            self.lib.tls20_pwd_commit.restype = ct.c_int
            self.lib.tls20_pwd_commit.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_size_t]
            self.lib.tls20_pwd_finish.restype = ct.c_int
            self.lib.tls20_pwd_finish.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.c_void_p, ct.c_size_t]
            self.lib.tls20_pwd_free.restype = None
            self.lib.tls20_pwd_free.argtypes = [ct.c_void_p]
            self.lib.tls20_pwd_ff_new.restype = ct.c_void_p
            self.lib.tls20_pwd_ff_new.argtypes = [ct.POINTER(ct.c_void_p),ct.c_size_t,ct.c_void_p,
                ct.c_void_p,ct.c_size_t,ct.c_void_p,ct.c_void_p,ct.c_uint]
            self.lib.tls20_pwd_ff_commit.restype=ct.c_int
            self.lib.tls20_pwd_ff_commit.argtypes=self.lib.tls20_pwd_commit.argtypes
            self.lib.tls20_pwd_ff_finish.restype=ct.c_int
            self.lib.tls20_pwd_ff_finish.argtypes=self.lib.tls20_pwd_finish.argtypes
        except (OSError, AttributeError, UnicodeError) as exc:
            raise ConfigurationError("could not load explicit PAKE helper ABI") from exc

    @sync_protocol_boundary
    def create(self, base, client_random, *, group=23, hash_name="sha256"):
        if (not isinstance(base, bytes) or len(base) != 32 or not isinstance(client_random, bytes)
                or len(client_random) != 32 or group not in GROUPS or hash_name not in ("sha256", "sha384")):
            raise ProtocolError("invalid PAKE primitive inputs")
        with self.provider._native_scope():
            self.provider._ready()
            base_buffer, pointer = None, None
            try:
                # Allocate separately under cleanup: allocating the public
                # random can fail after the secret base copy already exists.
                base_buffer = _buffer(base)
                random_buffer = _buffer(client_random)
                if group in ffdhe.SIZES:
                    prime=_buffer(ffdhe.PRIMES[group].to_bytes(ffdhe.SIZES[group],"big"))
                    pointer=self.lib.tls20_pwd_ff_new(self.functions,len(self.functions),self.provider._context,
                        prime,ffdhe.SIZES[group],base_buffer,random_buffer,int(hash_name[3:]))
                else:
                    nid = self.provider.lib.OBJ_txt2nid(GROUPS[group][0])
                    pointer = self.lib.tls20_pwd_new(self.functions, len(self.functions), self.provider._context,
                                                    nid, base_buffer, random_buffer, int(hash_name[3:]))
                if not pointer:
                    self.provider.lib.ERR_clear_error()
                    raise ProtocolError("native password element derivation failed")
                state = PakeState(self, pointer, group)
                pointer = None  # Ownership transfers only after construction.
                return state
            finally:
                if base_buffer is not None:
                    _wipe(base_buffer)
                if pointer:
                    self.lib.tls20_pwd_free(pointer)


class PakeState:
    def __init__(self, provider, pointer, group):
        # create() still owns the pointer while construction can fail. Reserve
        # the attribute before accounting, then publish ownership last.
        self.pointer = None
        self.provider, self.group = provider, group
        provider.provider._live_keys += 1
        self.pointer = pointer

    def close(self):
        if not getattr(self, "pointer", None):
            return  # Also safe for an object whose __init__ never completed.
        with self.provider.provider._native_scope():
            if self.pointer:
                self.provider.lib.tls20_pwd_free(self.pointer)
                self.pointer = None
                self.provider.provider._live_keys -= 1

    def __del__(self):
        self.close()

    def commit(self):
        with self.provider.provider._native_scope():
            if not self.pointer:
                raise ProtocolError("PAKE state is closed")
            output = ct.create_string_buffer(2050)
            method=(self.provider.lib.tls20_pwd_ff_commit if self.group in ffdhe.SIZES else self.provider.lib.tls20_pwd_commit)
            length = method(self.pointer, output, len(output))
            if length <= 0:
                self.close()
                raise ProtocolError("PAKE commitment generation failed")
            return output.raw[:length]

    def finish(self, peer):
        with self.provider.provider._native_scope():
            if not self.pointer or not isinstance(peer, bytes):
                raise ProtocolError("PAKE state is closed or peer input invalid")
            output = ct.create_string_buffer(GROUPS[self.group][1])
            try:
                method=(self.provider.lib.tls20_pwd_ff_finish if self.group in ffdhe.SIZES else self.provider.lib.tls20_pwd_finish)
                length = method(self.pointer, _buffer(peer), len(peer), output, len(output))
                if length != len(output):
                    raise ProtocolError("invalid PAKE commitment", alert=47)
                return output.raw
            finally:
                _wipe(output)
                self.close()
