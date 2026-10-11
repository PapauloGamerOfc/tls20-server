"""Explicit native PAKE tests; fixture oracle uses public, non-secret numbers."""

import ctypes as ct
import hashlib
import hmac
import os
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.openssl_provider import OpenSSLProvider
from tls20_server.pake_native import PakeProvider


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_PAKE"),
                     "explicit native PAKE fixtures not configured")
class NativePakeTests(unittest.TestCase):
    def setUp(self):
        self.native = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        self.provider = PakeProvider(self.native, os.environ["TLS20_TEST_PAKE"])

    def tearDown(self):
        self.native.close()

    def test_all_ec_groups_both_hashes_real_shared_secrets(self):
        for group, width in ((23, 32), (24, 48), (25, 66)):
            for name in ("sha256", "sha384"):
                with self.subTest(group=group, hash=name):
                    one = self.provider.create(bytes(range(32)), bytes(32), group=group, hash_name=name)
                    two = self.provider.create(bytes(range(32)), bytes(32), group=group, hash_name=name)
                    try:
                        A, B = one.commit(), two.commit()
                        self.assertEqual(len(A), 3 * width + 1)
                        self.assertEqual(one.finish(B), two.finish(A))
                    finally:
                        one.close(); two.close()

    def test_bad_commit_and_reuse_fail_closed(self):
        for change in (lambda v: v, lambda v: bytes(len(v)), lambda v: v[:-1],
                       lambda v: v[:64] + b"\x01\x01", lambda v: v + b"x"):
            state = self.provider.create(bytes(32), bytes(32))
            share = state.commit()
            with self.assertRaises(ProtocolError):
                state.finish(change(share))
            with self.assertRaises(ProtocolError):
                state.commit()

    def test_ffc_full_entropy_all_registered_safe_prime_groups(self):
        from tls20_server.ffdhe import SIZES
        for group,width in SIZES.items():
            for name in ("sha256","sha384"):
                one=self.provider.create(bytes(range(32)),bytes(32),group=group,hash_name=name)
                two=self.provider.create(bytes(range(32)),bytes(32),group=group,hash_name=name)
                try:
                    A,B=one.commit(),two.commit()
                    self.assertEqual(len(A),width*2+2)
                    self.assertEqual(int.from_bytes(A[width:width+2],"big"),width)
                    self.assertEqual(one.finish(B),two.finish(A))
                finally:one.close();two.close()
        for change in (lambda v:v,lambda v:bytes(len(v)),lambda v:v[:-1],
                       lambda v:v[:256]+b"\x00\x01\x01"):
            state=self.provider.create(bytes(32),bytes(32),group=256)
            share=state.commit()
            with self.assertRaises(ProtocolError):state.finish(change(share))

    def test_different_password_secrets_differ(self):
        one = self.provider.create(bytes(32), bytes(32))
        two = self.provider.create(bytes([1]) * 32, bytes(32))
        try:
            A, B = one.commit(), two.commit()
            self.assertNotEqual(one.finish(B), two.finish(A))
        finally:
            one.close(); two.close()

    def test_native_null_outputs_and_wrong_curve_subgroups_fail_closed(self):
        state=self.provider.create(bytes(32),bytes(32))
        try:
            self.assertEqual(self.provider.lib.tls20_pwd_commit(state.pointer,None,199),0)
            share=state.commit()
            self.assertEqual(self.provider.lib.tls20_pwd_finish(state.pointer,ct.create_string_buffer(share),len(share),None,32),0)
        finally:state.close()
        prime=(1<<256)-(1<<224)+(1<<192)+(1<<96)-1
        order=int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16)
        for change in (lambda v:prime.to_bytes(32,"big")+v[32:],
                       lambda v:bytes(32)+v[32:],
                       lambda v:v[:32]+prime.to_bytes(32,"big")+v[64:],
                       lambda v:v[:65]+order.to_bytes(32,"big"),
                       lambda v:bytes(31)+b"\x01"+bytes(31)+b"\x01"+v[64:]):
            one=self.provider.create(bytes(32),bytes(32));share=one.commit()
            with self.assertRaises(ProtocolError):one.finish(change(share))
        from tls20_server.ffdhe import PRIMES
        prime=PRIMES[256];order=(prime-1)//2
        nonmember=next(x for x in range(2,100) if pow(x,order,prime)!=1)
        for number in (0,1,prime-1,prime,nonmember):
            one=self.provider.create(bytes(32),bytes(32),group=256);share=one.commit()
            with self.assertRaises(ProtocolError):one.finish(number.to_bytes(256,"big")+share[256:])

    def test_test_only_helper_rejected_by_default(self):
        name = os.environ.get("TLS20_TEST_PAKE_ORACLE")
        if not name:
            self.skipTest("explicit test-only helper absent")
        with self.assertRaises(ConfigurationError):
            PakeProvider(self.native, name)

    def test_native_element_matches_independent_public_fixture_oracle(self):
        name = os.environ.get("TLS20_TEST_PAKE_ORACLE")
        if not name:
            self.skipTest("explicit test-only helper absent")
        provider = PakeProvider(self.native, name, allow_test_only=True)
        provider.lib.tls20_pwd_test_element.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_size_t]
        provider.lib.tls20_pwd_test_element.restype = ct.c_int
        # NIST public P-256 domain; all arithmetic below handles known fixtures.
        prime = (1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1
        a = prime - 3
        b = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
        base, random = bytes(range(32)), bytes(range(32, 64))
        for hash_name, algorithm in (("sha256", hashes.SHA256()), ("sha384", hashes.SHA384())):
            for counter in range(1, 256):
                seed = hmac.digest(bytes(algorithm.block_size), base + bytes((counter,)) + prime.to_bytes(32, "big"), hash_name)
                label = b"tls20 TLS-PWD Hunting And Pecking"
                digest = hashlib.new(hash_name, random).digest()
                info = b"\x00\x28" + bytes((len(label),)) + label + bytes((len(digest),)) + digest
                raw = HKDFExpand(algorithm, 40, info).derive(seed)
                x = int.from_bytes(raw, "big") % (prime - 1) + 1
                rhs = (x*x*x + a*x + b) % prime
                y = pow(rhs, (prime+1)//4, prime)
                if y*y % prime == rhs:
                    if y & 1 != seed[-1] & 1:
                        y = prime-y
                    expected = x.to_bytes(32, "big") + y.to_bytes(32, "big")
                    break
            state = provider.create(base, random, hash_name=hash_name)
            try:
                output = ct.create_string_buffer(64)
                self.assertEqual(provider.lib.tls20_pwd_test_element(state.pointer, output, 64), 64)
                self.assertEqual(output.raw, expected)
            finally:
                state.close()

    def test_ffc_native_element_matches_public_hkdf_oracle(self):
        name=os.environ.get("TLS20_TEST_PAKE_ORACLE")
        if not name:self.skipTest("explicit test-only helper absent")
        from tls20_server.ffdhe import PRIMES,SIZES
        provider=PakeProvider(self.native,name,allow_test_only=True)
        provider.lib.tls20_pwd_test_element.argtypes=[ct.c_void_p,ct.c_void_p,ct.c_size_t]
        provider.lib.tls20_pwd_test_element.restype=ct.c_int
        for group in SIZES:
            width,prime=SIZES[group],PRIMES[group]
            for hash_name,algorithm in (("sha256",hashes.SHA256()),("sha384",hashes.SHA384())):
                base,random=bytes(range(32)),bytes(range(32,64))
                for counter in range(1,256):
                    seed=hmac.digest(bytes(algorithm.block_size),base+bytes([counter])+prime.to_bytes(width,"big"),hash_name)
                    label=b"tls20 TLS-PWD Hunting And Pecking"
                    context=hashlib.new(hash_name,random).digest()
                    size=width+8
                    info=size.to_bytes(2,"big")+bytes([len(label)])+label+bytes([len(context)])+context
                    expanded=HKDFExpand(algorithm,size,info).derive(seed)
                    candidate=(int.from_bytes(expanded,"big")%(prime-1)+1)**2%prime
                    if candidate>1:break
                state=provider.create(base,random,group=group,hash_name=hash_name)
                try:
                    output=ct.create_string_buffer(width)
                    self.assertEqual(provider.lib.tls20_pwd_test_element(state.pointer,output,width),width)
                    self.assertEqual(output.raw,candidate.to_bytes(width,"big"))
                finally:state.close()
