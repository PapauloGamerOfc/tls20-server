"""Provider-backed Brainpool and constrained RSA-PSS offline signatures."""
import asyncio
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.x509.oid import NameOID

from tls20_server.credential_profiles import CredentialPolicy, DELEGATION_USAGE, resolve_peer
from tls20_server.errors import ProtocolError
from tls20_server.pki import (RSAPSSPublicKey, _children, _element, certificate_public_key,
    certificate_signature_scheme, verify_public_signature, load_signature_public_key, Credentials)
from tests.test_pki import der, issue


def tlv(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length()+7)//8)]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag]) + length + value


def pss_parameters(hash_number=1, mgf_number=1, salt=32, trailer=1):
    def digest(number):
        return tlv(0x30, tlv(6, bytes.fromhex('6086480165030402') + bytes([number])) + b'\x05\x00')
    return tlv(0x30, tlv(0xa0, digest(hash_number)) + tlv(0xa1, tlv(0x30,
        tlv(6, bytes.fromhex('2a864886f70d010108')) + digest(mgf_number)))
        + tlv(0xa2, tlv(2, bytes([salt]))) + tlv(0xa3, tlv(2, bytes([trailer]))))


class SignatureProfiles(unittest.TestCase):
    def setUp(self):
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Signature test')])
        self.peer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Signature peer')])
        self.root = issue(self.ca_key, self.ca_key, self.name, self.name, ca=True)
        self.proof_key = x25519.X25519PrivateKey.generate()
        self.policy = CredentialPolicy(trust_roots=(self.root,), peer_name='example.test')

    def parent(self, key):
        return issue(key, self.ca_key, self.peer_name, self.name,
            key_usage=x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            extra=[(x509.UnrecognizedExtension(DELEGATION_USAGE, b'\x05\x00'), False)])

    def pss_parent(self, key, parameters):
        original = self.parent(key)
        outer = _children(_element(der(original))[1])
        fields = _children(outer[0][1])
        public_fields = _children(_element(fields[6][2])[1])
        algorithm = tlv(0x30, tlv(6, bytes.fromhex('2a864886f70d01010a')) + parameters)
        fields[6] = (0x30, b'', tlv(0x30, algorithm + public_fields[1][2]))
        tbs = tlv(0x30, b''.join(field[2] for field in fields))
        signature = self.ca_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        return x509.load_der_x509_certificate(tlv(0x30, tbs + outer[1][2] + tlv(3, b'\0' + signature)))

    def grant(self, parent, key, scheme, algorithm):
        public = self.proof_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        body = (3900).to_bytes(4,'big') + b'\xfe\x00' + len(public).to_bytes(3,'big') + public + scheme.to_bytes(2,'big')
        message = b' '*64 + b'TLS20 server delegated credentials\0' + der(parent) + body
        if isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(message, padding.PSS(mgf=padding.MGF1(algorithm),salt_length=algorithm.digest_size), algorithm)
        else:
            signature = key.sign(message, ec.ECDSA(algorithm))
        return body + len(signature).to_bytes(2,'big') + signature

    def resolve(self, parent, grant, scheme):
        return resolve_peer((der(parent),), policy=self.policy, certificate_algorithms=(0x0403,),
            grant_algorithms=(scheme,), delegated_schemes=(0xfe00,), entry_extensions=(((34,grant),),))

    def test_all_brainpool_grants_and_distinct_certificate_offers(self):
        for curve, algorithm, scheme, ordinary in ((ec.BrainpoolP256R1(), hashes.SHA256(),0x081a,0x0403),
                (ec.BrainpoolP384R1(),hashes.SHA384(),0x081b,0x0503), (ec.BrainpoolP512R1(),hashes.SHA512(),0x081c,0x0603)):
            with self.subTest(scheme=scheme):
                key=ec.generate_private_key(curve)
                parent=self.parent(key)
                grant=self.grant(parent,key,scheme,algorithm)
                self.assertEqual(self.resolve(parent,grant,scheme).public_key.public_bytes_raw(),self.proof_key.public_key().public_bytes_raw())
                message=b'algorithm binding'; signature=key.sign(message,ec.ECDSA(algorithm))
                with self.assertRaises(ProtocolError): verify_public_signature(key.public_key(),ordinary,signature,message)
                issuer=issue(key,self.ca_key,self.name,self.name,ca=True)
                leaf=issue(self.proof_key,key,self.name,self.name,algorithm=algorithm)
                self.assertEqual(certificate_signature_scheme(leaf,issuer),scheme)

    def test_pss_family_and_key_constraints_survive_certificate_extraction(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        parent=self.pss_parent(key,pss_parameters())
        public=certificate_public_key(parent)
        self.assertIsInstance(public,RSAPSSPublicKey)
        self.assertEqual(public.restrictions,('sha256','sha256',32,1))
        reloaded=load_signature_public_key(public.spki_der)
        self.assertIsInstance(reloaded,RSAPSSPublicKey)
        self.assertEqual(reloaded.restrictions,public.restrictions)
        with self.assertRaises(ProtocolError): load_signature_public_key(public.spki_der+b'\0')
        grant=self.grant(parent,key,0x0809,hashes.SHA256())
        self.resolve(parent,grant,0x0809)
        message=b'PSS identity family'; signature=key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
        verify_public_signature(public,0x0809,signature,message)
        for candidate,scheme in ((key.public_key(),0x0809),(public,0x0804),(public,0x0401)):
            with self.assertRaises(ProtocolError): verify_public_signature(candidate,scheme,signature,message)
        for params in (pss_parameters(hash_number=2), pss_parameters(mgf_number=2), pss_parameters(salt=33), pss_parameters(trailer=2), b'\x30\x00'):
            restricted=certificate_public_key(self.pss_parent(key,params))
            with self.assertRaises(ProtocolError): verify_public_signature(restricted,0x0809,signature,message)
        unrestricted=certificate_public_key(self.pss_parent(key,b''))
        verify_public_signature(unrestricted,0x0809,signature,message)
        with self.assertRaises(ProtocolError): verify_public_signature(unrestricted,0x0809,signature[:-1],message)

    def test_real_tcp_grant_algorithms_resume_and_early_data(self):
        from tls20_server.handshake import client_handshake, server_handshake
        from tls20_server.tickets import TicketCache, TicketStore
        async def exercise():
            for scheme, key, digest in ((0x081a,ec.generate_private_key(ec.BrainpoolP256R1()),hashes.SHA256()),
                    (0x081b,ec.generate_private_key(ec.BrainpoolP384R1()),hashes.SHA384()),
                    (0x081c,ec.generate_private_key(ec.BrainpoolP512R1()),hashes.SHA512()),
                    (0x0809,rsa.generate_private_key(public_exponent=65537,key_size=2048),hashes.SHA256())):
                parent=self.pss_parent(key,pss_parameters()) if scheme==0x0809 else self.parent(key)
                credentials=Credentials([der(parent),der(self.root)],self.proof_key,
                    delegation=self.grant(parent,key,scheme,digest))
                cache,store=TicketCache(),TicketStore()
                tasks,writers,errors,early=set(),[],[],[]
                async def on_early(value): early.append(value)
                async def handler(reader,writer):
                    writers.append(writer)
                    try:
                        channel=await server_handshake(reader,writer,credentials,'example.test',
                            ticket_store=store,max_early_data=1024,on_early_data=on_early,timeout=3)
                        await channel.send(b'proof verified')
                        while await channel.recv() is not None: pass
                    except Exception as exc: errors.append(str(exc))
                    finally: writer.close()
                def accept(reader,writer):
                    task=asyncio.create_task(handler(reader,writer));tasks.add(task);task.add_done_callback(tasks.discard)
                listener=await asyncio.start_server(accept,'127.0.0.1',0)
                try:
                    for index in range(2):
                        reader,writer=await asyncio.open_connection('127.0.0.1',listener.sockets[0].getsockname()[1])
                        writers.append(writer)
                        channel=await client_handshake(reader,writer,'example.test',(self.root,),revocation_policy='offline',
                            credential_policy=self.policy,delegated_credentials=True,ticket_cache=cache,
                            early_data=b'early after grant validation' if index else b'',timeout=3)
                        self.assertEqual(await asyncio.wait_for(channel.recv(),3),b'proof verified',errors)
                        self.assertEqual(channel.resumed,bool(index))
                        self.assertEqual(channel.early_data_accepted,bool(index))
                        await channel.close()
                    self.assertEqual(early,[b'early after grant validation',b''])
                    self.assertFalse(errors)
                finally:
                    listener.close()
                    for writer in writers: writer.transport.abort()
                    await asyncio.wait_for(listener.wait_closed(),2)
                    pending=tuple(tasks)
                    for task in pending: task.cancel()
                    await asyncio.gather(*pending,return_exceptions=True)
        async def bounded(): await asyncio.wait_for(exercise(),20)
        asyncio.run(bounded())
