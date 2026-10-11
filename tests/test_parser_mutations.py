"""Deterministic malformed-input regression corpus (not cryptographic RNG).

This is bounded parser testing, not a claim of exhaustive protocol fuzzing.
Only ProtocolError is an acceptable wire-input failure: IndexError, native
codec errors and other implementation exceptions must not leak through.
"""
import random
import unittest

from tls20_server import crypto as c, messages as m
from tls20_server.application_auth import parse_request
from tls20_server.credential_cache import (compress_certificate, decompress_certificate,
    cached_certificate_body, resolve_cached_certificate, cached_request_body,
    resolve_cached_request)
from tls20_server.errors import ProtocolError
from tls20_server.optional_controls import TicketRequest, heartbeat_mode


class ParserMutationTests(unittest.TestCase):
    def test_bounded_wire_mutation_corpus(self):
        # Fixed public bytes are test inputs only; no real connection is made.
        _, public = c.traffic_key(29)
        _, auth_public = c.traffic_key(29)
        material = (b"test credential bytes, not a trusted certificate",)
        request_extensions = m.extension(50, b"\x00\x02\x08\x07")
        request = m.certificate_request(b"context", public)[4:]
        certificate = m.certificate(list(material))[4:]
        cases = [
            (m.parse_client_hello, m.client_hello(auth_public, public, "localhost", bytes(32))[4:]),
            (m.parse_server_hello, m.server_hello(public, bytes(32))[4:]),
            (m.parse_encrypted_extensions, m.encrypted_extensions()[4:]),
            (m.parse_certificate_request, request),
            (m.parse_certificate, certificate),
            (m.parse_new_session_ticket, m.new_session_ticket(b"identity", b"nonce", 60, 1, 0)[4:]),
            (m.extensions, request_extensions),
            (parse_request, m.frame(13, request)),
            (TicketRequest.parse, b"\x03\x02"),
            (heartbeat_mode, b"\x01"),
            (lambda value: resolve_cached_certificate(value, ((0, material),)),
             cached_certificate_body(material, (b"",))),
            (lambda value: resolve_cached_request(value, (request_extensions,)),
             cached_request_body(b"context", request_extensions, public)),
        ]
        for algorithm in (1, 2, 3):
            cases.append((lambda value: decompress_certificate(value, (1, 2, 3), max_size=4096),
                          compress_certificate(certificate, algorithm)))
        generator = random.Random(84928879)
        exercised = 0
        for parse, seed in cases:
            # Every truncation of these small authentic wire envelopes.
            corpus = [seed[:end] for end in range(len(seed) + 1)]
            corpus += [seed + b"\x00", seed + b"\xff" * 16]
            for _ in range(160):
                changed = bytearray(seed)
                for _ in range(1 + generator.randrange(4)):
                    if changed:
                        changed[generator.randrange(len(changed))] ^= 1 << generator.randrange(8)
                corpus.append(bytes(changed))
                corpus.append(generator.randbytes(generator.randrange(96)))
            for value in corpus:
                with self.subTest(parser=parse.__name__, length=len(value), sample=exercised):
                    try:
                        parse(value)
                    except ProtocolError:
                        pass
                exercised += 1
        self.assertGreater(exercised, 5000)
