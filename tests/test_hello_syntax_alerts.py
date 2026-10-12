"""Hello syntax errors are decode_error; valid but inconsistent values are not."""

import unittest

from tls20_server import messages as m
from tls20_server.errors import ProtocolError


def hello_extensions(frame, changes):
    reader = m._Reader(frame[4:])
    reader.take(34)
    reader.vector(1)
    if frame[0] == 1:
        reader.vector(2)
        reader.vector(1)
    else:
        reader.take(3)
    prefix = frame[4:4 + reader.position]
    values = m.extensions(reader.vector(2))
    reader.end()
    for kind, value in changes.items():
        if value is None:
            values.pop(kind, None)
        else:
            values[kind] = value
    return m.frame(frame[0], prefix + m._vec(b"".join(m.extension(k, v) for k, v in values.items()), 2))


class HelloSyntaxAlertTests(unittest.TestCase):
    def assert_alert(self, frame, alert):
        parser = m.parse_client_hello if frame[0] == 1 else m.parse_server_hello
        with self.assertRaises(ProtocolError) as caught:
            parser(frame[4:])
        self.assertEqual(caught.exception.alert, alert)

    def test_empty_extension_bodies_have_syntax_not_semantic_errors(self):
        for kind in (33, 42):
            hello = m.client_hello(b"a" * 32, b"b" * 32, "localhost", bytes(32),
                identity=b"identity", binder=bytes(32), combined_psk=kind == 33, early_data=kind == 42)
            m.parse_client_hello(hello[4:])
            for body in (b"\0", b"\0\0", b"garbage"):
                with self.subTest(context="CH", kind=kind, body=body):
                    self.assert_alert(hello_extensions(hello, {kind: body}), 50)
            # An empty payload still needs the extension's semantic dependencies.
            self.assert_alert(hello_extensions(hello, {41: None}), 47)
        server = m.server_hello(b"b" * 32, bytes(32), resumed=True, combined_psk=True)
        m.parse_server_hello(server[4:])
        for body in (b"\0", b"\0\0", b"garbage"):
            with self.subTest(context="SH", kind=33, body=body):
                self.assert_alert(hello_extensions(server, {33: body}), 50)
        self.assert_alert(hello_extensions(server, {41: None}), 47)

    def test_server_hello_vectors_and_value_controls(self):
        server = m.server_hello(b"b" * 32, bytes(32), resumed=True)
        m.parse_server_hello(server[4:])
        for kind in (43, 41):
            for body in (b"", b"\0", b"\0\0\0"):
                with self.subTest(kind=kind, body=body):
                    self.assert_alert(hello_extensions(server, {kind: body}), 50)
        for body in (b"", b"\0", b"\0\x1d", b"\0\x1d\0",
                     b"\0\x1d\0\x20" + b"b" * 31, b"\0\x1d\0\x20" + b"b" * 33):
            with self.subTest(kind=51, body=body):
                self.assert_alert(hello_extensions(server, {51: body}), 50)
        # Correct vector framing but the wrong fixed-size X25519 share is 47.
        self.assert_alert(hello_extensions(server, {51: b"\0\x1d\0\x1f" + b"b" * 31}), 47)
        self.assert_alert(hello_extensions(server, {43: b"\x03\x04"}), 47)
        # legacy_session_id_echo is an opaque<0..32>, not an arbitrary byte vector.
        self.assert_alert(m.frame(2, server[4:38] + b"\x21" + b"s" * 33 + server[39:]), 50)

    def test_retry_vectors_and_useless_retry(self):
        retry = m.server_hello(b"", bytes(32), retry=True, cookie=b"cookie")
        m.parse_server_hello(retry[4:])
        for body in (b"", b"\0", b"\0\x1d\0"):
            with self.subTest(kind=51, body=body):
                self.assert_alert(hello_extensions(retry, {51: body}), 50)
        for body in (b"", b"\0", b"\0\0", b"\0\1", b"\0\1cc"):
            with self.subTest(kind=44, body=body):
                self.assert_alert(hello_extensions(retry, {44: body}), 50)
        # A version-only HRR cannot change the next ClientHello: RFC9846 4.2.4.
        self.assert_alert(hello_extensions(retry, {44: None, 51: None}), 47)
        # Cookie-only HRR is useful without selecting a new key-share group.
        m.parse_server_hello(hello_extensions(retry, {51: None})[4:])
