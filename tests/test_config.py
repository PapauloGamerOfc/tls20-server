from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest

from tls20_server.config import Config, ConfigError, Endpoint, MAX_CONFIG_BYTES, load_config, parse_endpoint


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "server.toml"

    def load(self, content):
        self.path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return load_config(self.path)

    def test_defaults_are_local_experimental_and_paths_are_relative_to_config(self):
        config = self.load("")
        self.assertEqual(config.listen, Endpoint("127.0.0.1", 343))
        self.assertEqual(config.upstream, Endpoint("127.0.0.1", 8080))
        self.assertEqual(config.certificate_chain, (self.path.parent / "fullchain.pem").resolve())
        self.assertEqual(config.private_key, (self.path.parent / "server.key").resolve())
        self.assertEqual(config.max_connections, 128)
        self.assertEqual(config.handshake_timeout_seconds, 10)
        self.assertEqual(config.max_bytes_per_direction, 16777216)

    def test_valid_ipv4_ipv6_and_port_boundaries(self):
        self.assertEqual(parse_endpoint("0.0.0.0:343"), Endpoint("0.0.0.0", 343))
        self.assertEqual(parse_endpoint("[::]:65535"), Endpoint("::", 65535))
        self.assertEqual(parse_endpoint("[::1]:1", loopback=True), Endpoint("::1", 1))
        config = self.load('listen = "[::]:1021"\nupstream = "[::1]:8080"')
        self.assertEqual(str(config.listen), "[::]:1021")

    def test_remote_backend_dns_and_ambiguous_endpoints_are_rejected(self):
        for value in (
            "localhost:8080", "https://127.0.0.1:8080", "127.0.0.1:0",
            "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:+443",
            "127.0.0.1: 443", " 127.0.0.1:443", "::1:8080", "[::1]8080",
            "[127.0.0.1]:443", "[::1%eth0]:443", None, 123, "x" * 129,
        ):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_endpoint(value)
        for value in ("192.0.2.1:80", "0.0.0.0:80", "[::]:80", "[2001:db8::1]:80"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_endpoint(value, loopback=True)
        with self.assertRaises(ConfigError):
            Config(upstream=Endpoint("192.0.2.1", 80))

    def test_strict_fields_and_value_types(self):
        for content in (
            "typo = 1", "[section]\nlisten='127.0.0.1:1021'", "max_connections = true",
            "max_connections = 0", "max_connections = 1.5", "max_bytes_per_direction = -1",
            "handshake_timeout_seconds = 0",
            "handshake_timeout_seconds = true", "idle_timeout_seconds = inf",
            "idle_timeout_seconds = nan", "connect_timeout_seconds = -inf",
            'connect_timeout_seconds = "10"', "max_connection_seconds = 0",
            'private_key = ""', "certificate_chain = []", "listen = false",
        ):
            with self.subTest(content=content), self.assertRaises(ConfigError):
                self.load(content)
        config = self.load("max_connections=1\nhandshake_timeout_seconds=30\nidle_timeout_seconds=0.5")
        self.assertEqual(config.idle_timeout_seconds, 0.5)
        with self.assertRaises(ConfigError):
            replace(config, idle_timeout_seconds=10 ** 1000)

    def test_session_and_early_http_policy(self):
        config = self.load('upstream_early_data_aware=true\nearly_data_paths=["/static"]\nhandshake_timeout_seconds=60')
        self.assertTrue(config.session_tickets)
        self.assertEqual(config.early_data_paths, ("/static",))
        self.assertEqual(config.handshake_timeout_seconds, 60)
        for value in (
            'early_data_paths=["/"]', 'session_tickets=1', 'ticket_capacity=0',
            'ticket_lifetime_seconds=604801', 'ticket_lifetime_seconds=true',
            'max_early_data_bytes=-1', 'max_early_data_bytes=4294967296',
            'max_early_data_bytes=true', 'early_data_paths="/"',
            'upstream_early_data_aware=1',
            'upstream_early_data_aware=true\nearly_data_paths=["/", "/"]',
            'upstream_early_data_aware=true\nearly_data_paths=["/?action=x"]',
            'upstream_early_data_aware=true\nearly_data_paths=["/%2f"]',
            'upstream_early_data_aware=true\nearly_data_paths=[42]',
            'session_tickets=false\nupstream_early_data_aware=true\nearly_data_paths=["/"]',
        ):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.load(value)

    def test_dns_name_profile(self):
        for value in (
            "", "Example.com", "example.com.", "*.example.com", "127.0.0.1",
            "a..b", "-a.com", "a-.com", "a_b.com", "é.com", "a" * 64 + ".com",
            12, "a." * 127,
        ):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                Config(server_name=value)
        self.assertEqual(Config(server_name="xn--test-9ta.invalid").server_name, "xn--test-9ta.invalid")

    def test_invalid_toml_encoding_missing_file_and_size(self):
        for content in (b"\xff", "listen =", "listen='127.0.0.1:1'\nlisten='127.0.0.1:2'"):
            with self.subTest(content=content), self.assertRaises(ConfigError):
                self.load(content)
        with self.assertRaises(ConfigError):
            self.load(b"#" * (MAX_CONFIG_BYTES + 1))
        self.assertEqual(self.load(b"#" * MAX_CONFIG_BYTES).server_name, "localhost")
        with self.assertRaises(ConfigError):
            load_config(self.path.parent / "missing.toml")

    def test_paths_and_api_port_zero(self):
        config = self.load('private_key="secrets/key.pem"\ncertificate_chain="certs/fullchain.pem"')
        self.assertEqual(config.private_key, (self.path.parent / "secrets" / "key.pem").resolve())
        self.assertEqual(config.certificate_chain, (self.path.parent / "certs" / "fullchain.pem").resolve())
        self.assertEqual(Config(listen=Endpoint("127.0.0.1", 0)).listen.port, 0)
        with self.assertRaises(ConfigError):
            self.load('listen="127.0.0.1:0"')

    @unittest.skipUnless(os.name == "posix", "Symlink creation can require Windows privileges")
    def test_symlinked_configuration_resolves_paths_at_its_real_directory(self):
        directory = self.path.parent / "actual"
        directory.mkdir()
        real_config = directory / "server.toml"
        real_config.write_text('private_key="keys/server.key"', encoding="utf-8")
        directory_alias = self.path.parent / "directory-alias"
        directory_alias.symlink_to(directory, target_is_directory=True)
        file_alias = self.path.parent / "file-alias.toml"
        file_alias.symlink_to(real_config)
        for path in (directory_alias / "server.toml", file_alias):
            with self.subTest(path=path):
                config = load_config(path)
                self.assertEqual(config.private_key, (directory / "keys" / "server.key").resolve())
                self.assertEqual(config.certificate_chain, (directory / "fullchain.pem").resolve())


if __name__ == "__main__":
    unittest.main()
