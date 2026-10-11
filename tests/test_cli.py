"""CLI subprocess tests using temporary credentials and no network listeners."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tls20_server import __version__


ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="httpps-cli-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "lab with spaces"

    def run_cli(self, *arguments):
        result = subprocess.run(
            [sys.executable, "-m", "tls20_server", *map(str, arguments)],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="strict", timeout=30, check=False,
        )
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("BEGIN PRIVATE KEY", result.stdout + result.stderr)
        self.assertNotIn("BEGIN CERTIFICATE", result.stdout + result.stderr)
        return result

    def init_lab(self):
        result = self.run_cli("lab-init", "--directory", self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_version_and_help(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), __version__)
        self.assertEqual(result.stderr, "")
        for arguments in (("--help",), ("serve", "--help"),
                          ("check-config", "--help"), ("lab-init", "--help"),
                          ("get", "--help"), ("password-record", "--help")):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_command_is_required_and_unknown_commands_are_rejected(self):
        for arguments in ((), ("unknown-command",)):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)

    def test_lab_init_and_offline_configuration_validation(self):
        result = self.init_lab()
        self.assertIn("Created lab credentials", result.stdout)
        self.assertIn("Trust ca.pem explicitly", result.stdout)
        self.assertEqual({item.name for item in self.directory.iterdir()},
                         {"fullchain.pem", "server.key", "ca.pem", "server.toml"})
        config = (self.directory / "server.toml").read_text("utf-8")
        self.assertIn('server_name = "localhost"', config)
        self.assertIn('listen = "127.0.0.1:343"', config)
        result = self.run_cli("check-config", "--config", self.directory / "server.toml")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no listener opened", result.stdout)

    def test_second_lab_init_refuses_to_overwrite_any_file(self):
        self.init_lab()
        # Compare fingerprints rather than raw key material in assertion output.
        before = {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                  for item in self.directory.iterdir()}
        result = self.run_cli("lab-init", "--directory", self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error:", result.stderr)
        self.assertIn("new directory", result.stderr)
        after = {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                 for item in self.directory.iterdir()}
        self.assertEqual(before, after)

    def test_missing_configuration_fails_safely_before_opening_listener(self):
        absent = Path(self.temp.name) / "missing.toml"
        for command in ("check-config", "serve"):
            with self.subTest(command=command):
                result = self.run_cli(command, "--config", absent)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Cannot read the configuration file", result.stderr)
                self.assertEqual(result.stdout, "")
        self.assertFalse(absent.exists())

    def test_invalid_lab_names_leave_no_directory(self):
        for name in ("bad name", "UPPERCASE.example", "127.00.0.1", "*.example", "name."):
            with self.subTest(name=name):
                result = self.run_cli("lab-init", "--directory", self.directory, "--name", name)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Error:", result.stderr)
                self.assertFalse(self.directory.exists())

    def test_get_requires_explicit_revocation_policy_before_reading_ca(self):
        absent_ca = Path(self.temp.name) / "missing-ca.pem"
        result = self.run_cli("get", "httpps://localhost/", "--ca", absent_ca)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--revocation-policy", result.stderr)
        self.assertIn("required", result.stderr)
        result = self.run_cli("get", "httpps://localhost/", "--ca", absent_ca,
                              "--revocation-policy", "ignore")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)

    def test_invalid_url_with_explicit_policy_fails_without_network(self):
        self.init_lab()
        for policy in ("lab-offline", "offline"):
            result = self.run_cli("get", "https://localhost/", "--ca", self.directory / "ca.pem",
                                  "--revocation-policy", policy)
            self.assertEqual(result.returncode, 1)
            self.assertIn("invalid HTTPPS URL", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_salted_password_record_is_private_and_never_printed_or_overwritten(self):
        self.directory.mkdir()
        username=self.directory/"username.txt";password=self.directory/"password.txt";output=self.directory/"accounts.toml"
        username.write_text("alice",encoding="utf-8");password.write_text("private fixture password",encoding="utf-8")
        username.chmod(0o600);password.chmod(0o600)
        arguments=("password-record","--username-file",username,"--password-file",password,"--output",output)
        result=self.run_cli(*arguments)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn("private fixture password",result.stdout+result.stderr)
        self.assertNotIn("base_hex",result.stdout+result.stderr)
        import tomllib
        record=tomllib.loads(output.read_text("utf-8"))["accounts"][0]
        self.assertEqual(len(bytes.fromhex(record["base_hex"])),32)
        self.assertEqual(len(bytes.fromhex(record["salt_hex"])),32)
        before=output.read_bytes()
        result=self.run_cli(*arguments)
        self.assertEqual(result.returncode,1)
        self.assertEqual(output.read_bytes(),before)

    def test_profile_validation_is_available_to_cli_without_opening_listener(self):
        self.init_lab()
        profile=self.directory/"profile.toml"
        profile.write_text('role="server"\nservice="localhost"\n[credential]\n'
                           'chain="fullchain.pem"\nprivate_key="server.key"',encoding="utf-8")
        configuration=self.directory/"server.toml"
        configuration.write_text(configuration.read_text("utf-8")+'\nprofile_file="profile.toml"\n',encoding="utf-8")
        result=self.run_cli("check-config","--config",configuration)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("no listener opened",result.stdout)
        profile.write_text('role="client"\nservice="localhost"\n[trust]\nroots="ca.pem"',encoding="utf-8")
        result=self.run_cli("get","https://localhost/","--profile",profile)
        self.assertEqual(result.returncode,1)
        self.assertIn("invalid HTTPPS URL",result.stderr)


if __name__ == "__main__":
    unittest.main()
