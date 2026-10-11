"""Only public fixture bytes are written; temporary sinks are disposed by tests."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tls20_server import diagnostics as d
from tls20_server import _build_features


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "test-traffic.keys"

    def sink(self, **options):
        sink = d.DiagnosticSink(self.path, authorize_test_data=True, authorize_traffic=True, **options)
        self.addCleanup(sink.close)
        return sink

    def test_production_gate_and_environment_alone_never_authorize(self):
        self.assertFalse(_build_features.TEST_DIAGNOSTICS)
        with patch.dict(os.environ, SSLKEYLOGFILE=str(self.path)):
            with self.assertRaises(RuntimeError):
                self.sink()
        self.assertFalse(self.path.exists())

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_authorization_is_per_category(self):
        sink = self.sink()
        sink.emit("TLS20_CLIENT_TRAFFIC_SECRET_0", b"r" * 32, b"s" * 48)
        sink.emit("TLS20_EXPORTER_SECRET", b"r" * 32, b"s" * 48)
        sink.close()
        data = self.path.read_text(encoding="ascii")
        self.assertEqual(len(data.splitlines()), 1)
        self.assertTrue(data.startswith("TLS20_CLIENT_TRAFFIC_SECRET_0 "))
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_exporter_logging_requires_separate_opt_in(self):
        sink = self.sink(authorize_exporters=True)
        for label in d.TRAFFIC_LABELS | d.EXPORTER_LABELS:
            d.emit(sink, label, b"r" * 32, b"s" * 32)
        sink.close()
        self.assertEqual(len(self.path.read_text().splitlines()), 7)

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_no_overwrite_or_symlink_following(self):
        self.path.write_bytes(b"preserve fixture")
        with self.assertRaises(OSError):
            self.sink()
        self.assertEqual(self.path.read_bytes(), b"preserve fixture")
        link = self.path.with_suffix(".link")
        try:
            link.symlink_to(self.path)
        except OSError:
            return  # Windows may deny symlink creation without Developer Mode.
        with self.assertRaises(OSError):
            d.DiagnosticSink(link, authorize_test_data=True, authorize_traffic=True)
        self.assertEqual(self.path.read_bytes(), b"preserve fixture")

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_concurrent_entries_are_whole_lines(self):
        sink = self.sink()
        with ThreadPoolExecutor(max_workers=8) as threads:
            list(threads.map(lambda i: sink.emit("TLS20_CLIENT_TRAFFIC_SECRET_0", i.to_bytes(32, "big"), b"s" * 32), range(100)))
        sink.close()
        entries = self.path.read_text().splitlines()
        self.assertEqual(len(entries), 100)
        self.assertEqual(len(set(entries)), 100)
        self.assertTrue(all(len(line.split(" ")) == 3 for line in entries))

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_sink_failure_is_redacted_and_permanent(self):
        sink = self.sink()
        with patch.object(os, "write", side_effect=OSError("not included in diagnostic error")):
            sink.emit("TLS20_CLIENT_TRAFFIC_SECRET_0", b"r" * 32, b"s" * 32)
        self.assertEqual(sink.error, "diagnostic sink disabled after a local failure")
        sink.emit("TLS20_CLIENT_TRAFFIC_SECRET_0", b"r" * 32, b"s" * 32)
        self.assertEqual(self.path.read_bytes(), b"")

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_cannot_log_unknown_roots_or_update_generations(self):
        sink = self.sink()
        sink.emit("TLS20_HANDSHAKE_SECRET", b"r" * 32, b"s" * 32)
        self.assertIsNotNone(sink.error)
        self.assertEqual(self.path.read_bytes(), b"")
        for label in ("CLIENT_RANDOM", "CLIENT_TRAFFIC_SECRET_0", "TLS20_CLIENT_TRAFFIC_SECRET_1"):
            with self.assertRaises(ValueError):
                d.format_entry(label, b"r" * 32, b"s" * 32)

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    def test_requires_explicit_test_data_authorization(self):
        with self.assertRaises(ValueError):
            d.DiagnosticSink(self.path, authorize_traffic=True)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
