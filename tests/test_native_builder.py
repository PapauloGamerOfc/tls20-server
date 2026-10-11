"""Pinned sources and binary locations must not depend on ambient CMake defaults."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from tools.build_native_dependencies import find_one, verify_pinned_source


class NativeBuilderTests(unittest.TestCase):
    def test_pristine_revision_includes_untracked_ignored_and_submodules(self):
        capture = Mock(side_effect=["revision", ""])
        verify_pinned_source(Path("source"), "revision", capture)
        status_arguments = capture.call_args.args
        for flag in ("--untracked-files=all", "--ignored=matching", "--ignore-submodules=none"):
            self.assertIn(flag, status_arguments)

    def test_extra_or_modified_source_is_never_silently_cleaned(self):
        for status in ("?? Configurations/extra.conf", "!! Configurations/ignored.conf",
                       " M Configure", " m submodule"):
            with self.subTest(status=status):
                capture = Mock(side_effect=["revision", status])
                with self.assertRaisesRegex(SystemExit, "modified or extra"):
                    verify_pinned_source(Path("source"), "revision", capture)
                self.assertEqual(capture.call_count, 2)
        with self.assertRaisesRegex(SystemExit, "another revision"):
            verify_pinned_source(Path("source"), "revision", Mock(return_value="other"))

    def test_single_and_multi_configuration_outputs(self):
        for directory in (".", "Release"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                location = root / directory
                location.mkdir(exist_ok=True)
                library = location / "tls20-pake.dll"
                library.touch()
                self.assertEqual(find_one(root, "tls20-pake.dll"), library.resolve())

    def test_missing_and_ambiguous_binaries_are_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(SystemExit):
                find_one(root, "tls20-pake.dll")
            for name in ("Debug", "Release"):
                (root / name).mkdir()
                (root / name / "tls20-pake.dll").touch()
            with self.assertRaises(SystemExit):
                find_one(root, "tls20-pake.dll")
