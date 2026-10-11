"""Provider coverage cannot silently skip; unrelated OS checks remain distinct."""
import unittest

from tools.test_native_dependencies import native_coverage_skip


class NativeCoverageRunnerTests(unittest.TestCase):
    def test_required_native_profiles_cannot_skip(self):
        for name in ('test_its_credentials', 'test_its_handshake', 'test_pake',
                     'test_gost_credentials', 'test_sm_handshake', 'test_openssl_provider'):
            self.assertTrue(native_coverage_skip(f'tests.{name}.Tests.test_case', 'Not available'))
        self.assertTrue(native_coverage_skip('tests.test_crypto.Tests.test_case', 'Native oracle required'))

    def test_unrelated_windows_checks_are_not_its_profiles(self):
        self.assertFalse(native_coverage_skip(
            'tests.test_config.ConfigurationTests.test_symlinked_configuration_resolves_paths_at_its_real_directory',
            'Symlink creation can require Windows privileges'))
        self.assertFalse(native_coverage_skip(
            'tests.test_pki.CredentialFileTests.test_reject_publicly_readable_private_key',
            'POSIX mode check; Windows uses inherited ACLs'))
