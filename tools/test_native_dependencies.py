"""Run native-provider tests with explicit paths from a local build manifest.

No provider discovery or global environment changes. A missing native fixture
is a failure, not a green suite silently skipping the optional profiles.
"""
import argparse
import faulthandler
import json
import os
from pathlib import Path
import sys
import unittest
import warnings


def native_coverage_skip(test_id, reason):
    """Distinguish a missing optional profile from unrelated OS-only checks."""
    return test_id.startswith(('tests.test_its_credentials.', 'tests.test_its_handshake.')) or any(
        word in (test_id+' '+reason).lower()
        for word in ('pake', 'gost', 'sm2', 'sm_handshake', 'provider', 'oracle'))


def main():
    # A native crash must preserve its Python/thread call sites in CI logs;
    # it is never retried or converted into an optional-profile skip.
    faulthandler.enable()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    environment = manifest['environment']
    required = ('TLS20_TEST_OPENSSL', 'TLS20_TEST_OPENSSL_CLI', 'TLS20_TEST_PAKE',
                'TLS20_TEST_PAKE_ORACLE', 'TLS20_TEST_GOST_MODULE', 'TLS20_TEST_ITS_LIBRARY')
    for key in required:
        value = environment[key]
        if not isinstance(value, str) or not Path(value).is_absolute() or not Path(value).is_file():
            raise SystemExit(f'Missing explicit build fixture: {key}')
        os.environ[key] = value
    fixtures = Path(environment['TLS20_ITS_FIXTURE_DIR'])
    if not fixtures.is_absolute() or not fixtures.is_dir():
        raise SystemExit('Missing explicit ITS fixture directory')
    os.environ['TLS20_ITS_FIXTURE_DIR'] = str(fixtures)
    # Shared-library search paths must be in effect before importing test code.
    # Linux/macOS callers re-exec once, since loaders read these at process start.
    loader = 'DYLD_LIBRARY_PATH' if sys.platform == 'darwin' else 'LD_LIBRARY_PATH'
    if os.name != 'nt' and environment.get(loader) != os.environ.get(loader):
        import subprocess
        child_env = os.environ.copy()
        child_env[loader] = environment[loader]
        raise SystemExit(subprocess.call([sys.executable, *sys.argv], env=child_env))
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    warnings.simplefilter('error', ResourceWarning)
    tests = unittest.defaultTestLoader.discover(str(root/'tests'), top_level_dir=str(root))
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    missing = [(test.id(), why) for test, why in result.skipped
               if native_coverage_skip(test.id(), why)]
    if missing:
        for name, why in missing:
            print(f'ERROR: native coverage skipped: {name}: {why}', file=sys.stderr)
    raise SystemExit(0 if result.wasSuccessful() and not missing else 1)


if __name__ == '__main__':
    main()
