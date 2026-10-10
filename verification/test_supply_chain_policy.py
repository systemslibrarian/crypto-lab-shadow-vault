"""Exercise the real pinned checker against isolated licensed/unlicensed crates."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SupplyChainPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('CARGO_DENY_BIN') or shutil.which('cargo-deny')
        if not cls.binary:
            # Cargo also discovers plugins in CARGO_HOME/bin when it is not on PATH.
            candidate = pathlib.Path(os.environ.get('CARGO_HOME',
                                                     str(pathlib.Path.home() / '.cargo')))
            candidate = candidate / 'bin/cargo-deny'
            if candidate.is_file():
                cls.binary = str(candidate)
        if not cls.binary:
            raise RuntimeError('cargo-deny 0.20.2 is required; controls may not be skipped')
        version = subprocess.check_output([cls.binary, '--version'], text=True).strip()
        if version != 'cargo-deny 0.20.2':
            raise RuntimeError('use the workflow-pinned cargo-deny 0.20.2, got ' + version)

    def check_license(self, license, *, malformed=False, missing_database=False):
        with tempfile.TemporaryDirectory(prefix='shadow-policy-control-') as td:
            root = pathlib.Path(td)
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_text('pub fn fixture() {}\n')
            manifest = '[package]\nname="policy-control"\nversion="0.1.0"\nedition="2021"\n'
            if license is not None:
                manifest += 'license="' + license + '"\n'
            (root / 'Cargo.toml').write_text(manifest)
            policy = (ROOT / 'crate/deny.toml').read_text()
            if malformed:
                policy = policy.replace('unmaintained = "all"', 'unmaintained = "warn"')
            if missing_database:
                policy = policy.replace('db-path = "~/.cargo/advisory-db"',
                                        'db-path = "' + str(root / 'missing-advisory-db') + '"')
            (root / 'deny.toml').write_text(policy)
            subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root,
                           check=True, capture_output=True, text=True, timeout=60)
            lock = (root / 'Cargo.lock').read_bytes()
            result = subprocess.run([self.binary, '--locked', '--offline', 'check',
                                     'advisories' if missing_database else 'licenses'], cwd=root,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual((root / 'Cargo.lock').read_bytes(), lock)
            self.assertFalse((root / 'target').exists(), 'checker must not build/install dependencies')
            return result

    def test_allowed_mit_crate(self):
        result = self.check_license('MIT')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('error[', result.stderr)

    def test_unlicensed_crate_is_rejected(self):
        result = self.check_license(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unlicensed', result.stderr)

    def test_copyleft_is_not_added_to_allowlist(self):
        result = self.check_license('GPL-3.0-only')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('error[rejected]', result.stderr)

    def test_historical_invalid_scope_fails(self):
        result = self.check_license('MIT', malformed=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpected-value', result.stderr)

    def test_missing_advisory_database_is_not_success(self):
        result = self.check_license('MIT', missing_database=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing-advisory-db', result.stderr)


if __name__ == '__main__':
    unittest.main()
