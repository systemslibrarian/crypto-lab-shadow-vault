"""Offline controls for the real reproduction gate, not fabricated compiler runs."""
import hashlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reproduce', ROOT / 'scripts/reproduce-wasm.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ProvenanceControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def test_real_failed_command_retains_status_and_output(self):
        report, saves = {'commands': []}, []
        with self.assertRaisesRegex(RuntimeError, 'Command failed'):
            gate.run_command([sys.executable, '-c', 'print("diagnostic"); raise SystemExit(7)'],
                             self.root, {}, report, lambda: saves.append(True))
        self.assertEqual(report['commands'][0]['exit'], 7)
        self.assertIn('diagnostic', report['commands'][0]['stdout'])
        self.assertEqual(saves, [True])

    def test_real_timeout_is_not_a_success_or_missing_command(self):
        report = {'commands': []}
        with self.assertRaisesRegex(RuntimeError, 'timed out'):
            gate.run_command([sys.executable, '-c', 'import time; print("partial", flush=True); time.sleep(2)'],
                             self.root, {}, report, lambda: None, timeout=0.2)
        row = report['commands'][0]
        self.assertIsNone(row['exit'])
        self.assertTrue(row['timedOut'])
        self.assertIn('partial', row['stdout'])

    def test_failure_overwrites_old_success_receipt_and_preserves_outputs(self):
        output = self.root / 'pkg'; output.mkdir()
        for name in gate.ARTIFACTS:
            (output / name).write_bytes(b'previous artifact')
        receipt = output / 'wasm-provenance.json'
        receipt.write_text('{"state":"reproduced-current-source"}')
        with patch.object(gate, 'ROOT', self.root), patch.object(sys, 'argv', ['reproduce-wasm.py']), \
                patch.object(gate.platform, 'system', return_value='unsupported'), \
                self.assertRaisesRegex(RuntimeError, 'Unsupported build host'):
            gate.main()
        import json
        self.assertEqual(json.loads(receipt.read_text())['state'], 'failed')
        for name in gate.ARTIFACTS:
            self.assertEqual((output / name).read_bytes(), b'previous artifact')

    def pair(self):
        first, second = self.root / 'first', self.root / 'second'
        first.mkdir(); second.mkdir()
        for destination in (first, second):
            (destination / gate.ARTIFACTS[0]).write_bytes(b'export function fixture() {}\n')
            (destination / gate.ARTIFACTS[1]).write_bytes(b'\0asm\x01\0\0\0')
        return first, second

    def test_readable_equal_pair(self):
        first, second = self.pair()
        rows = gate.compare_artifacts(first, second)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['repeatMatches'] for row in rows))

    def test_one_changed_byte_cannot_pass(self):
        first, second = self.pair()
        (second / gate.ARTIFACTS[1]).write_bytes(b'\0asm\x01\0\0\0\x00')
        with self.assertRaisesRegex(RuntimeError, 'clean builds differ'):
            gate.compare_artifacts(first, second)

    def test_missing_js_cannot_pass(self):
        first, second = self.pair()
        (second / gate.ARTIFACTS[0]).unlink()
        with self.assertRaises(FileNotFoundError):
            gate.compare_artifacts(first, second)

    def test_equal_empty_outputs_cannot_pass(self):
        first, second = self.pair()
        for destination in (first, second):
            (destination / gate.ARTIFACTS[0]).write_bytes(b'')
        with self.assertRaisesRegex(RuntimeError, 'Empty'):
            gate.compare_artifacts(first, second)

    def test_equal_malformed_wasm_cannot_pass(self):
        first, second = self.pair()
        for destination in (first, second):
            (destination / gate.ARTIFACTS[1]).write_bytes(b'not a WASM binary')
        with self.assertRaisesRegex(RuntimeError, 'Malformed'):
            gate.compare_artifacts(first, second)

    def archive(self, name='tool/bin', link=False):
        archive = self.root / 'archive.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            info = tarfile.TarInfo(name)
            if link:
                info.type = tarfile.SYMTYPE; info.linkname = '/outside'
                bundle.addfile(info)
            else:
                info.size = 5; bundle.addfile(info, io.BytesIO(b'tool\n'))
        return archive

    def test_verified_archive_extracts(self):
        archive = self.archive()
        gate.unpack_verified(archive, hashlib.sha256(archive.read_bytes()).hexdigest(), self.root / 'out')
        self.assertEqual((self.root / 'out/tool/bin').read_bytes(), b'tool\n')

    def test_archive_hash_tamper_rejected_before_extract(self):
        archive = self.archive()
        with self.assertRaisesRegex(RuntimeError, 'hash mismatch'):
            gate.unpack_verified(archive, '0' * 64, self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_path_escape_rejected_even_with_matching_hash(self):
        archive = self.archive('../escaped')
        with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            gate.unpack_verified(archive, hashlib.sha256(archive.read_bytes()).hexdigest(), self.root / 'out')
        self.assertFalse((self.root / 'escaped').exists())

    def test_symlink_rejected_even_with_matching_hash(self):
        archive = self.archive(link=True)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            gate.unpack_verified(archive, hashlib.sha256(archive.read_bytes()).hexdigest(), self.root / 'out')

    def identity(self):
        return ('rustc 1.87.0 (17067e9ac 2025-05-09)\n'
                'binary: rustc\ncommit-hash: ' + gate.RUST_COMMIT + '\n'
                'host: aarch64-apple-darwin\nrelease: 1.87.0\nLLVM version: 20.1.1\n')

    def test_actual_selected_compiler_identity(self):
        gate.validate_compiler(self.identity())

    def test_other_compiler_rejected(self):
        with self.assertRaises(RuntimeError):
            gate.validate_compiler(self.identity().replace('1.87.0', '1.99.0'))

    def test_incomplete_or_ambiguous_compiler_rejected(self):
        for identity in (self.identity().replace('LLVM version: 20.1.1\n', ''),
                         self.identity() + 'release: 1.99.0\n'):
            with self.subTest(identity=identity), self.assertRaises(RuntimeError):
                gate.validate_compiler(identity)

    def test_exact_locked_dependency_archive(self):
        data = b'locked public crate fixture'
        package = dict(name='fixture', version='1.0.0', checksum=hashlib.sha256(data).hexdigest())
        cache = self.root / 'registry/cache/crates-io'; cache.mkdir(parents=True)
        path = cache / 'fixture-1.0.0.crate'; path.write_bytes(data)
        gate.verify_registry_archives([package], self.root)
        path.write_bytes(data + b'changed')
        with self.assertRaisesRegex(RuntimeError, 'changed locked dependency'):
            gate.verify_registry_archives([package], self.root)

    def test_missing_locked_dependency_archive_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Missing'):
            gate.verify_registry_archives([dict(name='fixture', version='1.0.0', checksum='0'*64)], self.root)

    def test_unsupported_provider_rejected_before_fetch(self):
        lock = self.root / 'Cargo.lock'
        lock.write_text('[[package]]\nname="fixture"\nversion="1.0.0"\nsource="git+https://example.invalid/private"\n')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            gate.registry_packages(lock)

    def test_incomplete_cargo_lock_rejected(self):
        lock = self.root / 'Cargo.lock'; lock.write_text('version=4\n')
        with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
            gate.registry_packages(lock)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.PIPE)

    def source_repo(self):
        self.git('init', '-q', '--initial-branch=main')
        for name, text in [('crate/Cargo.toml', '[package]\nname="fixture"\n'),
                           ('crate/Cargo.lock', 'version = 4\n'),
                           ('crate/src/lib.rs', 'pub fn fixture() {}\n'),
                           ('rust-toolchain.toml', '[toolchain]\nchannel="1.87.0"\n')]:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        self.git('add', 'crate', 'rust-toolchain.toml')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'immutable fixture')

    def test_immutable_source_capture_and_exact_blob_hashes(self):
        self.source_repo()
        sha, rows = gate.capture_source(self.root, self.root / 'copy')
        self.assertEqual(sha, self.git('rev-parse', 'HEAD').decode().strip())
        self.assertEqual(len(rows), 4)
        for row in rows:
            original = self.git('cat-file', 'blob', row['gitBlob'])
            self.assertEqual((self.root / 'copy' / row['path']).read_bytes(), original)
            self.assertEqual(row['sha256'], hashlib.sha256(original).hexdigest())

    def test_dirty_or_new_source_is_not_silently_excluded(self):
        self.source_repo()
        path = self.root / 'crate/new.rs'; path.write_text('uncommitted input')
        with self.assertRaisesRegex(RuntimeError, 'Uncommitted'):
            gate.capture_source(self.root, self.root / 'copy')
        self.assertEqual(path.read_text(), 'uncommitted input')

    def test_missing_required_tracked_source_rejected(self):
        self.source_repo()
        self.git('rm', '-q', 'crate/Cargo.lock')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'missing lock control')
        with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
            gate.capture_source(self.root, self.root / 'copy')


if __name__ == '__main__':
    unittest.main()
