#!/usr/bin/env python3
"""Deterministic release inputs and archives use tiny filesystem fixtures."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

import release_artifacts as artifacts


EPOCH = 1_700_000_000
TAG = 'v0.0.0-rc.1402'
COMMIT = 'a' * 40
DOCS = ['LICENSE', 'README.md', 'CHANGELOG.md']


class ReleaseArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def source(self, name):
        root = self.root / name
        for material in artifacts.BUILD_MATERIALS:
            p = root / material
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(('fixture ' + material).encode())
        for name in ['002_second.sql', '001_first.sql']:
            p = root / 'migrations' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('CREATE TABLE fixture();\n')
        return root

    def manifest(self, root, **changes):
        options = dict(tag=TAG, commit=COMMIT, epoch=EPOCH, go_version='go1.27.2')
        options.update(changes)
        return artifacts.build_manifest(root, **options)

    def test_manifest_is_identical_across_directories_and_file_metadata(self):
        first = self.source('PRIVATE_FIRST')
        second = self.source('PRIVATE_SECOND')
        for p in second.rglob('*'):
            if p.is_file():
                os.utime(p, (EPOCH + 100, EPOCH + 100))
                p.chmod(0o600)
        a, b = self.manifest(first), self.manifest(second)
        self.assertEqual(a, b)
        self.assertEqual(a['schema_version'], 'evydence-release-build-manifest.v1')
        self.assertEqual(a['build_time'], '2023-11-14T22:13:20Z')
        self.assertEqual(a['source_date_epoch'], EPOCH)
        self.assertEqual(a['commit'], COMMIT)
        self.assertEqual(a['build_recipe_version'], artifacts.RECIPE_VERSION)
        self.assertNotIn('PRIVATE', json.dumps(a))
        paths = [entry['path'] for entry in a['materials']]
        self.assertEqual(paths, sorted(paths))
        self.assertIn('go.mod', paths)
        self.assertIn('scripts/release_artifacts.py', paths)
        self.assertIn('migrations/001_first.sql', paths)
        for entry in a['materials']:
            self.assertFalse(Path(entry['path']).is_absolute())
            self.assertEqual(entry['digest'], 'sha256:' + hashlib.sha256((first / entry['path']).read_bytes()).hexdigest())

    def test_input_bytes_and_source_identity_change_manifest(self):
        source = self.source('source')
        initial = self.manifest(source)
        for options in [dict(commit='b' * 40), dict(epoch=EPOCH + 1), dict(tag='v0.0.0-rc.2')]:
            self.assertNotEqual(initial, self.manifest(source, **options))
        (source / 'migrations/001_first.sql').write_text('changed bytes')
        self.assertNotEqual(initial, self.manifest(source))

    def test_invalid_metadata_and_symlink_materials_are_rejected_without_paths(self):
        source = self.source('PRIVATE_SOURCE')
        for options in [dict(tag='../PRIVATE'), dict(commit='PRIVATE'), dict(go_version='go1.27.2 PRIVATE'),
                        dict(epoch=-1), dict(epoch=True), dict(epoch=2**32)]:
            with self.subTest(options=options), self.assertRaises(ValueError) as raised:
                self.manifest(source, **options)
            self.assertNotIn('PRIVATE', str(raised.exception))
        material = source / 'migrations/001_first.sql'
        material.unlink()
        material.symlink_to(self.root / 'PRIVATE_OUTSIDE')
        with self.assertRaises(ValueError) as raised:
            self.manifest(source)
        self.assertNotIn('PRIVATE', str(raised.exception))

    def payload(self, parent, executable='evydence'):
        directory = self.root / parent / ('evydence_' + TAG + '_fixture')
        directory.mkdir(parents=True)
        for name in [executable, *DOCS]:
            (directory / name).write_bytes(('bytes ' + name).encode())
        return directory

    def archive(self, directory, destination, executable='evydence'):
        artifacts.write_archive(directory, destination, EPOCH, [executable])

    def test_archives_match_despite_source_order_mtime_permissions_and_location(self):
        for suffix in ['tar.gz', 'zip']:
            with self.subTest(suffix=suffix):
                first = self.payload('first-' + suffix)
                second = self.payload('second-' + suffix)
                for p in second.iterdir():
                    data = p.read_bytes()
                    p.unlink()
                    p.write_bytes(data)
                    p.chmod(0o600)
                    os.utime(p, (EPOCH + 71, EPOCH + 71))
                a, b = self.root / ('one.' + suffix), self.root / ('two.' + suffix)
                self.archive(first, a)
                self.archive(second, b)
                self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_tar_metadata_and_member_modes_are_normalized(self):
        directory = self.payload('tar')
        output = self.root / 'release.tar.gz'
        self.archive(directory, output)
        with tarfile.open(output) as archive:
            members = archive.getmembers()
            self.assertEqual([m.name for m in members], sorted(m.name for m in members))
            for m in members:
                self.assertEqual((m.uid, m.gid, m.uname, m.gname, m.mtime), (0, 0, '', '', EPOCH))
                expected = 0o755 if m.isdir() or Path(m.name).name == 'evydence' else 0o644
                self.assertEqual(m.mode, expected)
                self.assertFalse(m.pax_headers)

    def test_windows_zip_has_fixed_utc_time_modes_order_and_no_extra_fields(self):
        directory = self.payload('windows', 'evydence.exe')
        output = self.root / 'release.zip'
        self.archive(directory, output, 'evydence.exe')
        with zipfile.ZipFile(output) as archive:
            entries = archive.infolist()
            self.assertEqual([m.filename for m in entries], sorted(m.filename for m in entries))
            expected_time = datetime.datetime.fromtimestamp(EPOCH, datetime.timezone.utc).timetuple()[:6]
            for entry in entries:
                self.assertEqual(entry.date_time, expected_time)
                self.assertEqual(entry.create_system, 3)
                self.assertEqual(entry.extra, b'')
                self.assertEqual(entry.comment, b'')
                expected = 0o755 if entry.is_dir() or Path(entry.filename).name == 'evydence.exe' else 0o644
                self.assertEqual((entry.external_attr >> 16) & 0o777, expected)

    def test_unlisted_files_symlinks_unsafe_names_and_overwrite_fail_before_writes(self):
        for mutation in ['extra', 'symlink', 'fifo', 'unsafe-name', 'overwrite']:
            with self.subTest(mutation=mutation):
                directory = self.payload(mutation)
                output = self.root / (mutation + '.zip')
                if mutation == 'extra':
                    (directory / 'PRIVATE.key').write_text('PRIVATE_SECRET')
                elif mutation == 'symlink':
                    (directory / 'evydence').unlink()
                    (directory / 'evydence').symlink_to(self.root / 'PRIVATE_OUTSIDE')
                elif mutation == 'fifo':
                    (directory / 'evydence').unlink()
                    os.mkfifo(directory / 'evydence')
                elif mutation == 'overwrite':
                    output.write_text('preserved')
                executable = '../PRIVATE' if mutation == 'unsafe-name' else 'evydence'
                with self.assertRaises(ValueError) as raised:
                    self.archive(directory, output, executable)
                self.assertNotIn('PRIVATE', str(raised.exception))
                if mutation == 'overwrite':
                    self.assertEqual(output.read_text(), 'preserved')
                else:
                    self.assertFalse(output.exists())

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(Path(artifacts.__file__)), *arguments],
                              capture_output=True, text=True, timeout=10)

    def test_manifest_entrypoint_uses_explicit_source_and_does_not_overwrite(self):
        source = self.source('cli-source')
        output = self.root / 'manifest.json'
        arguments = ['manifest', '--root', str(source), '--tag', TAG, '--commit', COMMIT,
                     '--epoch', str(EPOCH), '--go-version', 'go1.27.2', '--output', str(output)]
        result = self.cli(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text()), self.manifest(source))
        original = output.read_bytes()
        result = self.cli(*arguments)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_bytes(), original)
        self.assertNotIn(str(self.root), result.stderr)

    def test_archive_entrypoint_and_argument_errors_are_safe(self):
        directory = self.payload('cli-archive')
        output = self.root / 'archive.zip'
        result = self.cli('archive', '--directory', str(directory), '--output', str(output),
                          '--epoch', str(EPOCH), '--executable', 'evydence')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        for arguments in [['PRIVATE_UNKNOWN'], ['manifest', '--epoch', 'PRIVATE_SECRET'],
                          ['archive', '--directory', 'PRIVATE_PATH']]:
            with self.subTest(arguments=arguments):
                result = self.cli(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('PRIVATE', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
