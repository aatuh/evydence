#!/usr/bin/env python3
"""Exercise real release archive boundaries using small offline payloads."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

import release_artifacts
import release_subjects
import support_matrix


TAG = 'v0.0.0-rc.1403'


class ReleaseSubjectsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        self.expected = {}
        self.attempt = 0
        for target in support_matrix.release_plan(support_matrix.load_policy()):
            name = f"evydence_{TAG}_{target['goos']}_{target['goarch']}"
            directory = self.root / name
            directory.mkdir()
            commands = []
            for command in target['commands']:
                binary = command + ('.exe' if target['goos'] == 'windows' else '')
                data = (name + '/' + binary).encode()
                (directory / binary).write_bytes(data)
                commands.append(binary)
                self.expected[name + '/' + binary] = hashlib.sha256(data).hexdigest()
            for document in release_artifacts.DOCUMENTS:
                (directory / document).write_text('public fixture\n')
            suffix = '.zip' if target['goos'] == 'windows' else '.tar.gz'
            output = self.dist / (name + suffix)
            release_artifacts.write_archive(directory, output, 1700000000, commands)
            self.expected[output.name] = hashlib.sha256(output.read_bytes()).hexdigest()

    def collect(self):
        self.attempt += 1
        return release_subjects.collect(self.dist, TAG, self.root / ('scratch-' + str(self.attempt)))

    def test_all_eight_binaries_and_five_archives_bind_to_actual_bytes(self):
        records = self.collect()
        self.assertEqual(len(records), 13)
        self.assertEqual({item['name']: item['sha256'] for item in records}, self.expected)
        for item in records:
            self.assertEqual(hashlib.sha256(item['path'].read_bytes()).hexdigest(), item['sha256'])

    def test_missing_archive_or_binary_fails_closed(self):
        archive = next(self.dist.glob('*linux_amd64.tar.gz'))
        archive.unlink()
        with self.assertRaises(ValueError):
            self.collect()

    def test_archive_symlink_does_not_read_private_target(self):
        archive = next(self.dist.glob('*.zip'))
        archive.unlink()
        archive.symlink_to('/PRIVATE_CANARY')
        with self.assertRaisesRegex(ValueError, '^invalid release subject payload$') as error:
            self.collect()
        self.assertNotIn('PRIVATE_CANARY', str(error.exception))

    def test_tar_traversal_links_duplicates_and_missing_binary_are_rejected(self):
        archive = next(self.dist.glob('*linux_amd64.tar.gz'))
        for mode in ['traversal', 'symlink', 'duplicate', 'missing', 'oversized']:
            with self.subTest(mode=mode):
                with tarfile.open(archive, 'w:gz') as output:
                    name = archive.name.removesuffix('.tar.gz')
                    member = tarfile.TarInfo(name + '/evydence')
                    member.size = 1
                    if mode == 'traversal':
                        member.name = '../PRIVATE_CANARY'
                    elif mode == 'symlink':
                        member.type = tarfile.SYMTYPE
                        member.linkname = '/PRIVATE_CANARY'
                        member.size = 0
                    elif mode == 'oversized':
                        member.size = release_subjects.MAX_EXPANDED_BYTES + 1
                        # A header alone reproduces a malicious size declaration
                        # without allocating the claimed payload in the fixture.
                        output.fileobj.write(member.tobuf())
                        output.offset += tarfile.BLOCKSIZE
                    if mode != 'oversized':
                        output.addfile(member, io.BytesIO(b'x'))
                    if mode == 'duplicate':
                        output.addfile(member, io.BytesIO(b'x'))
                with self.assertRaisesRegex(ValueError, '^invalid release subject payload$'):
                    self.collect()

    def test_zip_traversal_and_duplicate_entries_are_rejected(self):
        archive = next(self.dist.glob('*.zip'))
        for names in [['../PRIVATE_CANARY'], ['same', 'same']]:
            with self.subTest(names=names):
                with zipfile.ZipFile(archive, 'w') as output:
                    for name in names:
                        output.writestr(name, 'x')
                with self.assertRaises(ValueError):
                    self.collect()


if __name__ == '__main__':
    unittest.main()
