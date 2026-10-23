#!/usr/bin/env python3
"""Check release module identities without executing Go or contacting providers."""
import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_evidence_metadata as metadata


class ReleaseModuleMetadataTests(unittest.TestCase):
    def modules(self, records):
        raw = ''.join(json.dumps(record) + '\n' for record in records)
        with mock.patch.object(metadata.subprocess, 'check_output', return_value=raw):
            return metadata.go_modules()

    def test_public_module_coordinates_are_sorted_without_host_paths(self):
        modules = self.modules([
            {'Path': 'example.com/z', 'Version': 'v1.2.3', 'Dir': '/PRIVATE_CANARY/cache/z'},
            {'Path': 'github.com/aatuh/evydence', 'Main': True, 'Dir': '/PRIVATE_CANARY/source'},
            {'Path': 'example.com/a', 'Version': 'v0.0.0-20260101000000-abcdef123456'},
        ])
        self.assertEqual(modules, [
            {'path': 'example.com/a', 'version': 'v0.0.0-20260101000000-abcdef123456'},
            {'path': 'example.com/z', 'version': 'v1.2.3'},
            {'path': 'github.com/aatuh/evydence', 'version': ''},
        ])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(modules))

    def test_unversioned_local_replacement_is_rejected_without_private_path(self):
        for replacement in ['/PRIVATE_CANARY/dependency', '../PRIVATE_CANARY', 'C:\\PRIVATE_CANARY']:
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(ValueError, '^invalid release module metadata$') as raised:
                    self.modules([{'Path': 'example.com/library', 'Version': 'v1.2.3',
                                   'Replace': {'Path': replacement}}])
                self.assertNotIn('PRIVATE_CANARY', str(raised.exception))

    def test_versioned_remote_replacement_identifies_the_effective_module(self):
        self.assertEqual(self.modules([
            {'Path': 'example.com/original', 'Version': 'v1.2.3',
             'Replace': {'Path': 'example.com/fork', 'Version': 'v1.2.4'}},
        ]), [{'path': 'example.com/fork', 'version': 'v1.2.4'}])

    def test_duplicate_json_keys_cannot_choose_a_different_module_identity(self):
        raw = '{"Path":"example.com/original","Path":"example.com/different","Version":"v1.0.0"}'
        with mock.patch.object(metadata.subprocess, 'check_output', return_value=raw):
            with self.assertRaisesRegex(ValueError, '^invalid release module metadata$'):
                metadata.go_modules()

    def test_conflicting_versions_for_the_same_effective_identity_are_rejected(self):
        with self.assertRaisesRegex(ValueError, '^invalid release module metadata$'):
            self.modules([{'Path': 'example.com/library', 'Version': 'v1.0.0'},
                          {'Path': 'example.com/library', 'Version': 'v1.1.0'}])

    def test_module_versions_are_typed_coordinates_and_cannot_contain_paths_or_tokens(self):
        for version in [True, 42, ['/PRIVATE_CANARY'], '../PRIVATE_CANARY',
                        'v1.0.0 PRIVATE_CANARY', 'v1.0.0?token=PRIVATE_CANARY']:
            with self.subTest(version=version):
                with self.assertRaisesRegex(ValueError, '^invalid release module metadata$'):
                    self.modules([{'Path': 'example.com/library', 'Version': version}])

    def test_invalid_module_metadata_fails_before_writing_release_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / 'dist'
            dist.mkdir()
            error = io.StringIO()
            with mock.patch.object(metadata.Path, 'cwd', return_value=root), \
                    mock.patch.object(metadata.sys, 'argv', ['metadata', 'v0.0.0-rc.1403', str(dist)]), \
                    mock.patch.object(metadata, 'run', return_value='a' * 40), \
                    mock.patch.object(metadata, 'go_modules', side_effect=ValueError('PRIVATE_CANARY')), \
                    contextlib.redirect_stderr(error):
                self.assertEqual(metadata.main(), 2)
            self.assertEqual(list(dist.iterdir()), [])
            self.assertNotIn('PRIVATE_CANARY', error.getvalue())
            self.assertNotIn('Traceback', error.getvalue())


if __name__ == '__main__':
    unittest.main()
