#!/usr/bin/env python3
"""Check pinned scanner source and installation records without network or Go."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import subprocess

import release_evidence_tools as tools


class EvidenceToolTests(unittest.TestCase):
    def test_source_module_identity_requires_exact_version_and_both_checksums(self):
        record = {'Version': 'v1.54.1', 'Sum': 'h1:IdNS5Ha7WfatXHDL0qzjdf7DBVnfb8OI3FpSbltv0nc=',
                  'GoModSum': 'h1:M3Nnl7wN05wWBbffETQ+P3TEhuCDuOUhfTD4tyNX4rA=', 'Dir': '/fixture/source'}
        self.assertEqual(tools.source_directory(record), Path('/fixture/source'))
        for key in ['Version', 'Sum', 'GoModSum', 'Dir']:
            with self.subTest(key=key):
                bad = copy.deepcopy(record)
                bad[key] = 'SECRET_CANARY'
                with self.assertRaisesRegex(ValueError, '^invalid pinned release tool$'):
                    tools.source_directory(bad)

    def test_installation_requires_binary_bytes_and_the_current_tool_recipe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'syft'
            binary.write_bytes(b'fixture')
            expected = {'schema': 'evydence-release-tool.v1', 'recipe_sha256': 'a' * 64,
                        'binary_sha256': hashlib.sha256(b'fixture').hexdigest()}
            (root / 'installation.json').write_text(json.dumps(expected))
            self.assertEqual(tools.verify_installation(root, 'a' * 64), binary)
            binary.write_bytes(b'substituted')
            with self.assertRaises(ValueError):
                tools.verify_installation(root, 'a' * 64)
            binary.write_bytes(b'fixture')
            with self.assertRaises(ValueError):
                tools.verify_installation(root, 'b' * 64)

    def test_symlinked_installation_and_record_cannot_redirect_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target'
            target.mkdir()
            link = root / 'link'
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                tools.verify_installation(link, 'a' * 64)
            (target / 'installation.json').symlink_to('/PRIVATE_CANARY')
            with self.assertRaises(ValueError):
                tools.verify_installation(target, 'a' * 64)

    def test_corrupt_cached_upstream_source_is_rejected_before_copy_or_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'cache'
            source.mkdir()
            record = {'Version': 'v1.54.1', 'Sum': tools.SOURCE_SUM,
                      'GoModSum': tools.SOURCE_MOD_SUM, 'Dir': str(source)}
            def reject_cache(arguments, **options):
                self.assertEqual(arguments, ['go', 'mod', 'verify'])
                module = (Path(options['cwd']) / 'go.mod').read_text()
                self.assertIn('require github.com/anchore/syft v1.54.1', module)
                self.assertNotIn('module github.com/anchore/syft\n', module)
                raise subprocess.CalledProcessError(1, arguments)
            with mock.patch.object(tools.subprocess, 'check_output', return_value=json.dumps(record).encode()), \
                    mock.patch.object(tools.subprocess, 'run', side_effect=reject_cache), \
                    mock.patch.object(tools.shutil, 'copytree') as copy_source:
                with self.assertRaises(subprocess.CalledProcessError):
                    tools.install(root / 'tools')
                copy_source.assert_not_called()


if __name__ == '__main__':
    unittest.main()
