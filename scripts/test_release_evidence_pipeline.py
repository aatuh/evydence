#!/usr/bin/env python3
"""Exercise the real metadata CLI boundary with fixture archives and a fake scanner."""
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

import release_evidence_metadata as metadata
import release_evidence_profile as profile
import release_evidence_verify
import release_sbom
import release_scanner


class EvidencePipelineTests(unittest.TestCase):
    def fixture(self):
        from test_release_subjects import ReleaseSubjectsTests, TAG
        fixture = ReleaseSubjectsTests('test_all_eight_binaries_and_five_archives_bind_to_actual_bytes')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        manifest = {'schema_version': 'evydence-release-build-manifest.v1',
                    'build_recipe_version': 'evydence-release-build.v1', 'commit': 'a' * 40,
                    'tag': TAG, 'go_version': release_scanner.SCANNER_GO_VERSION,
                    'materials': [{'path': 'go.mod', 'digest': 'sha256:' + 'b' * 64}]}
        (fixture.dist / 'release-build-manifest.json').write_bytes(profile.json_bytes(manifest))
        return fixture, TAG

    def invoke(self, fixture, tag, scanner):
        def run(args):
            if args[:2] == ['git', 'rev-parse']:
                return 'a' * 40
            if args[:2] == ['git', 'show']:
                return '2026-10-19T00:00:00+00:00'
            return 'go version ' + release_scanner.SCANNER_GO_VERSION + ' linux/amd64'
        stderr, stdout = io.StringIO(), io.StringIO()
        with mock.patch.object(metadata.Path, 'cwd', return_value=fixture.root), \
                mock.patch.object(metadata.sys, 'argv', ['metadata', tag, str(fixture.dist), '--syft', '/fixture/scanner']), \
                mock.patch.object(metadata, 'run', side_effect=run), \
                mock.patch.object(metadata, 'go_modules', return_value=[{'path': metadata.PROJECT_MODULE, 'version': ''}]), \
                mock.patch('release_scanner.verify_tool'), \
                mock.patch('release_evidence_tools.verify_installation', return_value=Path('/fixture/scanner')), \
                mock.patch('release_scanner.scan', side_effect=scanner), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = metadata.main()
        self.assertNotIn('PRIVATE_CANARY', stderr.getvalue())
        self.assertNotIn('SECRET_CANARY', stderr.getvalue())
        self.assertNotIn(str(fixture.root), stdout.getvalue())
        return result

    def test_metadata_cli_emits_one_bound_bom_for_each_actual_binary_and_archive(self):
        fixture, tag = self.fixture()
        def scan(_tool, subject, _workspace):
            return release_sbom.bound_bom(subject, [{'type': 'library', 'name': 'stdlib',
                                                    'version': release_scanner.SCANNER_GO_VERSION, 'purl': 'pkg:golang/stdlib@' + release_scanner.SCANNER_GO_VERSION.removeprefix('go')}])
        self.assertEqual(self.invoke(fixture, tag, scan), 0)
        index = json.loads((fixture.dist / profile.INDEX_NAME).read_text())
        self.assertEqual({item['name']: item['sha256'] for item in index['artifacts']}, fixture.expected)
        self.assertEqual(len(list(fixture.dist.glob('evydence-sbom-*.cdx.json'))), 13)
        self.assertEqual(release_evidence_verify.verify(fixture.dist, tag, 'a' * 40), 13)

        archive = next(fixture.dist.glob('*.zip'))
        original = archive.read_bytes()
        archive.write_bytes(original + b'substituted trailing payload')
        with self.assertRaises(ValueError):
            release_evidence_verify.verify(fixture.dist, tag, 'a' * 40)

    def test_missing_index_and_symlinked_evidence_fail_even_with_real_archive_subjects(self):
        fixture, tag = self.fixture()
        def scan(_tool, subject, _workspace):
            return release_sbom.bound_bom(subject, [{'type': 'library', 'name': 'stdlib',
                                                    'version': release_scanner.SCANNER_GO_VERSION, 'purl': 'pkg:golang/stdlib@' + release_scanner.SCANNER_GO_VERSION.removeprefix('go')}])
        self.assertEqual(self.invoke(fixture, tag, scan), 0)
        index = fixture.dist / profile.INDEX_NAME
        saved = index.read_bytes()
        index.unlink()
        with self.assertRaises(ValueError):
            release_evidence_verify.verify(fixture.dist, tag, 'a' * 40)
        private = fixture.root / 'PRIVATE_CANARY'
        private.write_bytes(saved)
        index.symlink_to(private)
        with self.assertRaises(ValueError):
            release_evidence_verify.verify(fixture.dist, tag, 'a' * 40)

    def test_scanner_failure_does_not_write_partial_or_private_evidence(self):
        fixture, tag = self.fixture()
        def fail(*_args):
            raise ValueError('SECRET_CANARY /PRIVATE_CANARY')
        self.assertEqual(self.invoke(fixture, tag, fail), 2)
        self.assertEqual(list(fixture.dist.glob('evydence-*')), [])


if __name__ == '__main__':
    unittest.main()
