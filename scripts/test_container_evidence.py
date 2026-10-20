#!/usr/bin/env python3
"""Check image evidence against validated OCI subjects, independent of a registry."""
import copy
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

import container_evidence
import release_oci
import release_sbom


class ContainerEvidenceTests(unittest.TestCase):
    def setUp(self):
        from test_release_oci import OCIImageTests, IMAGE, COMMIT
        fixture = OCIImageTests('test_actual_manifest_config_and_layers_bind_to_one_supported_image_subject')
        archive, digest = fixture.fixture()
        self.archive = archive
        self.addCleanup(fixture.doCleanups)
        self.subject = release_oci.inspect(archive, IMAGE, digest, COMMIT)
        self.materials = [{'path': 'Dockerfile', 'digest': 'sha256:' + 'b' * 64}]
        components = [{'type': 'library', 'name': 'stdlib', 'version': 'go1.27.2', 'purl': 'pkg:golang/stdlib@1.27.2'},
                      {'type': 'library', 'name': 'busybox', 'version': '1.37.0-r30',
                       'purl': 'pkg:apk/alpine/busybox@1.37.0-r30?arch=x86_64&distro=alpine-3.23.2'}]
        self.bom = release_sbom.bound_bom(self.subject, sorted(components, key=lambda item: item['purl']))

    def documents(self, *, invocation='local', buildx='v0.30.1', workflow_commit=None):
        return container_evidence.documents(self.subject, self.bom, self.materials,
                                            invocation=invocation, buildx_version=buildx,
                                            workflow_commit=workflow_commit)

    def test_image_subject_has_matching_bom_provenance_builder_inputs_and_index(self):
        documents = self.documents()
        container_evidence.verify_documents(documents, self.subject)
        statement = json.loads(documents[container_evidence.PROVENANCE_NAME])
        self.assertEqual(statement['predicateType'], 'https://slsa.dev/provenance/v1')
        self.assertEqual(statement['subject'], [{'name': self.subject['name'],
                                               'digest': {'sha256': self.subject['sha256']}}])
        self.assertIn('Dockerfile', json.dumps(statement['predicate']['buildDefinition']['resolvedDependencies']))
        self.assertIn('container_evidence.py', statement['predicate']['runDetails']['builder']['id'])
        self.assertIn('v0.30.1', json.dumps(statement['predicate']['runDetails']['builder']['version']))

    def test_hosted_builder_names_the_exact_source_workflow_and_run(self):
        invocation = 'https://github.com/aatuh/evydence/actions/runs/123'
        documents = self.documents(invocation=invocation, workflow_commit='c' * 40)
        container_evidence.verify_documents(documents, self.subject)
        statement = json.loads(documents[container_evidence.PROVENANCE_NAME])
        builder = statement['predicate']['runDetails']['builder']['id']
        self.assertTrue(builder.endswith('/container-image.yml@' + 'c' * 40))
        self.assertEqual(statement['predicate']['buildDefinition']['externalParameters']['source_commit'], self.subject['source_commit'])
        with self.assertRaises(ValueError):
            self.documents(invocation=invocation)

    def test_missing_or_consistently_substituted_image_subjects_fail(self):
        missing = self.documents()
        del missing[container_evidence.SBOM_NAME]
        with self.assertRaises(ValueError):
            container_evidence.verify_documents(missing, self.subject)
        forged = copy.deepcopy(self.subject)
        forged['sha256'] = '0' * 64
        bom = release_sbom.bound_bom(forged, self.bom['components'])
        documents = container_evidence.documents(forged, bom, self.materials, invocation='local', buildx_version='v0.30.1')
        with self.assertRaises(ValueError):
            container_evidence.verify_documents(documents, self.subject)

    def test_private_material_paths_provider_inputs_and_old_exporter_versions_fail(self):
        for invocation, buildx in [('https://user:SECRET_CANARY@example.com/run', 'v0.30.1'),
                                   ('local', 'v0.12.0'), ('local', '/PRIVATE_CANARY')]:
            with self.subTest(invocation=invocation, buildx=buildx):
                with self.assertRaisesRegex(ValueError, '^invalid container release evidence$'):
                    self.documents(invocation=invocation, buildx=buildx)
        self.materials[0]['path'] = '/PRIVATE_CANARY/Dockerfile'
        with self.assertRaisesRegex(ValueError, '^invalid container release evidence$'):
            self.documents()

    def arguments(self, mode):
        return [mode, '--oci', str(self.archive), '--image', self.subject['name'],
                '--digest', 'sha256:' + self.subject['sha256'], '--expected-commit', self.subject['source_commit'],
                '--out', str(self.archive.parent / 'evidence')]

    def test_cli_generates_then_verifies_actual_oci_bound_evidence_without_scanning_on_verify(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch('release_build.source_identity', return_value=self.subject['source_commit']), \
                mock.patch.object(container_evidence, 'source_materials', return_value=self.materials), \
                mock.patch('release_evidence_tools.verify_installation', return_value=Path('/fixture/syft')), \
                mock.patch('release_scanner.verify_tool'), \
                mock.patch('release_scanner.scan_container', return_value=self.bom) as scanner, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            args = self.arguments('generate') + ['--syft', '/fixture/syft', '--buildx-version', 'v0.30.1']
            self.assertEqual(container_evidence.main(args), 0)
            self.assertEqual(scanner.call_count, 1)
            self.assertEqual(container_evidence.main(self.arguments('verify')), 0)
            self.assertEqual(scanner.call_count, 1)
        self.assertNotIn(str(self.archive.parent), stdout.getvalue())
        self.assertEqual(stderr.getvalue(), '')

    def test_changed_source_stops_generation_before_scanning_or_writing_evidence(self):
        stderr = io.StringIO()
        with mock.patch('release_build.source_identity', side_effect=ValueError('PRIVATE_CANARY')), \
                mock.patch('release_scanner.scan_container') as scanner, \
                contextlib.redirect_stderr(stderr):
            args = self.arguments('generate') + ['--syft', '/fixture/syft', '--buildx-version', 'v0.30.1']
            self.assertEqual(container_evidence.main(args), 2)
            scanner.assert_not_called()
        self.assertFalse((self.archive.parent / 'evidence').exists())
        self.assertNotIn('PRIVATE_CANARY', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
