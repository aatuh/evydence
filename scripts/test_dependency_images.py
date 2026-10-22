#!/usr/bin/env python3
"""Image declaration coverage and digest-bound scanner projection regressions."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_images as images
import dependency_image_registry as registry

ROOT = Path(__file__).resolve().parents[1]


def scanner():
    config = {'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]},
              'config': {'Env': ['PASSWORD=SECRET_CANARY'], 'Labels': {'private': 'PRIVATE_CANARY'}}}
    config_raw = json.dumps(config).encode(); config_digest = 'sha256:' + hashlib.sha256(config_raw).hexdigest()
    manifest = {'schemaVersion': 2, 'mediaType': registry.OCI_MANIFEST,
                'config': {'mediaType': registry.OCI_CONFIG, 'digest': config_digest, 'size': len(config_raw)},
                'layers': [{'mediaType': registry.OCI_LAYER + '+gzip', 'digest': 'sha256:' + 'b' * 64, 'size': 20}]}
    manifest_raw = json.dumps(manifest).encode(); manifest_digest = 'sha256:' + hashlib.sha256(manifest_raw).hexdigest()
    document = {'source': {'type': 'image', 'metadata': {'imageID': config_digest, 'manifestDigest': manifest_digest,
                'manifest': base64.b64encode(manifest_raw).decode(), 'config': base64.b64encode(config_raw).decode(),
                'os': 'linux', 'architecture': 'amd64', 'labels': {'private': 'PRIVATE_CANARY'}}},
                'artifacts': [{'name': 'busybox', 'version': '1.37.0-r1', 'type': 'apk', 'purl': 'pkg:apk/alpine/busybox@1.37.0-r1?arch=x86_64&distro=alpine-3.23.6',
                               'locations': [{'path': '/PRIVATE_CANARY'}], 'metadata': {'private': 'PRIVATE_CANARY'},
                               'licenses': [{'value': 'GPL-2.0-only', 'spdxExpression': 'GPL-2.0-only', 'type': 'declared', 'locations': [{'path': '/PRIVATE_CANARY'}]}]}]}
    return document, manifest_digest, config_digest


class DiscoveryTests(unittest.TestCase):
    def test_repository_declared_images_include_legacy_local_and_operator_scopes(self):
        rows, inputs = images.discover(ROOT)
        self.assertEqual(sum(row['kind'] == 'registry' for row in rows), 5)
        self.assertEqual(sum(row['kind'] == 'source-build' for row in rows), 2)
        self.assertEqual(sum(row['kind'] == 'operator-selected' for row in rows), 2)
        self.assertTrue(any('v0.1.0-rc.5' in row['reference'] for row in rows))
        self.assertTrue(any('scorecard-action:v2.4.3' in row['reference'] for row in rows))
        self.assertIn('docs/reference/dependency-inventory.json', inputs)
        self.assertTrue(all(row['locations'] for row in rows))

    def test_dockerfile_stage_aliases_are_local_but_undeclared_bases_and_variables_fail(self):
        valid = b'FROM alpine:3.23 AS base\nFROM base AS final\n'
        self.assertEqual(images.docker_bases(valid), ['alpine:3.23'])
        for raw in [b'FROM unknown\n', b'FROM ${BASE}\n', b'FROM alpine:3.23 AS base\nFROM other\n']:
            with self.subTest(raw=raw), self.assertRaises(images.ImageInventoryError): images.docker_bases(raw)


class ProjectionTests(unittest.TestCase):
    def test_alpine_virtual_package_names_retain_coordinates_and_unknown_license(self):
        document, manifest, config = scanner()
        row = document['artifacts'][0]
        row.update(name='.postgresql-rundeps', version='20260514.190346',
                   purl='pkg:apk/alpine/.postgresql-rundeps@20260514.190346?arch=noarch&distro=alpine-3.23.4', licenses=[])
        result = images.project(json.dumps(document).encode(), manifest, config)['packages'][0]
        self.assertEqual(result['name'], '.postgresql-rundeps')
        self.assertEqual(result['license_status'], 'not-found')
        row.update(name='..', purl='pkg:apk/alpine/..@20260514.190346')
        with self.assertRaises(images.ImageInventoryError): images.project(json.dumps(document).encode(), manifest, config)

    def test_manifest_config_and_platform_bind_packages_while_private_scanner_data_is_omitted(self):
        document, manifest, config = scanner()
        result = images.project(json.dumps(document).encode(), manifest, config)
        self.assertEqual(result['image_id'], config)
        self.assertEqual(result['manifest_digest'], manifest)
        self.assertEqual(result['packages'][0]['license'], 'GPL-2.0-only')
        self.assertEqual(result['packages'][0]['license_status'], 'scanner-declared')
        self.assertNotIn('CANARY', json.dumps(result))

    def test_wrong_manifest_config_platform_or_missing_artifacts_fail(self):
        document, manifest, config = scanner()
        for case in ['manifest', 'config', 'platform', 'empty', 'source-type']:
            value = copy.deepcopy(document)
            if case == 'manifest': value['source']['metadata']['manifest'] = base64.b64encode(b'wrong').decode()
            if case == 'config': value['source']['metadata']['config'] = base64.b64encode(b'wrong').decode()
            if case == 'platform': value['source']['metadata']['architecture'] = 'arm64'
            if case == 'empty': value['artifacts'] = []
            if case == 'source-type': value['source']['type'] = 'directory'
            with self.subTest(case=case), self.assertRaises(images.ImageInventoryError):
                images.project(json.dumps(value).encode(), manifest, config)

    def test_multiple_missing_and_unsupported_license_declarations_do_not_become_approval(self):
        document, manifest, config = scanner()
        for licenses, expression, status in [([], None, 'not-found'),
                ([{'value': '', 'spdxExpression': ''}], None, 'unsupported'),
                ([{'spdxExpression': ' UNKNOWN '}], None, 'unsupported'),
                ([{'spdxExpression': '   '}], None, 'unsupported'),
                ([{'value': 'PRIVATE_CANARY prose', 'spdxExpression': 'not an expression', 'type': 'declared'}], None, 'unsupported'),
                ([{'value': 'MIT', 'spdxExpression': 'MIT', 'type': 'declared'},
                  {'value': 'Apache-2.0', 'spdxExpression': 'Apache-2.0', 'type': 'declared'}], None, 'multiple-declarations')]:
            value = copy.deepcopy(document); value['artifacts'][0]['licenses'] = licenses
            result = images.project(json.dumps(value).encode(), manifest, config)['packages'][0]
            self.assertEqual((result['license'], result['license_status']), (expression, status))
            self.assertNotIn('CANARY', json.dumps(result))

    def test_duplicate_package_conflicts_invalid_coordinates_and_limits_fail(self):
        document, manifest, config = scanner()
        value = copy.deepcopy(document); value['artifacts'].append(copy.deepcopy(value['artifacts'][0]))
        value['artifacts'][-1]['licenses'] = []
        with self.assertRaises(images.ImageInventoryError): images.project(json.dumps(value).encode(), manifest, config)
        for field, invalid in [('name', '../../PRIVATE_CANARY'), ('version', 'bad\nversion'), ('purl', 'https://SECRET_CANARY.invalid'), ('type', 'unsupported')]:
            value = copy.deepcopy(document); value['artifacts'][0][field] = invalid
            with self.subTest(field=field), self.assertRaises(images.ImageInventoryError): images.project(json.dumps(value).encode(), manifest, config)
        with patch.object(images, 'MAX_PACKAGES', 0), self.assertRaises(images.ImageInventoryError):
            images.project(json.dumps(document).encode(), manifest, config)

    def test_scan_is_registry_or_exact_local_id_only_with_isolated_bounded_execution(self):
        document, manifest, config = scanner()
        row = {'reference': 'docker.io/library/alpine:3.23', 'kind': 'registry'}
        resolution = {'manifest_digest': manifest, 'config': {'digest': config}}
        with tempfile.TemporaryDirectory() as folder, patch.object(images.inventory, '_run', return_value=json.dumps(document).encode()) as run:
            result = images.scan(Path('/scanner'), row, resolution, Path(folder))
            args, cwd, environment = run.call_args.args
            self.assertIn('registry:docker.io/library/alpine@' + manifest, args)
            self.assertIn('--platform', args)
            self.assertEqual(environment['HOME'], str(folder))
            self.assertNotIn('GH_TOKEN', environment)
            self.assertIn('dpkg-db-cataloger', args)
            self.assertNotIn('CANARY', json.dumps(result))


class ReportTests(unittest.TestCase):
    def test_offline_binding_rejects_input_coverage_coordinate_and_identity_tampering(self):
        document, manifest, config = scanner()
        declaration = {'reference': 'docker.io/library/alpine:3.23', 'kind': 'registry', 'locations': ['Dockerfile#base/0']}
        observation = images.project(json.dumps(document).encode(), manifest, config)
        report = {'schema': images.SCHEMA, 'scope': 'declared-linux-amd64-images', 'complete_artifact_sbom': False,
                  'inputs': {'input': hashlib.sha256(b'input').hexdigest()},
                  'scanner': {'name': 'syft', 'version': images.tools.release_sbom.SYFT_VERSION,
                              'recipe_sha256': images.tools.recipe_digest(), 'binary_sha256': 'a' * 64},
                  'coverage': {'declared': 1, 'scanned': 1, 'operator_selected': 0},
                  'images': [{**declaration, 'status': 'scanned', 'observation': observation,
                              'resolution': {'manifest_digest': manifest, 'config': {'digest': config}, 'root_digest': manifest}}]}
        changes = [lambda value: value['inputs'].update(input='a' * 64),
                   lambda value: value['coverage'].update(scanned=0),
                   lambda value: value['images'][0]['observation'].update(image_id='sha256:' + 'c' * 64),
                   lambda value: value['images'][0]['observation']['packages'][0].update(purl='https://SECRET_CANARY'),
                   lambda value: value['scanner'].update(recipe_sha256='a' * 64),
                   lambda value: value['images'][0]['observation']['packages'][0].update(license_status='not-found')]
        with patch.object(images, 'discover', return_value=([declaration], {'input': b'input'})), \
             patch.object(images, 'generator_inputs', return_value={}):
            images.check(ROOT, report)
            for change in changes:
                value = copy.deepcopy(report); change(value)
                with self.subTest(change=change), self.assertRaises(images.ImageInventoryError): images.check(ROOT, value)

    def test_collection_requires_exact_local_ids_and_freezes_inputs_before_scanning(self):
        document, manifest, config = scanner()
        rows = [{'reference': 'docker.io/library/alpine:3.23', 'kind': 'registry', 'locations': ['Dockerfile#base/0']},
                {'reference': 'evydence-local-mc:20250813-7394ce0dd2a8', 'kind': 'source-build', 'locations': ['compose#mc']},
                {'reference': '${EVYDENCE_IMAGE:-evydence:local}', 'kind': 'operator-selected', 'locations': ['compose#app']}]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'input').write_bytes(b'original'); binary = root / 'syft'; binary.write_bytes(b'tool')
            local = {rows[1]['reference']: config}
            result = images.project(json.dumps(document).encode(), manifest, config)
            with patch.object(images, 'discover', return_value=(rows, {'input': b'original'})), \
                 patch.object(images, 'generator_inputs', return_value={}), \
                 patch.object(images.tools, 'verify_installation', return_value=binary), \
                 patch.object(images.release_scanner, 'verify_tool'), \
                 patch.object(images.registry, 'resolve', return_value={'manifest_digest': manifest, 'config': {'digest': config}}), \
                 patch.object(images, 'scan', return_value=result) as scan:
                report = images.collect(root, root, binary, local)
                self.assertEqual(report['coverage'], {'declared': 3, 'scanned': 2, 'operator_selected': 1})
                self.assertEqual(scan.call_count, 2)
                self.assertEqual(report['images'][2]['status'], 'operator-selected')
                self.assertNotIn('CANARY', json.dumps(report))
                with self.assertRaises(images.ImageInventoryError): images.collect(root, root, binary, {})
                def mutate(*_args):
                    (root / 'input').write_bytes(b'changed'); return result
                scan.side_effect = mutate
                with self.assertRaises(images.ImageInventoryError): images.collect(root, root, binary, local)

    def test_atomic_report_refuses_unrelated_symlink_paths_and_preserves_owner_files(self):
        report = {'schema': images.SCHEMA, 'images': []}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root / 'report.json'
            images.write_report(root, 'report.json', report)
            before = target.read_bytes()
            with self.assertRaises(images.ImageInventoryError): images.write_report(root, 'report.json', report)
            images.write_report(root, 'report.json', report, replace=True)
            self.assertEqual(target.read_bytes(), before)
            target.write_text('owner data')
            with self.assertRaises(images.ImageInventoryError): images.write_report(root, 'report.json', report, replace=True)
            self.assertEqual(target.read_text(), 'owner data')
            (root / 'link').symlink_to(target)
            (root / 'directory-link').symlink_to(root, target_is_directory=True)
            for relative in ['link', 'directory-link/new.json', '../outside.json', str(target)]:
                with self.subTest(relative=relative), self.assertRaises(images.ImageInventoryError):
                    images.write_report(root, relative, report, replace=True)
            with patch.object(images.os, 'open', side_effect=OSError('failure')):
                with self.assertRaises(images.ImageInventoryError): images.write_report(root, 'report.json', report, replace=True)
            self.assertEqual(target.read_text(), 'owner data')


if __name__ == '__main__':
    unittest.main()
