#!/usr/bin/env python3
"""Verify scanner output is reduced to public package coordinates and bound subjects."""
import copy
import hashlib
import json
import unittest

import release_sbom


class ReleaseSBOMTests(unittest.TestCase):
    def scanner_bom(self):
        return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                'metadata': {'component': {'name': '/PRIVATE_CANARY/build/evydence'},
                             'properties': [{'name': 'credential', 'value': 'SECRET_CANARY'}]},
                'components': [{'type': 'library', 'name': 'example.com/library', 'version': 'v1.2.3',
                                'purl': 'pkg:golang/example.com/library@v1.2.3',
                                'bom-ref': '/PRIVATE_CANARY/cache',
                                'properties': [{'name': 'token', 'value': 'SECRET_CANARY'}]},
                               {'type': 'library', 'name': 'stdlib', 'version': 'go1.27.2',
                                'purl': 'pkg:golang/stdlib@1.27.2'}]}

    def test_only_public_coordinates_are_exported_from_scanner(self):
        scanner = self.scanner_bom()
        scanner['components'].append({'type': 'file', 'name': '/PRIVATE_CANARY/evydence'})
        components = release_sbom.public_components(scanner)
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0], {'type': 'library', 'name': 'example.com/library',
                                        'version': 'v1.2.3', 'purl': 'pkg:golang/example.com/library@v1.2.3'})
        exported = json.dumps(components)
        self.assertNotIn('PRIVATE_CANARY', exported)
        self.assertNotIn('SECRET_CANARY', exported)

    def test_unsafe_coordinates_are_rejected_instead_of_silently_omitted(self):
        for field, value in [('name', '/PRIVATE_CANARY'), ('version', '../PRIVATE_CANARY'),
                             ('purl', 'https://user:SECRET_CANARY@example.com/package'),
                             ('purl', 'pkg:golang/example.com/library@v1.2.3?token=SECRET_CANARY')]:
            with self.subTest(field=field, value=value):
                bom = self.scanner_bom()
                bom['components'][0][field] = value
                with self.assertRaisesRegex(ValueError, '^invalid release SBOM data$'):
                    release_sbom.public_components(bom)

    def test_duplicate_components_and_missing_package_inventory_fail(self):
        conflicting = copy.deepcopy(self.scanner_bom()['components'][0])
        conflicting['version'] = 'v9.9.9'
        for components in [[], [self.scanner_bom()['components'][0], conflicting], None]:
            with self.subTest(components=components):
                bom = self.scanner_bom()
                bom['components'] = components
                with self.assertRaises(ValueError):
                    release_sbom.public_components(bom)

    def test_same_package_in_multiple_archive_binaries_has_one_public_coordinate(self):
        bom = self.scanner_bom()
        repeated = copy.deepcopy(bom['components'][0])
        repeated['bom-ref'] = 'another-binary-specific-reference'
        repeated['properties'] = [{'name': 'syft:location:0:path', 'value': '/PRIVATE_CANARY/another'}]
        bom['components'].append(repeated)
        self.assertEqual(len(release_sbom.public_components(bom)), 2)

    def test_bom_identifies_the_exact_artifact_and_pinned_scanner(self):
        subject = {'name': 'evydence_v0.0.0-rc.1403_linux_amd64/evydence',
                   'kind': 'binary', 'sha256': hashlib.sha256(b'binary').hexdigest()}
        components = release_sbom.public_components(self.scanner_bom())
        bom = release_sbom.bound_bom(subject, components)
        component = bom['metadata']['component']
        self.assertEqual(component['name'], subject['name'])
        self.assertEqual(component['hashes'], [{'alg': 'SHA-256', 'content': subject['sha256']}])
        self.assertEqual(bom['components'], components)
        self.assertIn(release_sbom.SYFT_VERSION, json.dumps(bom['metadata']['tools']))
        release_sbom.verify_bom(bom, subject)
        wrong = copy.deepcopy(bom)
        wrong['metadata']['component']['hashes'][0]['content'] = '0' * 64
        with self.assertRaises(ValueError):
            release_sbom.verify_bom(wrong, subject)
        missing = copy.deepcopy(bom)
        del missing['metadata']['component']
        with self.assertRaises(ValueError):
            release_sbom.verify_bom(missing, subject)


if __name__ == '__main__':
    unittest.main()
