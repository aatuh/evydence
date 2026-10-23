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
        self.assertIn({'type': 'application', 'name': 'Evydence release evidence adapter', 'version': '1'},
                      bom['metadata']['tools']['components'])
        release_sbom.verify_bom(bom, subject)
        wrong = copy.deepcopy(bom)
        wrong['metadata']['component']['hashes'][0]['content'] = '0' * 64
        with self.assertRaises(ValueError):
            release_sbom.verify_bom(wrong, subject)
        missing = copy.deepcopy(bom)
        del missing['metadata']['component']
        with self.assertRaises(ValueError):
            release_sbom.verify_bom(missing, subject)

    def test_container_profile_includes_go_and_alpine_packages_without_host_metadata(self):
        scanner = self.scanner_bom()
        scanner['components'].append({'type': 'library', 'name': 'busybox', 'version': '1.37.0-r30',
            'purl': 'pkg:apk/alpine/busybox@1.37.0-r30?arch=x86_64&distro=alpine-3.23.2',
            'properties': [{'name': 'path', 'value': '/PRIVATE_CANARY'}]})
        scanner['components'].append({'type': 'operating-system', 'name': 'alpine', 'version': '3.23.2',
                                      'properties': [{'name': 'path', 'value': '/PRIVATE_CANARY'}]})
        components = release_sbom.public_components(scanner, allow_apk=True)
        self.assertEqual(len(components), 4)
        self.assertIn({'type': 'operating-system', 'name': 'alpine', 'version': '3.23.2'}, components)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(components))
        subject = {'name': 'ghcr.io/aatuh/evydence:v0.0.0-rc.1403', 'kind': 'container', 'sha256': 'a' * 64}
        bom = release_sbom.bound_bom(subject, components)
        self.assertEqual(bom['metadata']['component']['type'], 'container')
        release_sbom.verify_bom(bom, subject)
        with self.assertRaises(ValueError):
            release_sbom.public_components(scanner)

    def test_container_package_url_qualifiers_are_bounded_public_platform_coordinates(self):
        base = 'pkg:apk/alpine/busybox@1.37.0-r30'
        for suffix in ['?token=SECRET_CANARY', '?arch=x86_64&distro=/PRIVATE_CANARY',
                       '?arch=x86_64&arch=noarch&distro=alpine-3.23.2',
                       '?arch=x86_64&distro=alpine-3.23.2#PRIVATE_CANARY']:
            with self.subTest(suffix=suffix):
                scanner = self.scanner_bom()
                scanner['components'].append({'type': 'library', 'name': 'busybox', 'version': '1.37.0-r30',
                                               'purl': base + suffix})
                with self.assertRaises(ValueError):
                    release_sbom.public_components(scanner, allow_apk=True)

    def test_alpine_split_packages_retain_bounded_upstream_coordinate(self):
        scanner = self.scanner_bom()
        package = {'type': 'library', 'name': 'libcrypto3', 'version': '3.5.8-r0',
                   'purl': 'pkg:apk/alpine/libcrypto3@3.5.8-r0?arch=x86_64&distro=alpine-3.23.6&upstream=openssl'}
        scanner['components'].append(package)
        self.assertIn(package, release_sbom.public_components(scanner, allow_apk=True))
        for suffix in ['&upstream=/PRIVATE_CANARY', '&upstream=..', '&upstream=openssl%2FPRIVATE_CANARY',
                       '&upstream=openssl&upstream=busybox', '&upstream=openssl&token=SECRET_CANARY',
                       '&upstream=' + 'a' * 256]:
            with self.subTest(suffix=suffix):
                package['purl'] = 'pkg:apk/alpine/libcrypto3@3.5.8-r0?arch=x86_64&distro=alpine-3.23.6' + suffix
                with self.assertRaises(ValueError):
                    release_sbom.public_components(scanner, allow_apk=True)


if __name__ == '__main__':
    unittest.main()
