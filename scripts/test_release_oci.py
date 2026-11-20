#!/usr/bin/env python3
"""Verify OCI subject binding using complete small content-addressed image layouts."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import release_oci


IMAGE = 'ghcr.io/aatuh/evydence:v0.0.0-rc.1403'
COMMIT = 'a' * 40


class OCIImageTests(unittest.TestCase):
    def fixture(self, *, platform='amd64', wrong_diff_id=False, extra=None, corrupt_layer=False,
                malformed_compression=False, compatibility=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode='w') as layer:
            item = tarfile.TarInfo('etc/public-fixture')
            item.size = 7
            layer.addfile(item, io.BytesIO(b'fixture'))
        raw_layer = layer_buffer.getvalue()
        compressed_layer = gzip.compress(raw_layer, mtime=0)
        if malformed_compression:
            compressed_layer = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x07' + bytes(8)
        files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}'}
        def blob(raw, media):
            sha = hashlib.sha256(raw).hexdigest()
            files['blobs/sha256/' + sha] = raw
            return {'mediaType': media, 'digest': 'sha256:' + sha, 'size': len(raw)}
        layer = blob(compressed_layer, 'application/vnd.oci.image.layer.v1.tar+gzip')
        config = {'os': 'linux', 'architecture': platform,
                  'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + ('0' * 64 if wrong_diff_id else hashlib.sha256(raw_layer).hexdigest())]},
                  'config': {'Env': ['SECRET=SECRET_CANARY', 'HOME=/PRIVATE_CANARY'],
                             'Labels': {'org.opencontainers.image.revision': COMMIT,
                                        'org.opencontainers.image.version': 'v0.0.0-rc.1403',
                                        'org.opencontainers.image.source': 'https://github.com/aatuh/evydence'}}}
        config_descriptor = blob(json.dumps(config).encode(), 'application/vnd.oci.image.config.v1+json')
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                    'config': config_descriptor, 'layers': [layer]}
        descriptor = blob(json.dumps(manifest).encode(), manifest['mediaType'])
        files['index.json'] = json.dumps({'schemaVersion': 2, 'manifests': [descriptor]}).encode()
        if compatibility:
            files['manifest.json'] = json.dumps([{
                'Config': 'blobs/sha256/' + config_descriptor['digest'][7:],
                'Layers': ['blobs/sha256/' + layer['digest'][7:]], 'RepoTags': [IMAGE],
            }]).encode()
        if extra is not None:
            files[extra] = b'extra'
        if corrupt_layer:
            files['blobs/sha256/' + layer['digest'][7:]] += b'substituted'
        archive = root / 'image.oci.tar'
        with tarfile.open(archive, 'w') as output:
            for name, raw in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                output.addfile(item, io.BytesIO(raw))
        return archive, descriptor['digest']

    def inspect(self, archive, digest):
        return release_oci.inspect(archive, IMAGE, digest, COMMIT)

    def test_actual_manifest_config_and_layers_bind_to_one_supported_image_subject(self):
        archive, digest = self.fixture()
        subject = self.inspect(archive, digest)
        self.assertEqual(subject['name'], IMAGE)
        self.assertEqual(subject['sha256'], digest.removeprefix('sha256:'))
        self.assertEqual(subject['kind'], 'container')
        self.assertEqual(subject['platform'], 'linux/amd64')
        self.assertNotIn('CANARY', json.dumps(subject))

    def test_wrong_expected_manifest_and_corrupted_blob_fail(self):
        archive, digest = self.fixture()
        with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
            self.inspect(archive, 'sha256:' + '0' * 64)
        archive, digest = self.fixture(corrupt_layer=True)
        with self.assertRaises(ValueError):
            self.inspect(archive, digest)

    def test_single_image_docker_compatibility_index_keeps_the_same_subject(self):
        archive, digest = self.fixture(compatibility=True)
        subject = self.inspect(archive, digest)
        self.assertEqual(subject, {'name': IMAGE, 'kind': 'container', 'sha256': digest[7:],
                                   'bytes': subject['bytes'], 'platform': 'linux/amd64', 'source_commit': COMMIT})
        self.assertGreater(subject['bytes'], 0)

    def test_wrong_platform_and_layer_diff_id_fail(self):
        for values in [{'platform': 'arm64'}, {'wrong_diff_id': True}]:
            with self.subTest(values=values):
                archive, digest = self.fixture(**values)
                with self.assertRaises(ValueError):
                    self.inspect(archive, digest)

    def test_unsafe_or_unreferenced_envelope_members_fail(self):
        for name in ['../PRIVATE_CANARY', '/PRIVATE_CANARY', 'unexpected-file', 'blobs/sha256/' + '0' * 64]:
            with self.subTest(name=name):
                archive, digest = self.fixture(extra=name)
                with self.assertRaises(ValueError):
                    self.inspect(archive, digest)

    def test_decompression_limit_is_enforced_without_allocating_the_claimed_limit(self):
        archive, digest = self.fixture()
        with mock.patch.object(release_oci, 'MAX_LAYER_EXPANDED_BYTES', 512):
            with self.assertRaises(ValueError):
                self.inspect(archive, digest)

    def test_malformed_compressed_bytes_fail_with_a_safe_parser_error(self):
        archive, digest = self.fixture(malformed_compression=True)
        with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
            self.inspect(archive, digest)


class OCIIndexTests(unittest.TestCase):
    platforms = ('linux/amd64', 'linux/arm64')

    def fixture(self, *, architectures=('amd64', 'arm64'), configure=None,
                change_index=None, change_files=None, compatibility=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}'}

        def blob(value, media):
            raw = value if isinstance(value, bytes) else json.dumps(value).encode()
            sha = hashlib.sha256(raw).hexdigest()
            files['blobs/sha256/' + sha] = raw
            return {'mediaType': media, 'digest': 'sha256:' + sha, 'size': len(raw)}

        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode='w') as layer:
            item = tarfile.TarInfo('etc/public-fixture')
            item.size = 7
            layer.addfile(item, io.BytesIO(b'fixture'))
        raw_layer = layer_buffer.getvalue()
        layer = blob(gzip.compress(raw_layer, mtime=0), release_oci.LAYER_MEDIA + '+gzip')
        descriptors, expected, docker_entries = [], [], []
        for architecture in architectures:
            config = {'os': 'linux', 'architecture': architecture,
                      'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(raw_layer).hexdigest()]},
                      'config': {'Env': ['SECRET=SECRET_CANARY'], 'Labels': {
                          'org.opencontainers.image.revision': COMMIT,
                          'org.opencontainers.image.version': IMAGE.rsplit(':', 1)[1],
                          'org.opencontainers.image.source': 'https://github.com/aatuh/evydence'}}}
            if configure:
                configure(config, architecture)
            config_descriptor = blob(config, release_oci.CONFIG_MEDIA)
            manifest = {'schemaVersion': 2, 'mediaType': release_oci.MANIFEST_MEDIA,
                        'config': config_descriptor, 'layers': [layer]}
            descriptor = blob(manifest, release_oci.MANIFEST_MEDIA)
            descriptor['platform'] = {'os': 'linux', 'architecture': architecture}
            descriptors.append(descriptor)
            expected.append({'name': IMAGE, 'kind': 'container', 'sha256': descriptor['digest'][7:],
                             'bytes': descriptor['size'], 'platform': 'linux/' + architecture,
                             'source_commit': COMMIT})
            docker_entries.append({'Config': 'blobs/sha256/' + config_descriptor['digest'][7:],
                                   'Layers': ['blobs/sha256/' + layer['digest'][7:]], 'RepoTags': [IMAGE]})
        index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                 'manifests': descriptors}
        if change_index:
            change_index(index)
        root = blob(index, index['mediaType'])
        files['index.json'] = json.dumps({'schemaVersion': 2, 'manifests': [root]}).encode()
        if compatibility:
            files['manifest.json'] = json.dumps(docker_entries).encode()
        if change_files:
            change_files(files)
        archive = Path(temporary.name) / 'image.oci.tar'
        with tarfile.open(archive, 'w') as output:
            for name, raw in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                output.addfile(item, io.BytesIO(raw))
        return archive, root['digest'], sorted(expected, key=lambda item: item['platform'])

    def inspect(self, archive, digest, platforms=None):
        return release_oci.inspect_index(archive, IMAGE, digest, COMMIT,
                                         platforms=self.platforms if platforms is None else platforms)

    def test_index_and_every_child_are_bound_to_the_requested_source_and_platforms(self):
        for compatibility in (False, True):
            with self.subTest(compatibility=compatibility):
                archive, digest, expected = self.fixture(compatibility=compatibility)
                with mock.patch.object(tarfile.TarFile, 'extractall', side_effect=AssertionError('no extraction')):
                    result = self.inspect(archive, digest)
                self.assertEqual(result['name'], IMAGE)
                self.assertEqual(result['kind'], 'container-index')
                self.assertEqual(result['sha256'], digest[7:])
                self.assertEqual(result['source_commit'], COMMIT)
                self.assertGreater(result['bytes'], 0)
                self.assertEqual(result['images'], expected)
                self.assertNotIn('CANARY', json.dumps(result))

    def test_matrix_order_is_canonical_and_arm64_v8_is_accepted(self):
        def variant(index):
            for descriptor in index['manifests']:
                descriptor['platform']['variant'] = {'amd64': 'v1', 'arm64': 'v8'}[descriptor['platform']['architecture']]
        archive, digest, expected = self.fixture(architectures=('arm64', 'amd64'), change_index=variant,
            configure=lambda c, a: c.update(variant={'amd64': 'v1', 'arm64': 'v8'}[a]))
        self.assertEqual(self.inspect(archive, digest)['images'], expected)

    def test_missing_duplicate_extra_or_unrequested_platforms_fail(self):
        for architectures in [('amd64',), ('amd64', 'amd64'), ('amd64', 'arm64', 's390x'), ('amd64', 's390x')]:
            with self.subTest(architectures=architectures):
                archive, digest, _ = self.fixture(architectures=architectures)
                with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                    self.inspect(archive, digest)

    def test_invalid_requested_matrices_fail_before_opening_an_archive(self):
        for platforms in [(), ('linux/amd64', 'linux/amd64'), ('windows/amd64',),
                          ('linux/s390x',), 'linux/amd64', {'linux/amd64'}, (None,)]:
            with self.subTest(platforms=platforms):
                with mock.patch.object(release_oci.release_artifacts, 'regular_file') as reader:
                    with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                        self.inspect('unused', 'sha256:' + '0' * 64, platforms)
                    reader.assert_not_called()

    def test_second_image_labels_config_platform_and_expanded_digest_are_verified(self):
        changes = [lambda c: c.update(architecture='amd64'),
                   lambda c: c.update(os='windows'),
                   lambda c: c['config']['Labels'].update({'org.opencontainers.image.revision': 'b' * 40}),
                   lambda c: c['config']['Labels'].update({'org.opencontainers.image.version': 'different'}),
                   lambda c: c['config']['Labels'].update({'org.opencontainers.image.source': 'https://github.com/other/project'}),
                   lambda c: c['rootfs'].update(diff_ids=['sha256:' + '0' * 64]),
                   lambda c: c.update(variant='v9')]
        for number, change in enumerate(changes):
            with self.subTest(change=number):
                archive, digest, _ = self.fixture(configure=lambda c, a: change(c) if a == 'arm64' else None)
                with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                    self.inspect(archive, digest)

    def test_invalid_descriptor_platform_and_nested_or_attestation_entries_fail(self):
        changes = [lambda d: d.pop('platform'), lambda d: d.update(platform=None),
                   lambda d: d['platform'].update(variant='v9'),
                   lambda d: d['platform'].update({'os.features': ['unsupported']}),
                   lambda d: d.update(mediaType='application/vnd.oci.image.index.v1+json'),
                   lambda d: d['platform'].update(os='unknown', architecture='unknown'),
                   lambda d: d.update(size=True)]
        for number, change in enumerate(changes):
            with self.subTest(change=number):
                archive, digest, _ = self.fixture(change_index=lambda i: change(i['manifests'][1]))
                with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                    self.inspect(archive, digest)

    def test_expected_root_digest_and_all_child_blob_bytes_are_verified(self):
        archive, digest, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
            self.inspect(archive, 'sha256:' + '0' * 64)
        def corrupt(files):
            name = next(name for name, raw in files.items() if b'"architecture": "arm64"' in raw and b'rootfs' in raw)
            files[name] += b'changed'
        archive, digest, _ = self.fixture(change_files=corrupt)
        with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
            self.inspect(archive, digest)

    def test_expansion_limit_applies_across_all_images_including_shared_layers(self):
        archive, digest, _ = self.fixture()
        with mock.patch.object(release_oci, 'MAX_TOTAL_EXPANDED_BYTES', 15000):
            with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                self.inspect(archive, digest)

    def test_missing_or_unreferenced_child_blobs_and_unsafe_archive_paths_fail(self):
        def missing(files):
            name = next(name for name, raw in files.items() if b'"architecture": "arm64"' in raw and b'rootfs' in raw)
            del files[name]
        for change in [missing, lambda f: f.update({'../PRIVATE_CANARY': b'fixture'}),
                       lambda f: f.update({'blobs/sha256/' + hashlib.sha256(b'extra').hexdigest(): b'extra'})]:
            archive, digest, _ = self.fixture(change_files=change)
            with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                self.inspect(archive, digest)

    def test_docker_compatibility_index_cannot_hide_a_second_image(self):
        changes = [lambda v: v[1].update(Layers=[]), lambda v: v.pop(),
                   lambda v: v.append(v[0]), lambda v: v.__setitem__(1, v[0]),
                   lambda v: v[1].update(RepoTags=['ghcr.io/other/project:wrong'])]
        for number, change in enumerate(changes):
            with self.subTest(change=number):
                def change_files(files):
                    value = json.loads(files['manifest.json'])
                    change(value)
                    files['manifest.json'] = json.dumps(value).encode()
                archive, digest, _ = self.fixture(compatibility=True, change_files=change_files)
                with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
                    self.inspect(archive, digest)

    def test_legacy_single_manifest_reader_does_not_silently_accept_an_index(self):
        archive, digest, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, '^invalid release OCI payload$'):
            release_oci.inspect(archive, IMAGE, digest, COMMIT)


if __name__ == '__main__':
    unittest.main()
