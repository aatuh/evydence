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
                malformed_compression=False):
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


if __name__ == '__main__':
    unittest.main()
