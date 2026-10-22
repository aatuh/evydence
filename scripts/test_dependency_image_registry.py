#!/usr/bin/env python3
"""Read-only image identity, digest, platform and HTTP boundary regressions."""
import copy
import hashlib
import io
import json
import tempfile
import unittest
from unittest.mock import patch

import dependency_image_registry as registry


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def descriptor(raw, media):
    return {'mediaType': media, 'size': len(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}


def fixture():
    manifest = {'schemaVersion': 2, 'mediaType': registry.OCI_MANIFEST,
                'config': descriptor(b'config', registry.OCI_CONFIG),
                'layers': [descriptor(b'layer', registry.OCI_LAYER + '+gzip')]}
    raw = encoded(manifest); selected = descriptor(raw, registry.OCI_MANIFEST)
    selected['platform'] = {'os': 'linux', 'architecture': 'amd64'}
    root = encoded({'schemaVersion': 2, 'mediaType': registry.OCI_INDEX, 'manifests': [selected]})
    return root, raw


class IdentityTests(unittest.TestCase):
    def test_registry_names_and_digest_or_explicit_tag_are_normalized(self):
        digest = 'sha256:' + 'a' * 64
        result = registry.reference('alpine:3.23@' + digest)
        self.assertEqual(result, {'name': 'docker.io/library/alpine', 'registry': 'docker.io', 'repository': 'library/alpine', 'tag': '3.23', 'digest': digest})
        self.assertEqual(registry.reference('docker://ghcr.io/ossf/scorecard-action:v2.4.3')['name'], 'ghcr.io/ossf/scorecard-action')

    def test_credentials_queries_traversal_dynamic_and_unsupported_hosts_or_digests_fail(self):
        for value in ['alpine', 'https://SECRET_CANARY@ghcr.io/a/b:v1', 'localhost:5000/image:v1',
                      'ghcr.io/a/../b:v1', 'ghcr.io/a/b:v1?secret=PRIVATE_CANARY', '${IMAGE}',
                      'alpine@sha1:abc', 'alpine@sha256:' + 'a' * 63, 'ghcr.io/A/b:v1']:
            with self.subTest(value=value), self.assertRaises(registry.ImageRegistryError) as failure:
                registry.reference(value)
            self.assertNotIn('CANARY', str(failure.exception))


class ResolutionTests(unittest.TestCase):
    def resolve(self, root, manifest, *, value=None, change=None):
        digest = 'sha256:' + hashlib.sha256(root).hexdigest()
        row = registry.reference(value or 'alpine:3.23@' + digest)
        replies = [root, manifest] if json.loads(root).get('mediaType') in registry.INDEXES else [root]
        if change: replies = change(replies)
        with patch.object(registry, 'token', return_value='PRIVATE_CANARY'):
            with patch.object(registry, 'read', side_effect=[(raw, {}) for raw in replies]) as reader:
                result = registry.resolve(row)
        return result, reader

    def test_index_and_selected_manifest_are_digest_bound_without_fetching_layers_or_config(self):
        root, manifest = fixture()
        result, reader = self.resolve(root, manifest)
        self.assertEqual(result['root_digest'], 'sha256:' + hashlib.sha256(root).hexdigest())
        self.assertEqual(result['manifest_digest'], 'sha256:' + hashlib.sha256(manifest).hexdigest())
        self.assertEqual(result['platform_evidence'], 'index-assertion')
        self.assertEqual(result['requested_platform'], 'linux/amd64')
        self.assertEqual(reader.call_count, 2)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        self.assertEqual(result['config']['digest'], descriptor(b'config', registry.OCI_CONFIG)['digest'])

    def test_tag_resolution_remains_mutable_and_single_manifests_do_not_prove_platform(self):
        _root, manifest = fixture()
        result, reader = self.resolve(manifest, manifest, value='ghcr.io/ossf/scorecard-action:v2.4.3')
        self.assertTrue(result['mutable_reference'])
        self.assertEqual(result['platform_evidence'], 'not-observed')
        self.assertEqual(reader.call_count, 1)

    def test_mismatched_root_or_child_bytes_and_declared_size_fail(self):
        root, manifest = fixture()
        for value in ['alpine@sha256:' + '0' * 64, None]:
            with self.subTest(value=value), self.assertRaises(registry.ImageRegistryError):
                self.resolve(root, manifest, value=value, change=lambda replies: [replies[0], replies[-1] + b'tamper'])
        data = json.loads(root); data['manifests'][0]['size'] += 1
        with self.assertRaises(registry.ImageRegistryError): self.resolve(encoded(data), manifest)

    def test_ambiguous_missing_platform_invalid_schema_and_descriptor_urls_fail(self):
        root, manifest = fixture()
        for change in ['duplicate', 'wrong-platform', 'schema', 'urls']:
            data = json.loads(root)
            if change == 'duplicate': data['manifests'].append(copy.deepcopy(data['manifests'][0]))
            if change == 'wrong-platform': data['manifests'][0]['platform']['architecture'] = 'arm64'
            if change == 'schema': data['schemaVersion'] = True
            if change == 'urls': data['manifests'][0]['urls'] = ['https://SECRET_CANARY.invalid']
            with self.subTest(change=change), self.assertRaises(registry.ImageRegistryError): self.resolve(encoded(data), manifest)
        data = json.loads(manifest); data['layers'][0]['urls'] = ['https://SECRET_CANARY.invalid']
        with self.assertRaises(registry.ImageRegistryError): self.resolve(encoded(data), encoded(data))

    def test_layer_counts_compressed_size_budgets_and_malformed_json_fail(self):
        _root, manifest = fixture()
        for constant, limit in [('MAX_LAYERS', 0), ('MAX_IMAGE_BYTES', 3), ('MAX_JSON_BYTES', 3)]:
            with self.subTest(constant=constant), patch.object(registry, constant, limit), self.assertRaises(registry.ImageRegistryError):
                self.resolve(manifest, manifest)
        raw = b'{"schemaVersion":2,"schemaVersion":2}'
        with self.assertRaises(registry.ImageRegistryError): self.resolve(raw, raw)


class Response(io.BytesIO):
    status = 200
    headers = {}
    def geturl(self): return 'https://registry-1.docker.io/v2/library/alpine/manifests/3.23'


class HTTPTests(unittest.TestCase):
    def test_reader_uses_get_with_no_proxy_and_rejects_redirects_without_leaking_tokens(self):
        url = Response(b'').geturl()
        with patch.object(registry.urllib.request, 'build_opener') as build:
            build.return_value.open.return_value = Response(b'{}')
            self.assertEqual(registry.read(url, bearer='PRIVATE_CANARY')[0], b'{}')
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.method, 'GET')
        self.assertEqual(request.get_header('Authorization'), 'Bearer PRIVATE_CANARY')
        redirect = next(value for value in handlers if isinstance(value, registry.NoRedirect))
        with self.assertRaises(registry.ImageRegistryError):
            redirect.redirect_request(request, None, 302, 'redirect', {}, 'https://SECRET_CANARY.invalid')

    def test_bad_status_encoding_length_final_url_and_byte_budget_fail(self):
        url = Response(b'').geturl()
        for status, headers, final in [(403, {}, url), (200, {'Content-Encoding': 'gzip'}, url),
                                      (200, {'Content-Length': '9999999999'}, url),
                                      (200, {'Content-Length': '4'}, url), (200, {}, 'https://SECRET_CANARY.invalid')]:
            response = Response(b'{}'); response.status, response.headers = status, headers
            response.geturl = lambda: final
            with self.subTest(status=status, headers=headers), patch.object(registry.urllib.request, 'build_opener') as build:
                build.return_value.open.return_value = response
                with self.assertRaises(registry.ImageRegistryError) as failure: registry.read(url, bearer='PRIVATE_CANARY')
                self.assertNotIn('CANARY', str(failure.exception))

    def test_anonymous_pull_token_uses_only_fixed_issuer_scope_and_rejects_header_injection(self):
        row = registry.reference('alpine:3.23')
        with patch.object(registry, 'read', return_value=(b'{"token":"ANONYMOUS_TOKEN"}', {})) as read:
            self.assertEqual(registry.token(row), 'ANONYMOUS_TOKEN')
        self.assertTrue(read.call_args.args[0].startswith('https://auth.docker.io/token?'))
        self.assertIn('repository%3Alibrary%2Falpine%3Apull', read.call_args.args[0])
        for raw in [b'{"token":"bad\\r\\nheader"}', b'{"token":null}', b'{"token":"one","access_token":"different"}']:
            with self.subTest(raw=raw), patch.object(registry, 'read', return_value=(raw, {})):
                with self.assertRaises(registry.ImageRegistryError): registry.token(row)


if __name__ == '__main__':
    unittest.main()
