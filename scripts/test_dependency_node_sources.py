#!/usr/bin/env python3
"""Digest-first npm archive observation without installation or extraction."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import dependency_node_sources as sources


def archive(entries=None, manifest=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as target:
        values = [('package/package.json', json.dumps(manifest or {
            'name': '@scope/alpha', 'version': '1.2.3', 'license': 'MIT',
            'scripts': {'install': 'PRIVATE_CANARY'}}).encode()),
                  ('package/LICENSE', b'license observation'),
                  ('package/NOTICE', b'notice observation')]
        for name, content in values if entries is None else entries:
            item = tarfile.TarInfo(name)
            if isinstance(content, bytes):
                item.size = len(content)
                target.addfile(item, io.BytesIO(content))
            else:
                item.type, item.linkname = content
                target.addfile(item)
    return gzip.compress(buffer.getvalue(), mtime=0)


def component(raw):
    return {'ecosystem': 'npm', 'name': '@scope/alpha', 'version': '1.2.3',
            'license': 'MIT', 'source': {
                'url': 'https://registry.npmjs.org/@scope/alpha/-/alpha-1.2.3.tgz',
                'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()}}


class ArchiveTests(unittest.TestCase):
    def test_verified_bytes_supply_manifest_and_root_license_observations(self):
        raw = archive()
        result, files = sources.observe(raw, component(raw))
        self.assertEqual(result['verification'], 'sha512-verified')
        self.assertEqual(result['license'], 'MIT')
        self.assertEqual(result['declaration_status'], 'matched')
        self.assertEqual([item['file'] for item in files], ['LICENSE', 'NOTICE'])
        self.assertEqual([item['kind'] for item in files], ['license', 'notice'])
        self.assertTrue(all(hashlib.sha256(item['content']).hexdigest() == item['sha256'] for item in files))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_digest_is_verified_before_gzip_or_tar_parsing(self):
        raw = archive()
        with patch.object(sources, 'gzip') as decoder:
            with self.assertRaises(sources.NodeSourceError):
                sources.observe(raw + b'tampering', component(raw))
            decoder.GzipFile.assert_not_called()
        for integrity in ['sha1-anything', 'sha512-INVALID', None]:
            row = component(raw); row['source']['integrity'] = integrity
            with self.subTest(integrity=integrity), self.assertRaises(sources.NodeSourceError):
                sources.observe(raw, row)

    def test_manifest_identity_and_duplicate_json_keys_fail(self):
        for manifest in [{'name': 'different', 'version': '1.2.3'},
                         {'name': '@scope/alpha', 'version': '9.9.9'}]:
            raw = archive(manifest=manifest)
            with self.subTest(manifest=manifest), self.assertRaises(sources.NodeSourceError):
                sources.observe(raw, component(raw))
        for content in [b'{"name":"x","name":"y"}', b'{"x":1e999}', b'[]', b'\xff']:
            raw = archive([('package/package.json', content)])
            with self.subTest(content=content), self.assertRaises(sources.NodeSourceError):
                sources.observe(raw, component(raw))

    def test_license_declaration_disagreement_is_explicit_and_not_admitted(self):
        for expression, status in [('Apache-2.0', 'different'), (None, 'missing'),
                                   ({'type': 'MIT'}, 'unsupported')]:
            raw = archive(manifest={'name': '@scope/alpha', 'version': '1.2.3', 'license': expression})
            observation, _files = sources.observe(raw, component(raw))
            self.assertEqual(observation['declaration_status'], status)
            self.assertEqual(observation['license'], expression if isinstance(expression, str) else None)

    def test_traversal_duplicate_selected_paths_and_selected_links_fail(self):
        manifest = ('package/package.json', b'{"name":"@scope/alpha","version":"1.2.3","license":"MIT"}')
        bad = [('../outside', b'x'), ('/package/LICENSE', b'x'),
               ('package/../LICENSE', b'x'), ('other/LICENSE', b'x'),
               ('package/LICENSE', (tarfile.SYMTYPE, '/PRIVATE_CANARY')),
               ('package/package.json', (tarfile.LNKTYPE, 'elsewhere'))]
        for entry in bad:
            raw = archive([manifest, entry])
            with self.subTest(name=entry[0]), self.assertRaises(sources.NodeSourceError):
                sources.observe(raw, component(raw))
        raw = archive([manifest, ('package/LICENSE', b'one'), ('package/LICENSE', b'two')])
        with self.assertRaises(sources.NodeSourceError):
            sources.observe(raw, component(raw))

    def test_single_wrapper_and_dot_aliases_need_no_extraction_or_code_trust(self):
        raw = archive([('node/package.json', b'{"name":"@scope/alpha","version":"1.2.3","license":"MIT"}'),
                       ('node/./dist/index.js', b'PRIVATE_CANARY'),
                       ('node/dist/index.js', b'ignored code'),
                       ('node/./LICENSE', b'license observation')])
        result, files = sources.observe(raw, component(raw))
        self.assertEqual(result['declaration_status'], 'matched')
        self.assertEqual([item['file'] for item in files], ['LICENSE'])
        raw = archive([('package/package.json', b'{"name":"@scope/alpha","version":"1.2.3"}'),
                       ('package/./LICENSE', b'one'), ('package/LICENSE', b'two')])
        with self.assertRaises(sources.NodeSourceError):
            sources.observe(raw, component(raw))

    def test_nested_licenses_are_not_mislabeled_as_root_license_files(self):
        raw = archive([('package/package.json', b'{"name":"@scope/alpha","version":"1.2.3"}'),
                       ('package/vendor/LICENSE', b'nested'),
                       ('package/native.so', (tarfile.SYMTYPE, 'native.so.1'))])
        result, files = sources.observe(raw, component(raw))
        self.assertEqual(files, [])
        self.assertEqual(result['declaration_status'], 'missing')

    def test_compressed_decompressed_member_and_file_limits_fail(self):
        raw = archive()
        for constant, limit in [('MAX_ARCHIVE_BYTES', len(raw) - 1),
                                ('MAX_EXPANDED_BYTES', 100), ('MAX_MEMBERS', 1),
                                ('MAX_FILE_BYTES', 3), ('MAX_SELECTED_FILES', 1)]:
            with self.subTest(constant=constant), patch.object(sources, constant, limit):
                with self.assertRaises(sources.NodeSourceError):
                    sources.observe(raw, component(raw))

    def test_missing_manifest_invalid_compression_and_crc_fail(self):
        invalid = bytearray(archive()); invalid[10] = 255
        for raw in [archive([]), b'not gzip', archive()[:-5], archive() + b'junk', bytes(invalid)]:
            with self.subTest(length=len(raw)), self.assertRaises(sources.NodeSourceError):
                sources.observe(raw, component(raw))


class Response(io.BytesIO):
    status = 200
    headers = {}

    def geturl(self):
        return 'https://registry.npmjs.org/@scope/alpha/-/alpha-1.2.3.tgz'


class FetchTests(unittest.TestCase):
    def test_fetch_is_serial_bounded_and_persists_only_verified_bytes(self):
        raw = archive()
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(sources, '_open', return_value=Response(raw)) as opener:
                result, _files = sources.fetch(component(raw), Path(folder))
            self.assertEqual(result['verification'], 'sha512-verified')
            self.assertEqual(len(list(Path(folder).iterdir())), 1)
            self.assertEqual(next(Path(folder).iterdir()).read_bytes(), raw)
            self.assertEqual(opener.call_count, 1)

    def test_untrusted_url_is_rejected_before_any_network_or_write(self):
        raw = archive()
        for url in ['http://registry.npmjs.org/alpha', 'https://SECRET_CANARY@registry.npmjs.org/x',
                    'https://registry.npmjs.org.evil/x', 'https://registry.npmjs.org/x?token=SECRET_CANARY',
                    'https://registry.npmjs.org/@scope/alpha/-/other-1.2.3.tgz']:
            row = component(raw); row['source']['url'] = url
            with tempfile.TemporaryDirectory() as folder, patch.object(sources, '_open') as opener:
                with self.assertRaises(sources.NodeSourceError) as failure:
                    sources.fetch(row, Path(folder))
                opener.assert_not_called()
                self.assertEqual(list(Path(folder).iterdir()), [])
                self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_status_redirect_length_encoding_and_integrity_fail_without_publishing(self):
        raw = archive()
        responses = [Response(raw) for _ in range(6)]
        responses[0].status = 302
        responses[1].geturl = lambda: 'https://evil.invalid/SECRET_CANARY'
        responses[2].headers = {'Content-Length': str(len(raw) + 1)}
        responses[3].headers = {'Content-Encoding': 'gzip'}
        responses[4].headers = {'Content-Length': '-1'}
        responses[5] = Response(raw + b'tamper')
        for response in responses:
            with tempfile.TemporaryDirectory() as folder, patch.object(sources, '_open', return_value=response):
                with self.assertRaises(sources.NodeSourceError):
                    sources.fetch(component(raw), Path(folder))
                self.assertEqual(list(Path(folder).iterdir()), [])

    def test_response_budget_and_network_errors_are_safe(self):
        raw = archive()
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(sources, '_open', return_value=Response(raw)), patch.object(sources, 'MAX_ARCHIVE_BYTES', 10):
                with self.assertRaises(sources.NodeSourceError):
                    sources.fetch(component(raw), Path(folder))
            with patch.object(sources, '_open', side_effect=OSError('SECRET_CANARY')):
                with self.assertRaises(sources.NodeSourceError) as failure:
                    sources.fetch(component(raw), Path(folder))
            self.assertNotIn('SECRET_CANARY', str(failure.exception))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_transport_disables_proxies_credentials_and_redirects(self):
        with patch.object(sources.urllib.request, 'build_opener') as builder:
            sources._open('https://registry.npmjs.org/example/-/example-1.0.0.tgz')
        handlers = builder.call_args.args
        self.assertTrue(any(isinstance(item, sources.urllib.request.ProxyHandler) and item.proxies == {} for item in handlers))
        redirect = next(item for item in handlers if isinstance(item, sources.urllib.request.HTTPRedirectHandler))
        with self.assertRaises(sources.NodeSourceError):
            redirect.redirect_request(None, None, 302, 'redirect', {}, 'https://evil.invalid')
        request = builder.return_value.open.call_args.args[0]
        self.assertFalse(any(key.lower() == 'authorization' for key in request.headers))


if __name__ == '__main__':
    unittest.main()
