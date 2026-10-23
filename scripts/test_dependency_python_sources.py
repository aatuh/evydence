#!/usr/bin/env python3
"""Pinned Python artifact verification and metadata/license observation tests."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile

import dependency_python_sources as sources

VERSION = '6.0.3'
CORE = b'Metadata-Version: 2.4\nName: PyYAML\nVersion: 6.0.3\nLicense: MIT\n\nPRIVATE_CANARY'
WHEEL = 'pyyaml-6.0.3-cp314-cp314-manylinux2014_x86_64.whl'
SOURCE = 'pyyaml-6.0.3.tar.gz'


def payload(kind='sdist', entries=None):
    buffer = io.BytesIO()
    if kind == 'sdist':
        entries = entries if entries is not None else [('pyyaml-6.0.3/PKG-INFO', CORE),
                                                        ('pyyaml-6.0.3/LICENSE', b'license bytes')]
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, content in entries:
                member = tarfile.TarInfo(name)
                if isinstance(content, bytes):
                    member.size = len(content); archive.addfile(member, io.BytesIO(content))
                else:
                    member.type, member.linkname = content; archive.addfile(member)
        return gzip.compress(buffer.getvalue(), mtime=0)
    entries = entries if entries is not None else [('pyyaml-6.0.3.dist-info/METADATA', CORE),
                                                    ('pyyaml-6.0.3.dist-info/licenses/LICENSE', b'license bytes')]
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, content in entries:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive.writestr(name, content)
    return buffer.getvalue()


def artifact(raw, kind='sdist'):
    filename = SOURCE if kind == 'sdist' else WHEEL
    return {'filename': filename, 'packagetype': kind, 'size': len(raw), 'yanked': False,
            'url': 'https://files.pythonhosted.org/packages/aa/bb/' + 'c' * 60 + '/' + filename,
            'digests': {'sha256': hashlib.sha256(raw).hexdigest()},
            'upload_time_iso_8601': '2025-09-25T21:33:16.546886Z'}


def registry(rows):
    return json.dumps({'info': {'name': 'PyYAML', 'version': VERSION, 'requires_dist': None},
                       'urls': rows}).encode()


class MetadataTests(unittest.TestCase):
    def test_registry_selects_exactly_the_pinned_artifact_set(self):
        raw = payload(); row = artifact(raw)
        selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('digests', selected[0])
        self.assertEqual(selected[0]['published_at'], '2025-09-25T21:33:16.546886Z')

    def test_registry_identity_hash_coverage_duplicates_yanking_and_unsafe_urls_fail(self):
        raw = payload(); row = artifact(raw); digest = row['digests']['sha256']
        mutations = [('filename', '../SECRET_CANARY'), ('url', 'https://SECRET_CANARY@files.pythonhosted.org/x'),
                     ('url', row['url'] + '?token=SECRET_CANARY'), ('url', row['url'].replace('https:', 'http:')),
                     ('url', row['url'].replace('files.pythonhosted.org', 'evil.invalid')),
                     ('size', True), ('size', 0), ('yanked', True), ('yanked', 0),
                     ('packagetype', 'executable'), ('upload_time_iso_8601', 'not-a-time')]
        for key, value in mutations:
            changed = copy.deepcopy(row); changed[key] = value
            with self.subTest(key=key), self.assertRaises(sources.PythonSourceError) as failure:
                sources.select_artifacts(registry([changed]), VERSION, [digest])
            self.assertNotIn('SECRET_CANARY', str(failure.exception))
        for rows, hashes in [([], [digest]), ([row, row], [digest]), ([row], ['a' * 64])]:
            with self.assertRaises(sources.PythonSourceError):
                sources.select_artifacts(registry(rows), VERSION, hashes)
        for key, value in [('name', 'other'), ('version', '9.9.9'), ('requires_dist', ['other>=1'])]:
            body = json.loads(registry([row])); body['info'][key] = value
            with self.assertRaises(sources.PythonSourceError):
                sources.select_artifacts(json.dumps(body).encode(), VERSION, [digest])

    def test_registry_duplicate_keys_nonfinite_values_and_oversized_input_fail(self):
        for raw in [b'{"info":{},"info":{}}', b'{"x":NaN}', b'{"x":1e999}', b'[]', b'\xff', b'x' * (4*1024*1024+1)]:
            with self.assertRaises(sources.PythonSourceError):
                sources.select_artifacts(raw, VERSION, ['a'*64])


class ArchiveTests(unittest.TestCase):
    def test_legacy_distribution_case_keeps_exact_url_and_hash_bindings(self):
        raw = payload('bdist_wheel', [('PyYAML-6.0.3.dist-info/METADATA', CORE),
                                        ('PyYAML-6.0.3.dist-info/LICENSE', b'legacy license')])
        row = artifact(raw, 'bdist_wheel')
        row['filename'] = row['filename'].replace('pyyaml-', 'PyYAML-')
        row['url'] = row['url'].replace('pyyaml-', 'PyYAML-')
        selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
        observation, files = sources.observe(raw, selected, VERSION)
        self.assertEqual(observation['license'], 'MIT')
        self.assertEqual(selected['url'], row['url'])
        self.assertEqual(len(files), 1)

    def test_source_and_wheel_metadata_and_license_bytes_are_observed(self):
        for kind in ['sdist', 'bdist_wheel']:
            raw = payload(kind); row = artifact(raw, kind)
            selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
            observation, files = sources.observe(raw, selected, VERSION)
            self.assertEqual(observation['license'], 'MIT')
            self.assertEqual(observation['metadata_sha256'], hashlib.sha256(CORE).hexdigest())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]['content'], b'license bytes')
            self.assertNotIn('PRIVATE_CANARY', json.dumps(observation))

    def test_integrity_precedes_any_archive_parser(self):
        raw = payload(); row = artifact(raw)
        selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
        with patch.object(sources.tarfile, 'open') as parser:
            with self.assertRaises(sources.PythonSourceError):
                sources.observe(raw + b'tamper', selected, VERSION)
            parser.assert_not_called()

    def test_core_metadata_requires_identity_unique_headers_and_no_new_dependencies(self):
        for content in [CORE.replace(b'Name: PyYAML', b'Name: other'),
                        CORE.replace(b'Version: 6.0.3', b'Version: 9.9.9'),
                        CORE.replace(b'Name: PyYAML', b'Name: PyYAML\nName: other'),
                        CORE.replace(b'\n\n', b'\nRequires-Dist: other>=1\n\n'),
                        CORE.replace(b'License: MIT', b'License: MIT\nLicense: ISC'),
                        CORE.replace(b'Metadata-Version: 2.4', b'Metadata-Version: 99.0'), b'\xff']:
            raw = payload(entries=[('pyyaml-6.0.3/PKG-INFO', content)])
            row = artifact(raw); selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
            with self.assertRaises(sources.PythonSourceError):
                sources.observe(raw, selected, VERSION)

    def test_unknown_legacy_license_is_not_inferred_from_classifiers_or_prose(self):
        raw = payload(entries=[('pyyaml-6.0.3/PKG-INFO', CORE.replace(b'License: MIT', b'License: See the license file'))])
        row = artifact(raw); selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
        observation, files = sources.observe(raw, selected, VERSION)
        self.assertIsNone(observation['license'])
        self.assertEqual(files, [])

    def test_traversal_duplicate_selected_entries_and_links_fail_without_extraction(self):
        for entry in [('../outside', b'x'), ('/absolute', b'x'), ('pyyaml-6.0.3/../LICENSE', b'x'),
                      ('other/LICENSE', b'x'), ('pyyaml-6.0.3/LICENSE', (tarfile.SYMTYPE, '/PRIVATE_CANARY')),
                      ('pyyaml-6.0.3/PKG-INFO', CORE)]:
            raw = payload(entries=[('pyyaml-6.0.3/PKG-INFO', CORE), entry])
            row = artifact(raw); selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
            with self.assertRaises(sources.PythonSourceError):
                sources.observe(raw, selected, VERSION)
        raw = payload('bdist_wheel', [('pyyaml-6.0.3.dist-info/METADATA', CORE), ('../LICENSE', b'x')])
        row = artifact(raw, 'bdist_wheel'); selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
        with self.assertRaises(sources.PythonSourceError):
            sources.observe(raw, selected, VERSION)

    def test_archive_member_expansion_and_file_budgets_fail(self):
        for kind in ['sdist', 'bdist_wheel']:
            raw = payload(kind); row = artifact(raw, kind)
            selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
            for constant, value in [('MAX_FILE_BYTES', 3), ('MAX_MEMBERS', 1), ('MAX_EXPANDED_BYTES', 10)]:
                with self.subTest(kind=kind, constant=constant), patch.object(sources, constant, value):
                    with self.assertRaises(sources.PythonSourceError):
                        sources.observe(raw, selected, VERSION)

    def test_selected_wheel_symlinks_duplicates_and_bad_crc_fail(self):
        link = zipfile.ZipInfo('pyyaml-6.0.3.dist-info/licenses/LICENSE')
        link.create_system = 3; link.external_attr = 0o120777 << 16
        for entries in [[('pyyaml-6.0.3.dist-info/METADATA', CORE), (link, b'/PRIVATE_CANARY')],
                        [('pyyaml-6.0.3.dist-info/METADATA', CORE)] * 2]:
            raw = payload('bdist_wheel', entries)
            row = artifact(raw, 'bdist_wheel')
            selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
            with self.assertRaises(sources.PythonSourceError):
                sources.observe(raw, selected, VERSION)
        for kind in ['sdist', 'bdist_wheel']:
            raw = bytearray(payload(kind))
            if kind == 'sdist':
                raw[-8] ^= 255
            else:
                raw[raw.index(b'license bytes')] ^= 255
            raw = bytes(raw); row = artifact(raw, kind)
            selected = sources.select_artifacts(registry([row]), VERSION, [row['digests']['sha256']])[0]
            with self.assertRaises(sources.PythonSourceError):
                sources.observe(raw, selected, VERSION)


class Response(io.BytesIO):
    status = 200
    headers = {}
    def geturl(self):
        return 'https://pypi.org/pypi/PyYAML/6.0.3/json'


class TransportTests(unittest.TestCase):
    def test_http_is_bounded_and_refuses_redirects_encoding_status_and_wrong_lengths(self):
        url = Response(b'').geturl()
        with patch.object(sources, '_open', return_value=Response(b'body')):
            self.assertEqual(sources.download(url, 10), b'body')
        responses = [Response(b'body') for _ in range(5)]
        responses[0].status = 302
        responses[1].geturl = lambda: 'https://evil.invalid'
        responses[2].headers = {'Content-Length': '5'}
        responses[3].headers = {'Content-Encoding': 'gzip'}
        responses[4].headers = {'Content-Length': '-1'}
        for response in responses:
            with patch.object(sources, '_open', return_value=response), self.assertRaises(sources.PythonSourceError):
                sources.download(url, 10)
        with patch.object(sources, '_open', return_value=Response(b'body')), self.assertRaises(sources.PythonSourceError):
            sources.download(url, 3)
        with patch.object(sources, '_open', side_effect=OSError('SECRET_CANARY')):
            with self.assertRaises(sources.PythonSourceError) as failure:
                sources.download(url, 10)
            self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_transport_drops_proxies_and_does_not_follow_redirects(self):
        with patch.object(sources.urllib.request, 'build_opener') as builder:
            sources._open(Response(b'').geturl())
        handlers = builder.call_args.args
        self.assertTrue(any(isinstance(item, sources.urllib.request.ProxyHandler) and item.proxies == {} for item in handlers))
        redirect = next(item for item in handlers if isinstance(item, sources.urllib.request.HTTPRedirectHandler))
        with self.assertRaises(sources.PythonSourceError):
            redirect.redirect_request(None, None, 302, '', {}, 'https://evil.invalid')

    def test_fetch_checks_every_pinned_artifact_and_keeps_raw_bodies_out_of_report(self):
        raw = payload(); row = artifact(raw); digest = row['digests']['sha256']
        requirements = ('PyYAML==6.0.3 --hash=sha256:' + digest).encode()
        calls = []
        def download(url, _limit):
            calls.append(url)
            return raw if url == row['url'] else registry([row])
        with tempfile.TemporaryDirectory() as folder, patch.object(sources, 'download', side_effect=download):
            component, files = sources.fetch(requirements, Path(folder))
            self.assertEqual(component['ecosystem'], 'pypi')
            self.assertEqual(component['source']['verification'], 'sha256-verified')
            self.assertEqual(component['license'], 'MIT')
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(files), 1)
            self.assertNotIn('PRIVATE_CANARY', json.dumps(component))
            self.assertEqual(len(list(Path(folder).glob('*.tar.gz'))), 1)

    def test_fetch_preserves_cross_artifact_license_disagreements(self):
        raw_source = payload()
        raw_wheel = payload('bdist_wheel', [('pyyaml-6.0.3.dist-info/METADATA', CORE.replace(b'License: MIT', b'License: ISC'))])
        rows = [artifact(raw_source), artifact(raw_wheel, 'bdist_wheel')]
        requirements = ('PyYAML==6.0.3 ' + ' '.join('--hash=sha256:' + row['digests']['sha256'] for row in rows)).encode()
        bodies = dict(zip([row['url'] for row in rows], [raw_source, raw_wheel]))
        def download(url, _limit):
            return bodies[url] if url in bodies else registry(rows)
        with tempfile.TemporaryDirectory() as folder, patch.object(sources, 'download', side_effect=download) as fetch:
            component, _files = sources.fetch(requirements, Path(folder))
            self.assertEqual(fetch.call_count, 3)
            self.assertIsNone(component['license'])
            self.assertEqual(component['license_status'], 'ambiguous')
            self.assertEqual({row['license'] for row in component['source']['artifacts']}, {'MIT', 'ISC'})

    def test_license_budget_aborts_before_downloading_another_artifact(self):
        raw_source, raw_wheel = payload(), payload('bdist_wheel')
        rows = [artifact(raw_source), artifact(raw_wheel, 'bdist_wheel')]
        requirements = ('PyYAML==6.0.3 ' + ' '.join('--hash=sha256:' + row['digests']['sha256'] for row in rows)).encode()
        bodies = dict(zip([row['url'] for row in rows], [raw_source, raw_wheel]))
        def download(url, _limit):
            return bodies[url] if url in bodies else registry(rows)
        with tempfile.TemporaryDirectory() as folder, patch.object(sources, 'download', side_effect=download) as fetch:
            with patch.object(sources, 'MAX_LICENSE_SET_BYTES', 1, create=True), self.assertRaises(sources.PythonSourceError):
                sources.fetch(requirements, Path(folder))
            self.assertEqual(fetch.call_count, 2)


if __name__ == '__main__':
    unittest.main()
