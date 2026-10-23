#!/usr/bin/env python3
"""Build-tool archive integrity, path, resource and network regressions."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import dependency_build_tools as tools

ROOT = Path(__file__).resolve().parents[1]


def archive(entries=None, *, name='helm'):
    prefix = 'linux-amd64/' if name == 'helm' else ''
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as target:
        for path, value in entries if entries is not None else [
                (prefix + name, b'unexecuted binary'), (prefix + 'LICENSE', b'license text'),
                (prefix + 'NOTICE', b'notice text')]:
            entry = tarfile.TarInfo(path)
            if isinstance(value, bytes):
                entry.size = len(value)
                target.addfile(entry, io.BytesIO(value))
            else:
                entry.type, entry.linkname = value
                target.addfile(entry)
    return gzip.compress(output.getvalue(), mtime=0)


def component(raw, name='helm'):
    rows = tools.archive_tools((ROOT / 'release/support-matrix.json').read_bytes())
    row = next(row for row in rows if row['name'] == name)
    row['source']['sha256'] = hashlib.sha256(raw).hexdigest()
    return row


class ArchiveTests(unittest.TestCase):
    def test_policy_selections_use_exact_pinned_archive_sources(self):
        rows = tools.archive_tools((ROOT / 'release/support-matrix.json').read_bytes())
        self.assertEqual([row['name'] for row in rows], ['helm', 'oasdiff'])
        self.assertEqual(rows[0]['source']['url'], 'https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz')
        self.assertEqual(rows[1]['source']['url'], 'https://github.com/oasdiff/oasdiff/releases/download/v1.29.1/oasdiff_1.29.1_linux_amd64.tar.gz')
        self.assertTrue(all(row['license'] is None for row in rows))

    def test_checksum_verified_archives_yield_binary_and_root_notice_digests_without_extraction(self):
        for name in ['helm', 'oasdiff']:
            with self.subTest(name=name):
                raw = archive(name=name)
                observation, files = tools.observe(raw, component(raw, name))
                self.assertEqual(observation['verification'], 'sha256-verified')
                self.assertEqual(observation['binary_sha256'], hashlib.sha256(b'unexecuted binary').hexdigest())
                self.assertEqual([file['file'] for file in files], ['LICENSE', 'NOTICE'])
                self.assertEqual([file['kind'] for file in files], ['license', 'notice'])
                self.assertTrue(all(hashlib.sha256(file['content']).hexdigest() == file['sha256'] for file in files))

    def test_bad_digest_or_source_is_rejected_before_archive_parsing(self):
        raw = archive()
        for change in [('sha256', '0' * 64), ('sha256', None),
                       ('url', 'https://SECRET_CANARY.invalid/file'), ('platform', 'windows/amd64')]:
            row = component(raw); row['source'][change[0]] = change[1]
            with self.subTest(field=change[0]), patch.object(tools.gzip, 'GzipFile') as decoder:
                with self.assertRaises(tools.BuildToolError) as failure:
                    tools.observe(raw, row)
                decoder.assert_not_called()
                self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_traversal_conflicting_wrappers_duplicate_aliases_and_selected_links_fail(self):
        for entry in [('../outside', b'x'), ('/linux-amd64/LICENSE', b'x'),
                      ('linux-amd64/../LICENSE', b'x'), ('other/LICENSE', b'x'),
                      ('linux-amd64/LICENSE', (tarfile.SYMTYPE, '/SECRET_CANARY')),
                      ('linux-amd64/helm', (tarfile.LNKTYPE, 'other'))]:
            raw = archive([('linux-amd64/helm', b'binary'), entry])
            with self.subTest(path=entry[0]), self.assertRaises(tools.BuildToolError):
                tools.observe(raw, component(raw))
        raw = archive([('linux-amd64/helm', b'binary'), ('linux-amd64/./LICENSE', b'one'),
                       ('linux-amd64/LICENSE', b'two')])
        with self.assertRaises(tools.BuildToolError):
            tools.observe(raw, component(raw))

    def test_missing_binary_and_corrupted_or_truncated_gzip_fail(self):
        raw = archive()
        for changed in [archive([]), archive([('linux-amd64/LICENSE', b'license')]),
                        raw[:-3], raw + b'junk', b'not gzip']:
            with self.subTest(length=len(changed)), self.assertRaises(tools.BuildToolError):
                tools.observe(changed, component(changed))

    def test_license_absence_and_nested_notice_scope_are_explicit(self):
        raw = archive([('linux-amd64/helm', b'binary'), ('linux-amd64/vendor/LICENSE', b'nested')])
        observation, files = tools.observe(raw, component(raw))
        self.assertEqual(files, [])
        self.assertEqual(observation['verification'], 'sha256-verified')

    def test_compressed_expanded_member_and_license_limits_fail(self):
        raw = archive()
        for constant, limit in [('MAX_ARCHIVE_BYTES', len(raw) - 1), ('MAX_EXPANDED_BYTES', 100),
                                ('MAX_MEMBERS', 1), ('MAX_FILE_BYTES', 3), ('MAX_SELECTED_FILES', 1)]:
            with self.subTest(constant=constant), patch.object(tools, constant, limit):
                with self.assertRaises(tools.BuildToolError):
                    tools.observe(raw, component(raw))


class Response(io.BytesIO):
    status = 200
    headers = {}
    url = 'https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz'

    def geturl(self):
        return self.url


class FetchTests(unittest.TestCase):
    def test_only_verified_bytes_are_saved_in_owned_work(self):
        raw = archive(); row = component(raw)
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(tools, '_open', return_value=Response(raw)) as opener:
                observation, _files = tools.fetch(row, Path(folder))
            opener.assert_called_once_with(row['source']['url'])
            self.assertEqual(observation['verification'], 'sha256-verified')
            self.assertEqual(len(list(Path(folder).iterdir())), 1)
            with patch.object(tools, '_open', return_value=Response(raw + b'tamper')):
                with self.assertRaises(tools.BuildToolError):
                    tools.fetch(row, Path(folder))
            self.assertEqual(len(list(Path(folder).iterdir())), 1)

    def test_bad_responses_limits_redirects_and_existing_files_preserve_owner_data(self):
        raw = archive(); row = component(raw)
        for status, headers, url in [(404, {}, Response.url), (200, {'Content-Encoding': 'gzip'}, Response.url),
                                     (200, {'Content-Length': '9999999999'}, Response.url),
                                     (200, {'Content-Length': str(len(raw) + 1)}, Response.url),
                                     (200, {}, 'https://SECRET_CANARY.invalid/file')]:
            response = Response(raw); response.status, response.headers, response.url = status, headers, url
            with tempfile.TemporaryDirectory() as folder, patch.object(tools, '_open', return_value=response):
                with self.assertRaises(tools.BuildToolError) as failure:
                    tools.fetch(row, Path(folder))
                self.assertEqual(list(Path(folder).iterdir()), [])
                self.assertNotIn('SECRET_CANARY', str(failure.exception))
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / (row['source']['sha256'] + '.tar.gz')
            destination.write_bytes(b'owner data')
            with patch.object(tools, '_open', return_value=Response(raw)), self.assertRaises(tools.BuildToolError):
                tools.fetch(row, Path(folder))
            self.assertEqual(destination.read_bytes(), b'owner data')

    def test_network_reader_ignores_proxies_and_restricts_https_redirect_destinations(self):
        with patch.object(tools.urllib.request, 'build_opener') as build:
            tools._open(Response.url)
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        redirect = next(handler for handler in handlers if isinstance(handler, tools._ReleaseRedirect))
        request = tools.urllib.request.Request('https://github.com/oasdiff/oasdiff/releases/download/v1.29.1/oasdiff_1.29.1_linux_amd64.tar.gz')
        for destination in ['http://release-assets.githubusercontent.com/a', 'https://evil.invalid/a',
                            'https://USER:SECRET_CANARY@release-assets.githubusercontent.com/a',
                            'https://release-assets.githubusercontent.com:443/a']:
            with self.subTest(destination=destination), self.assertRaises(tools.BuildToolError):
                redirect.redirect_request(request, None, 302, 'redirect', {}, destination)
        self.assertIsNotNone(redirect.redirect_request(request, None, 302, 'redirect', {},
                             'https://release-assets.githubusercontent.com/path?signature=PRIVATE_CANARY'))
        helm = tools.urllib.request.Request(Response.url)
        with self.assertRaises(tools.BuildToolError):
            redirect.redirect_request(helm, None, 302, 'redirect', {}, 'https://release-assets.githubusercontent.com/path')

    def test_streaming_transfer_size_and_deadline_fail_before_archive_parsing(self):
        raw = archive(); row = component(raw)
        for setting in ['bytes', 'deadline']:
            with self.subTest(setting=setting), tempfile.TemporaryDirectory() as folder:
                with patch.object(tools, '_open', return_value=Response(raw)), patch.object(tools, 'observe') as observe:
                    with patch.object(tools, 'MAX_ARCHIVE_BYTES', len(raw) - 1) if setting == 'bytes' else patch.object(tools.time, 'monotonic', side_effect=[0, 181]):
                        with self.assertRaises(tools.BuildToolError):
                            tools.fetch(row, Path(folder))
                    observe.assert_not_called()
                    self.assertEqual(list(Path(folder).iterdir()), [])

    def test_github_download_retains_only_initial_url_in_public_observation(self):
        raw = archive(name='oasdiff'); row = component(raw, 'oasdiff')
        response = Response(raw)
        response.url = 'https://release-assets.githubusercontent.com/path?signature=PRIVATE_CANARY'
        with tempfile.TemporaryDirectory() as folder, patch.object(tools, '_open', return_value=response):
            observation, files = tools.fetch(row, Path(folder))
        self.assertNotIn('PRIVATE_CANARY', str(observation))
        self.assertTrue(files)


if __name__ == '__main__':
    unittest.main()
