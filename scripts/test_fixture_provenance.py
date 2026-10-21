#!/usr/bin/env python3
"""Fixture identity, source transformation, coverage and notice regressions."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import fixture_provenance as provenance


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def fixture(root):
    (root / 'testdata').mkdir()
    (root / 'LICENSE').write_bytes(b'project license fixture')
    (root / 'testdata/example.json').write_bytes(b'{"answer":42}\n')
    (root / 'testdata/parser-corpus.v1.json').write_text('{"fixtures":[]}')
    return {'schema': 'evydence-fixture-provenance.v1',
            'notices': [{'id': 'evydence', 'license': 'AGPL-3.0-only', 'path': 'LICENSE',
                         'sha256': sha(b'project license fixture'), 'source': None}],
            'fixtures': [{'id': 'example', 'license': 'AGPL-3.0-only', 'notices': ['evydence'],
                          'files': [{'path': 'testdata/example.json', 'sha256': sha(b'{"answer":42}\n')}],
                          'source': {'kind': 'project', 'introduced_commit': 'a' * 40}}]}


class CatalogTests(unittest.TestCase):
    def test_reader_can_bind_one_immutable_input_set(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root); captured = {}
            def read(folder, name, maximum):
                if name not in captured:captured[name] = provenance.read_bytes(folder, name, maximum)
                return captured[name]
            before = provenance.validate(root, catalog, read_file=read)
            self.assertEqual(set(captured), {'LICENSE', 'testdata/example.json', provenance.CORPUS})
            (root / 'testdata/example.json').write_text('concurrent owner edit')
            self.assertEqual(provenance.validate(root, catalog, read_file=read), before)
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, catalog)

    def test_notice_and_source_note_paths_cannot_read_unrelated_local_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root)
            raw = b'example.json SECRET_CANARY'
            (root / 'private.txt').write_bytes(raw)
            notice = {'id': 'unrelated', 'license': 'AGPL-3.0-only', 'path': 'private.txt',
                      'sha256': sha(raw), 'source': {'repository': 'example/upstream', 'commit': 'b' * 40,
                      'path': 'LICENSE', 'sha256': sha(raw), 'git_blob': blob(raw)}}
            changed = copy.deepcopy(catalog); changed['notices'].append(notice)
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, changed)
            entry = {'path': 'testdata/example.json', 'sha256': sha(b'{"answer":42}\n'),
                     'license': 'AGPL-3.0-only', 'source': 'private.txt'}
            (root / provenance.CORPUS).write_text(json.dumps({'fixtures': [entry]}))
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, catalog)

    def test_project_fixture_and_notice_bytes_are_bound_without_new_license_grants(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root)
            rows = provenance.validate(root, catalog)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['license'], 'AGPL-3.0-only')
            self.assertEqual(rows[0]['source']['verification'], 'local-digests-checked')
            changed = copy.deepcopy(catalog); changed['fixtures'][0]['license'] = 'MIT'
            with self.assertRaises(provenance.ProvenanceError):
                provenance.validate(root, changed)

    def test_changed_missing_unclassified_duplicate_and_symlink_fixtures_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root)
            for modification in ['changed', 'missing', 'new', 'symlink', 'duplicate']:
                with self.subTest(modification=modification):
                    target = root / 'testdata/example.json'
                    target.write_bytes(b'{"answer":42}\n')
                    changed = copy.deepcopy(catalog)
                    if modification == 'changed':target.write_bytes(b'changed')
                    elif modification == 'missing':target.unlink()
                    elif modification == 'new':(root / 'testdata/unclassified.json').write_text('{}')
                    elif modification == 'symlink':target.unlink();target.symlink_to(root / 'LICENSE')
                    else:changed['fixtures'].append(copy.deepcopy(changed['fixtures'][0]))
                    with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, changed)
                    if target.is_symlink():target.unlink()
                    extra = root / 'testdata/unclassified.json'
                    if extra.exists():extra.unlink()

    def test_notice_tampering_unsafe_paths_unknown_fields_and_bad_refs_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root)
            for field, value in [('path', '../SECRET_CANARY'), ('sha256', 'bad'), ('unknown', True)]:
                changed = copy.deepcopy(catalog); changed['notices'][0][field] = value
                with self.subTest(field=field), self.assertRaises(provenance.ProvenanceError) as failure:
                    provenance.validate(root, changed)
                self.assertNotIn('SECRET_CANARY', str(failure.exception))
            (root / 'LICENSE').write_text('tampered')
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, catalog)

    def test_grouping_cannot_relabel_an_existing_project_cc0_declaration(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root)
            name = 'internal/app/parsers/scanners/testdata/generic.json'
            path = root / name;path.parent.mkdir(parents=True);path.write_bytes(b'{}')
            catalog['fixtures'][0]['files'].append({'path': name, 'sha256': sha(b'{}')})
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, catalog)

    def test_source_transformations_preserve_json_types_and_fragment_order(self):
        source = {'repository': 'example/source', 'commit': 'b' * 40, 'path': 'input.json',
                  'sha256': sha(b'{"value":1}'), 'git_blob': blob(b'{"value":1}')}
        source.update(kind='json', canonical_sha256=sha(provenance.canonical_json(b'{"value":1}')))
        provenance.check_transform(source, b'{ "value" : 1 }')
        with self.assertRaises(provenance.ProvenanceError):provenance.check_transform(source, b'{"value":true}')
        for raw in [b'{"value":NaN}', b'{"value":1,"value":2}', b'{"value":1e999}']:
            with self.assertRaises(provenance.ProvenanceError):provenance.canonical_json(raw)
        source = dict(source, kind='bytes'); source.pop('canonical_sha256')
        provenance.check_transform(source, b'{"value":1}')
        with self.assertRaises(provenance.ProvenanceError):provenance.check_transform(source, b'}1:"eulav"{')

    def test_markdown_block_selection_tracks_non_json_fences_and_omits_prose(self):
        raw = b'```text\nnot JSON\n```\n\n```json\n{"answer":42}\n```\n'
        self.assertEqual(provenance.json_block(raw, 0), b'{"answer":42}')
        for index in [True, -1, 1, 1000]:
            with self.subTest(index=index), self.assertRaises(provenance.ProvenanceError):
                provenance.json_block(raw, index)

    def test_corpus_license_and_source_mapping_must_agree_with_catalog(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root)
            (root / 'testdata/SOURCE.md').write_text('example.json is a project fixture')
            manifest = {'fixtures': [{'path': 'testdata/example.json', 'sha256': sha(b'{"answer":42}\n'),
                                     'license': 'AGPL-3.0-only', 'source': 'testdata/SOURCE.md'}]}
            path = root / 'testdata/parser-corpus.v1.json';path.write_text(json.dumps(manifest))
            provenance.validate(root, catalog)
            manifest['fixtures'][0]['license'] = 'CC-BY-3.0';path.write_text(json.dumps(manifest))
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, catalog)

    def test_upstream_license_notice_must_cover_the_same_repository_revision_and_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); catalog = fixture(root); row = catalog['fixtures'][0]
            raw = (root / row['files'][0]['path']).read_bytes()
            row['source'] = {'kind': 'bytes', 'repository': 'example/upstream', 'commit': 'b' * 40,
                             'path': 'example.json', 'sha256': sha(raw), 'git_blob': blob(raw)}
            # A project's own notice cannot establish a copied upstream file's license.
            with self.assertRaises(provenance.ProvenanceError):provenance.validate(root, catalog)
            path = root / 'testdata/licenses/source.LICENSE';path.parent.mkdir();path.write_bytes(b'notice')
            notice = {'id': 'upstream', 'license': 'AGPL-3.0-only', 'path': 'testdata/licenses/source.LICENSE',
                      'sha256': sha(b'notice'), 'source': {'repository': 'example/upstream', 'commit': 'b' * 40,
                      'path': 'LICENSE', 'sha256': sha(b'notice'), 'git_blob': blob(b'notice')}}
            catalog['notices'].append(notice);row['notices'] = ['upstream']
            provenance.validate(root, catalog)
            for key, value in [('repository', 'unrelated/repo'), ('commit', 'c' * 40), ('path', 'unrelated/LICENSE')]:
                changed = copy.deepcopy(catalog); changed['notices'][-1]['source'][key] = value
                with self.subTest(key=key), self.assertRaises(provenance.ProvenanceError):provenance.validate(root, changed)

    def test_repository_catalog_covers_all_fixture_roots_and_corrected_corpus(self):
        root = Path(__file__).resolve().parents[1]
        rows = provenance.validate(root, provenance.load(root))
        self.assertTrue(rows)
        by_path = {item['path']: row for row in rows for item in row['source']['files']}
        expected = {
            'internal/app/parsers/cyclonedx/testdata/official/valid-standard-1.6.json': 'Apache-2.0',
            'internal/app/parsers/spdx/testdata/spdx-2.3-example.json': 'AGPL-3.0-only',
            'internal/app/parsers/vex/testdata/openvex/openvex-spec-minimal.json': 'CC0-1.0',
            'internal/app/parsers/vex/testdata/cyclonedx-vex/official-vex-1.4.json': 'CC0-1.0'}
        for path, license in expected.items():self.assertEqual(by_path[path]['license'], license)


class ProviderTests(unittest.TestCase):
    def test_upstream_cache_budget_stops_before_the_next_fetch(self):
        raw = b'four'
        first = {'repository': 'example/source', 'commit': 'b' * 40, 'path': 'LICENSE',
                 'sha256': sha(raw), 'git_blob': blob(raw)}
        second = dict(first, path='OTHER')
        catalog = {'notices': [{'source': first}, {'source': second}], 'fixtures': []}
        calls = []
        def fetch(source):calls.append(source);return raw
        with patch.object(provenance, 'MAX_TOTAL_BYTES', 3), self.assertRaises(provenance.ProvenanceError):
            provenance.verify_upstream(catalog, fetch)
        self.assertEqual(len(calls), 1)

    def test_shared_source_is_fetched_once_but_every_transform_is_checked(self):
        raw = b'```json\n{"a":1}\n```\n```json\n{"a":2}\n```\n'
        ref = {'repository': 'example/source', 'commit': 'b' * 40, 'path': 'SPEC.md',
               'sha256': sha(raw), 'git_blob': blob(raw)}
        first = dict(ref, kind='markdown-json', json_block=0,
                     canonical_sha256=sha(provenance.canonical_json(b'{"a":1}')))
        second = dict(ref, kind='markdown-json', json_block=1,
                      canonical_sha256=sha(provenance.canonical_json(b'{"a":999}')))
        catalog = {'notices': [], 'fixtures': [{'source': first}, {'source': second}]}
        calls = []
        def fetch(source):
            calls.append(source)
            return raw
        with self.assertRaises(provenance.ProvenanceError):provenance.verify_upstream(catalog, fetch)
        self.assertEqual(len(calls), 1)

    def test_authenticated_contents_reads_bind_repository_commit_path_size_and_blob(self):
        raw = b'license source'
        source = {'repository': 'example/source', 'commit': 'b' * 40, 'path': 'LICENSE',
                  'sha256': sha(raw), 'git_blob': blob(raw)}
        reply = {'type': 'file', 'path': 'LICENSE', 'size': len(raw), 'sha': blob(raw),
                 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
        with patch.dict(provenance.os.environ, {'PATH': '/usr/bin', 'HOME': '/PRIVATE_CANARY', 'GH_TOKEN': 'SECRET_CANARY'}, clear=True):
            with patch.object(provenance, 'capture', return_value=json.dumps(reply).encode()) as capture:
                self.assertEqual(provenance.github_source(source), raw)
                args, _cwd, environment, maximum, timeout = capture.call_args.args
                self.assertIn('--method', args);self.assertIn('GET', args)
                self.assertIn('repos/example/source/contents/LICENSE?ref=' + 'b' * 40, args)
                self.assertEqual(environment['GH_PROMPT_DISABLED'], '1')
                self.assertLessEqual(maximum, 4 * 1024 * 1024)
                self.assertLessEqual(timeout, 60)
        for field, value in [('type', 'symlink'), ('path', '../SECRET_CANARY'), ('size', True),
                             ('sha', 'c' * 40), ('content', 'INVALID'), ('encoding', 'none')]:
            changed = dict(reply, **{field: value})
            with patch.object(provenance, 'capture', return_value=json.dumps(changed).encode()):
                with self.assertRaises(provenance.ProvenanceError) as failure:provenance.github_source(source)
                self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_unsafe_source_refs_fail_before_provider_call(self):
        raw = b'x';source = {'repository': 'example/source', 'commit': 'b' * 40, 'path': 'LICENSE',
                            'sha256': sha(raw), 'git_blob': blob(raw)}
        for key, value in [('repository', '../evil'), ('commit', 'master'), ('path', '../SECRET_CANARY'),
                           ('path', 'LICENSE?token=SECRET_CANARY'), ('git_blob', 'invalid')]:
            changed = dict(source, **{key: value})
            with patch.object(provenance, 'capture') as capture, self.assertRaises(provenance.ProvenanceError):
                provenance.github_source(changed)
            self.assertFalse(capture.called)


if __name__ == '__main__':
    unittest.main()
