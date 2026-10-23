#!/usr/bin/env python3
"""Dependency inventory integrity and privacy regressions; provider calls are faked."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import sys
import time
import unittest
from unittest.mock import patch
import zipfile
import dependency_node_sources
import dependency_python_sources
import dependency_build_tools
import dependency_actions
import dependency_go_tools
import dependency_classifier
import fixture_provenance

SPEC = importlib.util.spec_from_file_location('dependency_inventory', Path(__file__).with_name('dependency_inventory.py'))
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)
H1 = 'h1:' + base64.b64encode(b'a' * 32).decode()
INTEGRITY = 'sha512-' + base64.b64encode(b'b' * 64).decode()


def graph():
    return [{'Path': 'example.com/main', 'Main': True, 'Dir': '/PRIVATE_CANARY'},
            {'Path': 'example.com/library', 'Version': 'v1.2.3',
             'Time': '2026-01-02T03:04:05Z', 'Dir': '/PRIVATE_CANARY/cache',
             'Origin': {'URL': 'https://SECRET_CANARY@example.com/repo'}}]


def download():
    return {'Path': 'example.com/library', 'Version': 'v1.2.3', 'Sum': H1,
            'GoModSum': H1, 'Dir': '/PRIVATE_CANARY/cache', 'Zip': '/PRIVATE_CANARY/module.zip'}


def node():
    manifest = {'name': 'site', 'version': '0.1.0', 'devDependencies': {'alpha': '1.2.3'}}
    lock = {'name': 'site', 'version': '0.1.0', 'lockfileVersion': 3,
            'packages': {'': dict(manifest), 'node_modules/alpha': {
                'version': '1.2.3', 'license': 'MIT', 'dev': True,
                'resolved': 'https://registry.npmjs.org/alpha/-/alpha-1.2.3.tgz',
                'integrity': INTEGRITY}}}
    return manifest, lock


class MetadataTests(unittest.TestCase):
    def test_repository_snapshot_binds_current_inputs_and_keeps_scope_gaps_explicit(self):
        root = Path(__file__).parents[1]
        report = json.loads((root / 'docs/reference/dependency-inventory.json').read_text())
        self.assertEqual(report['schema'], INVENTORY.SCHEMA)
        self.assertFalse(report['complete'])
        self.assertEqual(set(report['generator']['files']), set(INVENTORY.GENERATOR_FILES))
        for name, digest in dict(report['inputs'], **report['generator']['files']).items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest,
                             'inventory inputs or generator changed without regeneration')
        self.assertNotIn('npm-source-license', report['remaining_scopes'])
        self.assertNotIn('python', report['remaining_scopes'])
        self.assertNotIn('fixtures', report['remaining_scopes'])
        self.assertNotIn('build-tool-archives', report['remaining_scopes'])
        self.assertNotIn('actions', report['remaining_scopes'])
        self.assertNotIn('standalone-go-tools', report['remaining_scopes'])
        self.assertEqual({tool['id'] for tool in report['standalone_go_tools']}, {'cosign', 'minio', 'mc'})
        self.assertTrue(all(tool['module_count'] > 0 and tool['verification'] == 'go-mod-verify'
                            for tool in report['standalone_go_tools']))
        self.assertTrue(report['components'])
        for row in report['components']:
            self.assertNotIn('vulnerabilities', row)
            if row['ecosystem'] == 'gomod':
                self.assertEqual(row['source']['verification'], 'go-mod-verify')
            elif row['ecosystem'] == 'npm':
                self.assertEqual(row['source']['verification'], 'sha512-verified')
                self.assertIn('package_json_sha256', row['source'])
            elif row['ecosystem'] == 'pypi':
                self.assertEqual(row['source']['verification'], 'sha256-verified')
                self.assertTrue(row['source']['artifacts'])
            elif row['ecosystem'] == 'fixture':
                self.assertEqual(row['source']['verification'], 'local-digests-checked')
                self.assertTrue(row['license_notices'])
                self.assertTrue(row['license_evidence'])
            elif row['ecosystem'] == 'generic':
                self.assertIn(row['name'], {'helm', 'oasdiff'})
                self.assertEqual(row['source']['verification'], 'sha256-verified')
                self.assertEqual(len(row['source']['binary_sha256']), 64)
            elif row['ecosystem'] == 'github-actions':
                self.assertEqual(row['source']['verification'], 'github-git-objects')
                self.assertEqual(row['version'], row['source']['commit'])
                self.assertTrue(row['source']['files'])
            else:
                self.fail('unrecognized inventory ecosystem')
        scanner = [row for row in report['components'] if row['name'] == 'github.com/anchore/syft']
        self.assertEqual(len(scanner), 1)
        self.assertEqual(scanner[0]['origins'], ['scanner-tool'])
        raw = json.dumps(report)
        self.assertNotIn('/home/', raw)
        self.assertNotIn('/mnt/', raw)
        self.assertNotIn('PRIVATE_CANARY', raw)

    def test_go_json_stream_is_complete_bounded_and_strict(self):
        records = graph()
        raw = b'\n'.join(json.dumps(row).encode() for row in records)
        self.assertEqual(INVENTORY.parse_go_stream(raw), records)
        for raw in [b'', b'{}{}garbage', b'{"Path":"x","Path":"y"}',
                    b'{"x":NaN}', b'{"x":1e999}', b'\xff', b'[]',
                    b' ' * (4 * 1024 * 1024 + 1)]:
            with self.subTest(raw=raw[:32]), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.parse_go_stream(raw)

    def test_go_normalization_drops_paths_and_raw_provider_fields(self):
        rows = INVENTORY.go_components(graph(), [download()], 'application', 'example.com/main')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['name'], 'example.com/library')
        self.assertEqual(rows[0]['source'], {'sum': H1, 'go_mod_sum': H1})
        self.assertEqual(rows[0]['license_status'], 'unobserved')
        self.assertIsNone(rows[0]['license'])
        self.assertNotIn('vulnerabilities', rows[0])
        self.assertEqual(rows[0]['version_published_at'], '2026-01-02T03:04:05Z')
        text = json.dumps(rows)
        self.assertNotIn('PRIVATE_CANARY', text)
        self.assertNotIn('SECRET_CANARY', text)

    def test_sourcehut_module_path_is_preserved_without_shell_expansion(self):
        rows, source = graph(), download()
        rows[1]['Path'] = source['Path'] = 'git.sr.ht/~sbinet/gg'
        result = INVENTORY.go_components(rows, [source], 'scanner', 'example.com/main')
        self.assertEqual(result[0]['name'], 'git.sr.ht/~sbinet/gg')

    def test_go_main_identity_errors_replacements_and_missing_sources_fail(self):
        mutations = [[], graph()[1:], graph() + graph()[:1], graph() + graph()[1:]]
        for rows in mutations:
            with self.subTest(rows=len(rows)), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.go_components(rows, [download()], 'application', 'example.com/main')
        for key, value in [('Error', {'Err': 'PRIVATE_CANARY'}), ('Replace', {'Path': '/PRIVATE_CANARY'}),
                           ('Path', '../PRIVATE_CANARY'), ('Version', '*'),
                           ('Time', '2026-01-01'), ('Time', True)]:
            rows = graph(); rows[1][key] = value
            with self.subTest(key=key), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.go_components(rows, [download()], 'application', 'example.com/main')
        for records in [[], [download(), download()]]:
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.go_components(graph(), records, 'application', 'example.com/main')
        for key in ['Sum', 'GoModSum']:
            for value in [None, 'h1:INVALID', H1 + '\n']:
                record = download(); record[key] = value
                with self.subTest(key=key), self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.go_components(graph(), [record], 'application', 'example.com/main')

    def test_node_sources_are_declarations_without_fabricated_verification(self):
        manifest, lock = node()
        rows = INVENTORY.node_components(manifest, lock)
        self.assertEqual(rows[0]['name'], 'alpha')
        self.assertEqual(rows[0]['license'], 'MIT')
        self.assertEqual(rows[0]['license_status'], 'declared')
        self.assertEqual(rows[0]['source']['verification'], 'lockfile-declared')
        self.assertEqual(rows[0]['locations'], ['node_modules/alpha'])
        self.assertNotIn('vulnerabilities', rows[0])
        lock['packages']['node_modules/alpha'].pop('license')
        row = INVENTORY.node_components(manifest, lock)[0]
        self.assertIsNone(row['license'])
        self.assertEqual(row['license_status'], 'unknown')

    def test_node_artifact_declarations_and_text_observations_remain_distinct(self):
        row = INVENTORY.node_components(*node())[0]
        raw = b'license text'; digest = hashlib.sha256(raw).hexdigest()
        files = [{'file': 'LICENSE', 'kind': 'license', 'sha256': digest, 'content': raw}]
        matches = {digest: {'sha256': digest, 'license': 'Apache-2.0', 'coverage_percent': 100,
                           'ids': ['Apache-2.0'], 'status': 'candidate'}}
        observation = {'verification': 'sha512-verified', 'package_json_sha256': 'a' * 64,
                       'license': 'MIT', 'declaration_status': 'matched'}
        result = INVENTORY.attach_node_licenses(row, observation, files, matches)
        self.assertEqual(result['license'], 'MIT')
        self.assertEqual(result['license_status'], 'artifact-declared')
        self.assertEqual(result['license_text_candidate'], 'Apache-2.0')
        self.assertEqual(result['license_evidence'][0]['license'], 'Apache-2.0')
        self.assertEqual(row['source']['verification'], 'lockfile-declared')
        observation.update(license='BSD-2-Clause', declaration_status='different')
        result = INVENTORY.attach_node_licenses(row, observation, files, matches)
        self.assertIsNone(result['license'])
        self.assertEqual(result['license_status'], 'ambiguous')
        self.assertEqual(result['lockfile_license'], 'MIT')
        self.assertEqual(result['artifact_license'], 'BSD-2-Clause')

    def test_python_declarations_are_not_replaced_by_a_single_text_candidate(self):
        row = {'ecosystem': 'pypi', 'name': 'PyYAML', 'version': '6.0.3', 'license': 'MIT',
               'license_status': 'artifact-declared', 'source': {'verification': 'sha256-verified'}}
        raw = b'text'; digest = hashlib.sha256(raw).hexdigest()
        files = [{'file': 'fixture:LICENSE', 'kind': 'license', 'content': raw, 'sha256': digest}]
        matches = {digest: {'sha256': digest, 'license': 'Apache-2.0', 'ids': ['Apache-2.0'],
                           'coverage_percent': 100, 'status': 'candidate'}}
        result = INVENTORY.attach_declared_licenses(row, files, matches)
        self.assertEqual(result['license'], 'MIT')
        self.assertEqual(result['license_status'], 'artifact-declared')
        self.assertEqual(result['license_text_candidate'], 'Apache-2.0')
        self.assertEqual(result['license_text_status'], 'candidate')
        self.assertNotIn('license_evidence', row)

    def test_node_nested_and_scoped_locations_keep_identity_and_merge(self):
        manifest, lock = node()
        scoped = copy.deepcopy(lock['packages']['node_modules/alpha'])
        scoped['resolved'] = 'https://registry.npmjs.org/@scope/beta/-/beta-1.2.3.tgz'
        lock['packages']['node_modules/alpha/node_modules/@scope/beta'] = scoped
        lock['packages']['node_modules/@scope/beta'] = dict(scoped)
        rows = INVENTORY.node_components(manifest, lock)
        beta = next(row for row in rows if row['name'] == '@scope/beta')
        self.assertEqual(len(beta['locations']), 2)

    def test_node_lock_mismatch_paths_links_and_unsafe_sources_fail(self):
        manifest, lock = node()
        for value in [2, True, '3']:
            changed = copy.deepcopy(lock); changed['lockfileVersion'] = value
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.node_components(manifest, changed)
        changed = copy.deepcopy(lock); changed['packages']['']['devDependencies']['alpha'] = '9.9.9'
        with self.assertRaises(INVENTORY.InventoryError):
            INVENTORY.node_components(manifest, changed)
        for path in ['../PRIVATE_CANARY', '/node_modules/alpha', 'node_modules/../alpha',
                     'node_modules/alpha/other/beta', 'node_modules/@scope']:
            changed = copy.deepcopy(lock); changed['packages'][path] = dict(changed['packages']['node_modules/alpha'])
            with self.subTest(path=path), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.node_components(manifest, changed)
        for key, value in [('link', True), ('link', 0), ('link', None), ('version', '*'), ('integrity', 'sha1-abc'),
                           ('integrity', INTEGRITY + '\n'), ('dev', 'yes'), ('license', ['MIT']),
                           ('resolved', 'https://SECRET_CANARY@registry.npmjs.org/alpha.tgz'),
                           ('resolved', 'https://registry.npmjs.org/alpha.tgz?token=SECRET_CANARY'),
                           ('resolved', 'http://registry.npmjs.org/alpha.tgz'),
                           ('resolved', 'https://example.com/alpha.tgz')]:
            changed = copy.deepcopy(lock); changed['packages']['node_modules/alpha'][key] = value
            with self.subTest(key=key), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.node_components(manifest, changed)

    def test_conflicting_node_license_or_source_for_one_identity_fails(self):
        manifest, lock = node()
        other = dict(lock['packages']['node_modules/alpha']); other['license'] = 'GPL-3.0-only'
        lock['packages']['node_modules/alpha/node_modules/alpha'] = other
        with self.assertRaises(INVENTORY.InventoryError):
            INVENTORY.node_components(manifest, lock)


class FilesAndClassificationTests(unittest.TestCase):
    def zip_fixture(self, root, entries=None):
        path = root / 'module.zip'
        entries = {'LICENSE': b'synthetic license', 'README.md': b'unrelated'} if entries is None else entries
        with zipfile.ZipFile(path, 'w') as archive:
            for name, content in entries.items():
                archive.writestr('example.com/library@v1.2.3/' + name, content)
        record = download(); record['Zip'] = str(path)
        return record

    def test_license_bytes_are_read_from_bounded_zip_entries_without_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); record = self.zip_fixture(root, {'LICENSE': b'license', 'NOTICE': b'notice'})
            files = INVENTORY.license_files(root, record)
            self.assertEqual([row['file'] for row in files], ['LICENSE', 'NOTICE'])
            self.assertEqual(files[0]['sha256'], hashlib.sha256(b'license').hexdigest())
            self.assertEqual(files[0]['content'], b'license')
            self.assertEqual(files[1]['kind'], 'notice')
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['module.zip'])

    def test_zip_paths_symlinks_duplicate_entries_and_oversize_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            root = Path(folder); external = Path(outside)
            record = self.zip_fixture(external)
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.license_files(root, record)
            record = self.zip_fixture(root)
            (root / 'link.zip').symlink_to(root / 'module.zip'); record['Zip'] = str(root / 'link.zip')
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.license_files(root, record)
            (root / 'child').symlink_to(external, target_is_directory=True)
            record['Zip'] = str(root / 'child/module.zip')
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.license_files(root, record)
            record = self.zip_fixture(root, {'LICENSE': b'x' * (1024 * 1024 + 1)})
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.license_files(root, record)
            record = self.zip_fixture(root)
            with zipfile.ZipFile(root / 'module.zip', 'a') as archive:
                info = zipfile.ZipInfo('example.com/library@v1.2.3/COPYING')
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, 'PRIVATE_CANARY')
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.license_files(root, record)

    def test_classification_response_cannot_drop_or_change_input_identity(self):
        digest = hashlib.sha256(b'license').hexdigest()
        row = {'sha256': digest, 'license': 'MIT', 'coverage_percent': 100,
               'ids': ['MIT'], 'status': 'candidate'}
        report = {'schema': 'evydence-license-classification.v1', 'results': [row]}
        self.assertEqual(INVENTORY.classifications(json.dumps(report).encode(), [digest])[digest], row)
        for key, value in [('sha256', '0' * 64), ('status', 'approved'),
                           ('license', 'GPL-3.0-only'), ('coverage_percent', 94),
                           ('ids', ['MIT', 'GPL-3.0-only']), ('path', '/PRIVATE_CANARY')]:
            changed = copy.deepcopy(report); changed['results'][0][key] = value
            with self.subTest(key=key), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.classifications(json.dumps(changed).encode(), [digest])
        for records in [[], [row, row]]:
            changed = dict(report, results=records)
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.classifications(json.dumps(changed).encode(), [digest])

    def test_unknown_or_multiple_primary_licenses_are_not_silently_admitted(self):
        component = INVENTORY.go_components(graph(), [download()], 'application', 'example.com/main')[0]
        files = [{'file': 'LICENSE', 'kind': 'license', 'sha256': 'a' * 64, 'content': b'first'},
                 {'file': 'COPYING', 'kind': 'license', 'sha256': 'b' * 64, 'content': b'second'}]
        matches = {digest: {'sha256': digest, 'license': license, 'coverage_percent': 100,
                           'ids': [license], 'status': 'candidate'}
                   for digest, license in [('a' * 64, 'MIT'), ('b' * 64, 'Apache-2.0')]}
        row = INVENTORY.attach_licenses(component, files, matches)
        self.assertEqual(row['license_status'], 'ambiguous')
        self.assertIsNone(row['license'])
        self.assertNotIn('content', json.dumps(row))
        self.assertEqual(INVENTORY.attach_licenses(component, [], {})['license_status'], 'not-found')

    def test_tool_environment_omits_credentials_and_disables_switching_and_parallel_downloads(self):
        parent = dict(os.environ, GH_TOKEN='SECRET_CANARY', EVYDENCE_DATABASE_URL='PRIVATE_CANARY',
                      GOTOOLCHAIN='auto', GOFLAGS='-mod=mod', GOPRIVATE='*', GONOSUMDB='*',
                      GOPROXY='https://SECRET_CANARY@example.com', GOMEMLIMIT='99GiB')
        env = INVENTORY.tool_environment(parent)
        self.assertEqual(env['GOTOOLCHAIN'], 'local')
        self.assertEqual(env['GOENV'], 'off')
        self.assertEqual(env['GOWORK'], 'off')
        self.assertEqual(env['GOMAXPROCS'], '1')
        self.assertEqual(env['GOPROXY'], 'https://proxy.golang.org')
        self.assertNotIn('SECRET_CANARY', json.dumps(env))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(env))

    def test_atomic_report_write_rejects_paths_and_preserves_unrelated_files(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            root = Path(folder); (root / 'out').mkdir()
            report = {'schema': 'evydence-dependency-inventory.v1', 'components': []}
            INVENTORY.write_report(root, 'out/report.json', report)
            self.assertEqual(json.loads((root / 'out/report.json').read_text()), report)
            for target in ['../PRIVATE_CANARY', str(Path(outside) / 'report.json')]:
                with self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.write_report(root, target, report)
            (root / 'out/other.txt').write_text('PRIVATE_CANARY')
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.write_report(root, 'out/other.txt', report, replace=True)
            (root / 'link').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.write_report(root, 'link/report.json', report)
            self.assertEqual((root / 'out/other.txt').read_text(), 'PRIVATE_CANARY')

    def test_failed_staging_creation_never_removes_someone_elses_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); staged = root / '.dependency-inventory-fixed'
            staged.write_text('owner data')
            class Existing:
                hex = 'fixed'
            with patch.object(INVENTORY.uuid, 'uuid4', return_value=Existing()), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.write_report(root, 'report.json', {'schema': INVENTORY.SCHEMA, 'components': []})
            self.assertTrue(staged.exists(), 'foreign staging file was removed')
            self.assertEqual(staged.read_text(), 'owner data')


class ProcessTests(unittest.TestCase):
    def test_failed_tool_keeps_bounded_private_diagnostics_without_public_error_details(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); log = root / 'tool.log'
            with self.assertRaises(INVENTORY.InventoryError) as raised:
                INVENTORY._run([sys.executable, '-c', 'import sys;print("source failure");sys.exit(3)'],
                               root, INVENTORY.tool_environment(os.environ), log=log)
            self.assertEqual((root / 'tool.stdout').read_bytes(), b'source failure\n')
            self.assertNotIn('source failure', str(raised.exception))

    def test_process_output_and_errors_are_bounded_and_not_echoed(self):
        env = INVENTORY.tool_environment(os.environ)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertEqual(INVENTORY._run([sys.executable, '-c', 'print("ok")'], root, env), b'ok\n')
            for code in ['import sys;sys.stdout.write("x"*(4*1024*1024+1))',
                         'import sys;sys.stderr.write("PRIVATE_CANARY"*30000)',
                         'import sys;sys.stderr.write("PRIVATE_CANARY");sys.exit(7)']:
                with self.subTest(code=code[:30]), self.assertRaises(INVENTORY.InventoryError) as raised:
                    INVENTORY._run([sys.executable, '-c', code], root, env, timeout=5)
                self.assertNotIn('PRIVATE_CANARY', str(raised.exception))

    def test_timeout_kills_its_process_group_even_when_parent_already_exited(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            code = '''import os,time
pid=os.fork()
if pid:
 open("child.pid","w").write(str(pid))
 os._exit(0)
time.sleep(30)
'''
            try:
                with self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY._run([sys.executable, '-c', code], root,
                                   INVENTORY.tool_environment(os.environ), timeout=0.2)
                pid = int((root / 'child.pid').read_text())
                for _attempt in range(20):
                    path = Path('/proc') / str(pid) / 'stat'
                    if not path.exists() or path.read_text().split()[2] == 'Z':
                        break
                    time.sleep(0.01)
                else:
                    self.fail('timed-out process left a running child')
            finally:
                path = root / 'child.pid'
                if path.exists():
                    try:
                        os.kill(int(path.read_text()), 9)
                    except ProcessLookupError:
                        pass


class FixtureObservationTests(unittest.TestCase):
    def test_fixture_observations_bind_payloads_notes_catalog_and_notice_bytes(self):
        root = Path(__file__).parents[1]
        inputs = {fixture_provenance.CATALOG: (root / fixture_provenance.CATALOG).read_bytes()}
        rows, observations = INVENTORY.fixture_components(root, inputs)
        self.assertEqual(len(rows), 34)
        self.assertEqual(len({file['path'] for row in rows for file in row['source']['files']}), 56)
        self.assertIn('LICENSE', inputs)
        self.assertIn(fixture_provenance.CORPUS, inputs)
        self.assertIn('internal/app/parsers/spdx/testdata/SOURCE.md', inputs)
        for row in rows:
            for file in row['source']['files']:
                self.assertEqual(hashlib.sha256(inputs[file['path']]).hexdigest(), file['sha256'])
            for notice, file in zip(row['license_notices'], observations[row['name']]):
                self.assertEqual(file['content'], inputs[notice['path']])
                self.assertEqual(file['sha256'], notice['sha256'])
                self.assertEqual(file['kind'], 'notice' if notice['id'] in {'trivy-notice', 'sigstore-go-copyright-txt'} else 'license')
            self.assertNotIn('content', json.dumps(row))


class ScannerToolTests(unittest.TestCase):
    def record(self, root):
        import release_evidence_tools as tools
        return {'Path': 'github.com/anchore/syft', 'Version': 'v' + tools.release_sbom.SYFT_VERSION,
                'Sum': tools.SOURCE_SUM, 'GoModSum': tools.SOURCE_MOD_SUM,
                'Dir': str(root / 'source'), 'Zip': str(root / 'module.zip'),
                'Origin': {'Hash': tools.release_scanner.SYFT_SOURCE_COMMIT}}

    def test_scanner_main_source_is_verified_as_a_dependency_before_license_reads(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); record = self.record(root); calls = []
            def run(args, cwd, environment, **kwargs):
                calls.append(args)
                if args[:3] == ['go', 'mod', 'download']:
                    self.assertIn(record['Sum'], (cwd / 'go.sum').read_text())
                    self.assertIn(record['GoModSum'], (cwd / 'go.sum').read_text())
                    return json.dumps(record).encode()
                self.assertEqual(args, ['go', 'mod', 'verify'])
                return b'all modules verified\n'
            def licenses(cache, source):
                self.assertEqual(calls[-1], ['go', 'mod', 'verify'])
                self.assertEqual(source, record)
                return []
            with patch.object(INVENTORY, '_run', side_effect=run), patch.object(INVENTORY, 'license_files', side_effect=licenses):
                row, files = INVENTORY.scanner_tool(root, {}, root, 'go1.27.3')
            self.assertEqual(row['name'], 'github.com/anchore/syft')
            self.assertEqual(row['origins'], ['scanner-tool'])
            self.assertEqual(row['source']['verification'], 'go-mod-verify')
            self.assertEqual(row['source']['commit'], record['Origin']['Hash'])
            self.assertEqual(files, [])
            self.assertNotIn(str(root), json.dumps(row))

    def test_scanner_identity_checksum_revision_or_failed_verification_cannot_supply_licenses(self):
        mutations = [{'Path': 'example.com/other'}, {'Version': 'v0.0.0'}, {'Sum': H1},
                     {'GoModSum': H1}, {'Origin': {'Hash': '0' * 40}}, {'Origin': None},
                     {'Error': 'SECRET_CANARY'}]
        for mutation in mutations + [None]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); record = self.record(root)
                if mutation:
                    record.update(mutation)
                def run(args, *_args, **_kwargs):
                    if args[:3] == ['go', 'mod', 'download']:
                        return json.dumps(record).encode()
                    raise INVENTORY.InventoryError('verification failed')
                with patch.object(INVENTORY, '_run', side_effect=run), patch.object(INVENTORY, 'license_files') as licenses:
                    with self.assertRaises(INVENTORY.InventoryError) as failure:
                        INVENTORY.scanner_tool(root, {}, root, 'go1.27.3')
                    licenses.assert_not_called()
                    self.assertNotIn('SECRET_CANARY', str(failure.exception))


class CollectorTests(unittest.TestCase):
    def setUp(self):
        def standalone_tool(profile, _work, _environment, _cache, _expected_go):
            return [], {}, {'id': profile['id'], 'module': profile['module'], 'module_count': 0}
        standalone_mock = patch.object(INVENTORY, 'standalone_tool', side_effect=standalone_tool)
        self.standalone_tool = standalone_mock.start()
        self.addCleanup(standalone_mock.stop)
        def action_collect(rows, _work):
            rows = copy.deepcopy(rows)
            for row in rows:
                row['source'].update(verification='github-git-objects', runtime={'using': 'node24', 'dependencies': []}, files=[])
            return rows, {(row['name'], row['version']): [] for row in rows}
        action_mock = patch.object(dependency_actions, 'collect', side_effect=action_collect)
        self.action_collect = action_mock.start()
        self.addCleanup(action_mock.stop)
        def tool_fetch(_row, _work):
            return ({'verification': 'sha256-verified', 'binary_sha256': 'b' * 64}, [])
        tool_mock = patch.object(dependency_build_tools, 'fetch', side_effect=tool_fetch)
        self.tool_fetch = tool_mock.start()
        self.addCleanup(tool_mock.stop)
        scanner = {'ecosystem': 'gomod', 'name': 'github.com/anchore/syft', 'version': 'v1.54.1',
                   'origins': ['scanner-tool'], 'license': None, 'license_status': 'unobserved',
                   'license_evidence': [], 'version_published_at': None,
                   'source': {'sum': H1, 'go_mod_sum': H1, 'verification': 'go-mod-verify'}}
        scanner_mock = patch.object(INVENTORY, 'scanner_tool', return_value=(scanner, []))
        self.scanner_tool = scanner_mock.start()
        self.addCleanup(scanner_mock.stop)
        def fetch(_row, _work):
            return ({'verification': 'sha512-verified', 'package_json_sha256': 'a' * 64,
                     'license': 'MIT', 'declaration_status': 'matched'}, [])
        mock = patch.object(dependency_node_sources, 'fetch', side_effect=fetch)
        self.node_fetch = mock.start()
        self.addCleanup(mock.stop)
        def python_fetch(_requirements, _work):
            return ({'ecosystem': 'pypi', 'name': 'PyYAML', 'version': '6.0.3', 'origins': ['qa'],
                     'license': 'MIT', 'license_status': 'artifact-declared', 'license_evidence': [],
                     'source': {'verification': 'sha256-verified', 'artifacts': []}}, [])
        python_mock = patch.object(dependency_python_sources, 'fetch', side_effect=python_fetch)
        self.python_fetch = python_mock.start()
        self.addCleanup(python_mock.stop)

    def test_cli_rejects_output_escape_before_starting_collection(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {}, clear=True), patch.object(INVENTORY, 'collect') as collect:
                self.assertEqual(INVENTORY.main(['--root', folder, '--work-root', folder,
                                                  '--output', '../PRIVATE_CANARY']), 2)
                self.assertFalse(collect.called, 'collection ran before output validation')

    def fixture(self, root):
        workflow = root / '.github/workflows/check.yml'
        workflow.parent.mkdir(parents=True)
        workflow.write_text('on: [push]\njobs:\n  build:\n    steps:\n      - uses: example/action@' + 'a' * 40 + '\n')
        for name in dependency_go_tools.INPUTS:
            target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((Path(__file__).parents[1] / name).read_bytes())
        (root / dependency_go_tools.WORKFLOW).write_text(
            'jobs:\n  sign-image:\n    steps:\n      - name: Install cosign\n'
            '        run: go install github.com/sigstore/cosign/v2/cmd/cosign@v2.6.1\n')
        for _scope, mod, sums, module in INVENTORY.GRAPHS:
            (root / mod).parent.mkdir(parents=True, exist_ok=True)
            (root / mod).write_text('module ' + module + '\n\ngo 1.26.10\n')
            (root / sums).write_text('fixture sums\n')
        for name in INVENTORY.GENERATOR_FILES:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((Path(__file__).parents[1] / name).read_bytes())
        (root / 'release/support-matrix.json').write_bytes(
            (Path(__file__).parents[1] / 'release/support-matrix.json').read_bytes())
        (root / 'site/marketing').mkdir(parents=True)
        manifest, lock = node()
        (root / 'site/marketing/package.json').write_text(json.dumps(manifest))
        (root / 'site/marketing/package-lock.json').write_text(json.dumps(lock))
        (root / 'tools/requirements-qa.txt').write_bytes(
            (Path(__file__).parents[1] / 'tools/requirements-qa.txt').read_bytes())
        cache = root / 'cache'; cache.mkdir()
        raw = (Path(__file__).parents[1] / 'internal/platform/config/database_dsn.LICENSE').read_bytes()
        (root / 'LICENSE').write_bytes(raw)
        (root / 'testdata').mkdir()
        (root / 'testdata/example.json').write_bytes(b'{"example":true}')
        (root / fixture_provenance.CORPUS).write_text('{"fixtures":[]}')
        catalog = {'schema': fixture_provenance.SCHEMA,
                   'notices': [{'id': 'evydence', 'license': 'AGPL-3.0-only', 'path': 'LICENSE',
                                'sha256': hashlib.sha256(raw).hexdigest(), 'source': None}],
                   'fixtures': [{'id': 'example', 'license': 'AGPL-3.0-only', 'notices': ['evydence'],
                                 'files': [{'path': 'testdata/example.json', 'sha256': hashlib.sha256(b'{"example":true}').hexdigest()}],
                                 'source': {'kind': 'project'}}]}
        (root / fixture_provenance.CATALOG).write_text(json.dumps(catalog))
        with zipfile.ZipFile(cache / 'module.zip', 'w') as archive:
            archive.writestr('example.com/library@v1.2.3/LICENSE', raw)
        return cache

    def fake_runner(self, root, cache, calls, *, fail_verify=False, mutate=False, truncate=False,
                    mutate_fixture=False, add_fixture=False, mutate_workflow=False, add_workflow=False):
        def run(args, cwd, environment, **kwargs):
            calls.append((list(args), str(cwd), dict(environment)))
            if args == ['go', 'version']:
                return b'go version go1.27.3 linux/amd64\n'
            if args == ['go', 'env', 'GOMODCACHE']:
                return str(cache).encode() + b'\n'
            if args[:2] == ['go', 'build']:
                return b''
            if args[0].endswith('license-classifier'):
                rows = json.loads(kwargs['data'])
                results = [{'sha256': row['sha256'], 'license': 'MIT', 'coverage_percent': 100,
                            'ids': ['MIT'], 'status': 'candidate'} for row in rows]
                if truncate:
                    results = []
                return json.dumps({'schema': 'evydence-license-classification.v1', 'results': results}).encode()
            if args[:4] == ['go', 'list', '-m', '-mod=readonly']:
                main = (Path(cwd) / 'go.mod').read_text().splitlines()[0].split()[1]
                rows = graph(); rows[0]['Path'] = main
                return b'\n'.join(json.dumps(row).encode() for row in rows)
            if args[:3] == ['go', 'mod', 'download']:
                row = download(); row['Zip'] = str(cache / 'module.zip')
                with (Path(cwd) / 'go.sum').open('a') as sums:
                    sums.write('new isolated checksum\n')
                return json.dumps(row).encode()
            if args == ['go', 'mod', 'verify']:
                if fail_verify:
                    raise INVENTORY.InventoryError('source verification failed')
                if mutate:
                    (root / 'go.sum').write_text('concurrent owner edit\n')
                if mutate_fixture:
                    (root / 'testdata/example.json').write_text('concurrent owner edit\n')
                if add_fixture:
                    (root / 'testdata/late.json').write_text('{}')
                if mutate_workflow:
                    (root / '.github/workflows/check.yml').write_text('concurrent owner edit\n')
                if add_workflow:
                    (root / '.github/workflows/late.yaml').write_text('jobs: {}\n')
                return b'all modules verified\n'
            self.fail('unexpected tool command')
        return run

    def trusted_classifier(self,work):
        workspace=work/'trusted-classifier'; workspace.mkdir(mode=0o700)
        executable=workspace/'license-classifier'; executable.write_bytes(b'trusted base executable')
        root=Path(__file__).parents[1]
        sources={name:{'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()}
                 for name in ['tools/go.mod','tools/go.sum','tools/cmd/license-inventory/main.go']}
        receipt={'schema':dependency_classifier.SCHEMA,'trusted_base':'a'*40,'go_version':'go1.27.3',
                 'sources':sources,'binary_sha256':hashlib.sha256(executable.read_bytes()).hexdigest()}
        env=dependency_classifier.environment({'PATH':'/trusted/bin','GH_TOKEN':'SECRET_CANARY'},workspace)
        return dependency_classifier.BuiltClassifier(workspace,receipt,env)

    def test_external_classifier_keeps_proposed_code_as_data_and_binds_actual_generators(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); cache=self.fixture(root); work=root/'work'; work.mkdir()
            classifier=self.trusted_classifier(work)
            proposed_python=root/'scripts/dependency_inventory.py'
            proposed_python.write_text('raise RuntimeError("PRIVATE_CANARY proposed Python executed")')
            proposed_go=root/'tools/cmd/license-inventory/main.go'
            proposed_go.write_text('package main // PRIVATE_CANARY proposed Go must not build')
            calls=[]; runner=self.fake_runner(root,cache,calls)
            with patch.object(INVENTORY,'_run',runner),patch.object(dependency_classifier.inventory,'_run',runner):
                result=INVENTORY.collect(root,work,{'GH_TOKEN':'SECRET_CANARY'},classifier=classifier)
            self.assertEqual(result['generator']['classifier'],classifier.receipt)
            self.assertEqual(result['generator']['files']['scripts/dependency_inventory.py'],
                             hashlib.sha256((Path(__file__).parents[1]/'scripts/dependency_inventory.py').read_bytes()).hexdigest())
            self.assertEqual(result['generator']['files']['tools/cmd/license-inventory/main.go'],
                             classifier.receipt['sources']['tools/cmd/license-inventory/main.go']['sha256'])
            self.assertEqual(result['inputs']['tools/go.mod'],hashlib.sha256((root/'tools/go.mod').read_bytes()).hexdigest())
            self.assertNotEqual(result['inputs']['tools/go.mod'],classifier.receipt['sources']['tools/go.mod']['sha256'])
            self.assertFalse(any(args[:2]==['go','build'] for args,_,_ in calls))
            self.assertTrue(any(args==[str(classifier.executable)] for args,_,_ in calls))
            self.assertTrue(all(env['HOME']==classifier.environment['HOME'] and env['GOAUTH']=='off'
                                and env['GOVCS']=='*:off' and 'GH_TOKEN' not in env for _,_,env in calls))
            self.assertIn('PRIVATE_CANARY',proposed_python.read_text()); self.assertIn('PRIVATE_CANARY',proposed_go.read_text())
            self.assertNotIn('CANARY',json.dumps(result))

    def test_invalid_external_classifier_is_rejected_before_provider_work(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.fixture(root); work=root/'work'; work.mkdir()
            for value in [object(),self.trusted_classifier(work)]:
                if isinstance(value,dependency_classifier.BuiltClassifier): value.executable.write_bytes(b'tampered')
                with self.subTest(value=type(value).__name__),patch.object(INVENTORY,'_run') as run, \
                     self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.collect(root,work,{},classifier=value)
                run.assert_not_called(); self.action_collect.assert_not_called(); self.node_fetch.assert_not_called()

    def test_trusted_generator_edit_during_external_collection_aborts_and_preserves_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cache=self.fixture(root);work=root/'work';work.mkdir()
            classifier=self.trusted_classifier(work);code=work/'trusted-code';code.mkdir()
            for name in INVENTORY.GENERATOR_FILES:
                target=code/name;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((Path(__file__).parents[1]/name).read_bytes())
            target=code/'scripts/dependency_inventory.py'
            runner=self.fake_runner(root,cache,[])
            def mutate(args,*pos,**kwargs):
                if args==['go','mod','verify']:target.write_text('PRIVATE_CANARY owner edit')
                return runner(args,*pos,**kwargs)
            with patch.object(INVENTORY,'ROOT',code),patch.object(INVENTORY,'_run',mutate), \
                 patch.object(dependency_classifier.inventory,'_run',mutate),self.assertRaises(INVENTORY.InventoryError) as error:
                INVENTORY.collect(root,work,{},classifier=classifier)
            self.assertNotIn('CANARY',str(error.exception));self.assertIn('CANARY',target.read_text())

    def test_collector_verifies_before_classification_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            before = {path: path.read_bytes() for path in root.rglob('*') if path.is_file()}
            calls = []
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)):
                result = INVENTORY.collect(root, work, dict(os.environ, GH_TOKEN='SECRET_CANARY'))
            self.assertEqual(result['schema'], 'evydence-dependency-inventory.v1')
            self.assertFalse(result['complete'])
            self.assertNotIn('python', result['remaining_scopes'])
            self.assertEqual(len(result['components']), 8)
            self.assertNotIn('standalone-go-tools', result['remaining_scopes'])
            self.assertEqual(self.standalone_tool.call_count, 3)
            self.assertEqual({tool['id'] for tool in result['standalone_go_tools']}, {'cosign', 'minio', 'mc'})
            self.assertNotIn('actions', result['remaining_scopes'])
            self.action_collect.assert_called_once()
            self.assertNotIn('build-tool-archives', result['remaining_scopes'])
            self.assertEqual(self.tool_fetch.call_count, 2)
            self.scanner_tool.assert_called_once()
            archive_tools = [row for row in result['components'] if row['ecosystem'] == 'generic']
            self.assertTrue(all(row['source']['verification'] == 'sha256-verified' for row in archive_tools))
            library = next(row for row in result['components'] if row['name'] == 'example.com/library')
            self.assertEqual(library['origins'], ['application', 'qa', 'scanner'])
            self.assertEqual(library['license'], 'MIT')
            self.assertEqual(library['source']['verification'], 'go-mod-verify')
            self.assertEqual(self.node_fetch.call_count, 1)
            npm = next(row for row in result['components'] if row['ecosystem'] == 'npm')
            self.assertEqual(npm['source']['verification'], 'sha512-verified')
            self.assertEqual(npm['license_status'], 'artifact-declared')
            self.assertEqual(self.python_fetch.call_count, 1)
            python = next(row for row in result['components'] if row['ecosystem'] == 'pypi')
            self.assertEqual(python['license'], 'MIT')
            self.assertEqual(python['license_text_status'], 'not-found')
            fixture = next(row for row in result['components'] if row['ecosystem'] == 'fixture')
            self.assertEqual(fixture['license'], 'AGPL-3.0-only')
            self.assertEqual(fixture['license_text_candidate'], 'MIT')
            self.assertEqual(fixture['license_status'], 'recorded-declaration')
            self.assertTrue(all(path.read_bytes() == raw for path, raw in before.items()))
            verify = [i for i, (args, _cwd, _env) in enumerate(calls) if args == ['go', 'mod', 'verify']]
            classifier = [i for i, (args, _cwd, _env) in enumerate(calls) if args[0].endswith('license-classifier')]
            self.assertEqual(len(verify), 3)
            self.assertLess(max(verify), min(classifier))
            self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
            self.assertNotIn('SECRET_CANARY', json.dumps(result))
            self.assertTrue(all(env['GOTOOLCHAIN'] == 'local' and env['GOMAXPROCS'] == '1' for _args, _cwd, env in calls))

    def test_failed_verification_or_incomplete_classifier_cannot_produce_inventory(self):
        for fail_verify, truncate in [(True, False), (False, True)]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
                calls = []
                runner = self.fake_runner(root, cache, calls, fail_verify=fail_verify, truncate=truncate)
                with patch.object(INVENTORY, '_run', runner), self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.collect(root, work, os.environ)
                self.assertFalse((root / 'docs/reference/dependency-inventory.json').exists())

    def test_failed_npm_source_cannot_produce_a_report_or_run_classifier(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            calls = []
            self.node_fetch.side_effect = dependency_node_sources.NodeSourceError('PRIVATE_CANARY')
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)):
                with self.assertRaises(INVENTORY.InventoryError) as failure:
                    INVENTORY.collect(root, work, {})
            self.assertNotIn('PRIVATE_CANARY', str(failure.exception))
            self.assertFalse(any(args[:2] == ['go', 'build'] for args, _cwd, _env in calls))
            self.assertFalse(any(args[:3] == ['go', 'list', '-m'] for args, _cwd, _env in calls),
                             'module graph work started before the npm source preflight')
            self.assertFalse((root / 'docs/reference/dependency-inventory.json').exists())

    def test_failed_python_source_aborts_before_other_graph_work(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            calls = []
            self.python_fetch.side_effect = dependency_python_sources.PythonSourceError()
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, {})
            self.assertFalse(self.node_fetch.called)
            self.assertFalse(any(args[:3] == ['go', 'list', '-m'] for args, _cwd, _env in calls))

    def test_bad_fixture_stops_before_any_tool_or_provider_work(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            (root / 'testdata/example.json').write_text('tampering')
            calls = []
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, {})
            self.assertEqual(len(calls), 0)
            self.assertFalse(self.node_fetch.called)
            self.assertFalse(self.python_fetch.called)

    def test_fixture_edits_or_late_unclassified_files_abort_without_overwriting_them(self):
        for operation in ['mutate_fixture', 'add_fixture']:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
                runner = self.fake_runner(root, cache, [], **{operation: True})
                with patch.object(INVENTORY, '_run', runner), self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.collect(root, work, {})
                if operation == 'mutate_fixture':
                    self.assertEqual((root / 'testdata/example.json').read_text(), 'concurrent owner edit\n')
                else:
                    self.assertEqual((root / 'testdata/late.json').read_text(), '{}')

    def test_bad_workflow_stops_before_tools_or_providers_and_preserves_its_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            source = root / '.github/workflows/check.yml'
            source.write_text('jobs:\n  call:\n    uses: example/action@main\n')
            calls = []
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, {})
            self.assertEqual(calls, [])
            self.action_collect.assert_not_called()
            self.assertIn('@main', source.read_text())

    def test_bad_standalone_pins_stop_before_tools_or_providers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            source = root / dependency_go_tools.CATALOG
            record = json.loads(source.read_text()); record['tools'][0]['sum'] = 'invalid'
            source.write_text(json.dumps(record))
            calls = []
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, {})
            self.assertEqual(calls, [])
            self.action_collect.assert_not_called(); self.standalone_tool.assert_not_called()

    def test_standalone_pin_edit_during_collection_is_preserved_and_aborts_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            source = root / dependency_go_tools.CATALOG
            delegate = self.fake_runner(root, cache, [])
            def run(args, *positional, **keyword):
                if args == ['go', 'mod', 'verify']: source.write_text('concurrent owner edit\n')
                return delegate(args, *positional, **keyword)
            with patch.object(INVENTORY, '_run', side_effect=run), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, {})
            self.assertEqual(source.read_text(), 'concurrent owner edit\n')

    def test_workflow_edits_and_new_unclassified_workflows_abort_without_overwriting_them(self):
        for operation in ['mutate_workflow', 'add_workflow']:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
                with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, [], **{operation: True})):
                    with self.assertRaises(INVENTORY.InventoryError): INVENTORY.collect(root, work, {})
                name = 'check.yml' if operation == 'mutate_workflow' else 'late.yaml'
                expected = 'concurrent owner edit\n' if operation == 'mutate_workflow' else 'jobs: {}\n'
                self.assertEqual((root / '.github/workflows' / name).read_text(), expected)

    def test_concurrent_source_change_aborts_without_overwriting_the_owner_edit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            runner = self.fake_runner(root, cache, [], mutate=True)
            with patch.object(INVENTORY, '_run', runner), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, os.environ)
            self.assertEqual((root / 'go.sum').read_text(), 'concurrent owner edit\n')

    def test_license_set_budget_is_enforced_before_building_or_running_classifier(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            calls = []
            runner = self.fake_runner(root, cache, calls)
            with patch.object(INVENTORY, '_run', runner), patch.object(
                    INVENTORY, 'MAX_LICENSE_SET_BYTES', 1, create=True), self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.collect(root, work, os.environ)
            self.assertFalse(any(args[:2] == ['go', 'build'] for args, _cwd, _env in calls),
                             'classifier build ran after the license-set budget was exceeded')


if __name__ == '__main__':
    unittest.main()
