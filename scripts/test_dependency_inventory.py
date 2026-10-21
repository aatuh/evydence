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
        self.assertIn('npm-source-license', report['remaining_scopes'])
        self.assertIn('python', report['remaining_scopes'])
        self.assertIn('fixtures', report['remaining_scopes'])
        self.assertTrue(report['components'])
        for row in report['components']:
            self.assertNotIn('vulnerabilities', row)
            if row['ecosystem'] == 'gomod':
                self.assertEqual(row['source']['verification'], 'go-mod-verify')
            else:
                self.assertEqual(row['source']['verification'], 'lockfile-declared')
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


class CollectorTests(unittest.TestCase):
    def test_cli_rejects_output_escape_before_starting_collection(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {}, clear=True), patch.object(INVENTORY, 'collect') as collect:
                self.assertEqual(INVENTORY.main(['--root', folder, '--work-root', folder,
                                                  '--output', '../PRIVATE_CANARY']), 2)
                self.assertFalse(collect.called, 'collection ran before output validation')

    def fixture(self, root):
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
        cache = root / 'cache'; cache.mkdir()
        raw = (Path(__file__).parents[1] / 'internal/platform/config/database_dsn.LICENSE').read_bytes()
        with zipfile.ZipFile(cache / 'module.zip', 'w') as archive:
            archive.writestr('example.com/library@v1.2.3/LICENSE', raw)
        return cache

    def fake_runner(self, root, cache, calls, *, fail_verify=False, mutate=False, truncate=False):
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
                return b'all modules verified\n'
            self.fail('unexpected tool command')
        return run

    def test_collector_verifies_before_classification_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cache = self.fixture(root); work = root / 'work'; work.mkdir()
            before = {path: path.read_bytes() for path in root.rglob('*') if path.is_file()}
            calls = []
            with patch.object(INVENTORY, '_run', self.fake_runner(root, cache, calls)):
                result = INVENTORY.collect(root, work, dict(os.environ, GH_TOKEN='SECRET_CANARY'))
            self.assertEqual(result['schema'], 'evydence-dependency-inventory.v1')
            self.assertFalse(result['complete'])
            self.assertIn('python', result['remaining_scopes'])
            self.assertEqual(len(result['components']), 2)
            library = next(row for row in result['components'] if row['ecosystem'] == 'gomod')
            self.assertEqual(library['origins'], ['application', 'qa', 'scanner'])
            self.assertEqual(library['license'], 'MIT')
            self.assertEqual(library['source']['verification'], 'go-mod-verify')
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
