#!/usr/bin/env python3
"""Standalone Go tool pins, installation bindings and verified graph regressions."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import dependency_go_tools as tools
import dependency_inventory as inventory

ROOT = Path(__file__).resolve().parents[1]
H1 = 'h1:' + base64.b64encode(b'a' * 32).decode()


def inputs():
    return {name: (ROOT / name).read_bytes() for name in tools.INPUTS}


class PinTests(unittest.TestCase):
    def test_real_pin_catalog_matches_all_three_installation_sources(self):
        rows = tools.profiles(inputs())
        self.assertEqual([row['id'] for row in rows], ['cosign', 'mc', 'minio'])
        self.assertEqual({row['scope'] for row in rows}, {'tool-cosign', 'fixture-minio', 'fixture-mc'})
        self.assertEqual(rows[0]['module'], 'github.com/sigstore/cosign/v2')

    def test_missing_duplicate_unknown_pins_and_unsafe_or_unpinned_metadata_fail(self):
        original = inputs(); document = json.loads(original[tools.CATALOG])
        mutations = [lambda data: data['tools'].pop(),
                     lambda data: data['tools'].append(copy.deepcopy(data['tools'][0])),
                     lambda data: data['tools'][0].update(id='unknown'),
                     lambda data: data['tools'][0].update(version='latest'),
                     lambda data: data['tools'][0].update(module='https://SECRET_CANARY@invalid'),
                     lambda data: data['tools'][0].update(package='example.com/other'),
                     lambda data: data['tools'][0].update(sum='h1:invalid'),
                     lambda data: data['tools'][0].update(go_mod_sum=None),
                     lambda data: data['tools'][0].update(commit='a' * 39),
                     lambda data: data['tools'][0].update(extra='unsupported')]
        for mutate in mutations:
            value = copy.deepcopy(document); mutate(value); changed = dict(original)
            changed[tools.CATALOG] = json.dumps(value).encode()
            with self.subTest(mutate=mutate), self.assertRaises(tools.ToolSourceError) as failure:
                tools.profiles(changed)
            self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_installation_version_flags_or_extra_installs_cannot_drift_silently(self):
        original = inputs()
        for name, old, new in [('.github/workflows/container-image.yml', b'cosign@v2.6.1', b'cosign@latest'),
                               ('deploy/local-dependencies/Dockerfile', b'-p=1 -trimpath ', b''),
                               ('deploy/local-dependencies/Dockerfile', b'7394ce0dd2a8 &&', b'000000000000 &&'),
                               ('.github/workflows/container-image.yml', b'go install github.com/sigstore/cosign/v2/cmd/cosign@v2.6.1',
                                b'go install github.com/sigstore/cosign/v2/cmd/cosign@v2.6.1\n          go install example.com/other@v1.0.0')]:
            changed = dict(original); self.assertIn(old, changed[name]); changed[name] = changed[name].replace(old, new)
            with self.subTest(name=name), self.assertRaises(tools.ToolSourceError): tools.profiles(changed)


class GraphTests(unittest.TestCase):
    def fixture(self, root):
        profile = tools.profiles(inputs())[0]
        cache, work = root / 'cache', root / 'work'; cache.mkdir(); work.mkdir()
        path = cache / 'module.zip'
        original = ('module ' + profile['module'] + '\n\ngo 1.24.6\n\nrequire example.com/library v1.2.3\n').encode()
        with zipfile.ZipFile(path, 'w') as target:
            prefix = profile['module'] + '@' + profile['version'] + '/'
            target.writestr(prefix + 'go.mod', original)
            target.writestr(prefix + 'go.sum', b'# upstream source sums\n')
            target.writestr(prefix + 'LICENSE', b'license observation')
        with zipfile.ZipFile(cache / 'library.zip', 'w') as target:
            target.writestr('example.com/library@v1.2.3/LICENSE', b'license observation')
        source = {'Path': profile['module'], 'Version': profile['version'], 'Sum': profile['sum'],
                  'GoModSum': profile['go_mod_sum'], 'Zip': str(path),
                  'Origin': {'Hash': profile['commit']}}
        return profile, cache, work, source, original

    def runner(self, source, calls, *, source_change=None, fail_verify=False, replace=False, mutate=False):
        def run(args, cwd, environment, **kwargs):
            calls.append(list(args))
            if args[:3] == ['go', 'mod', 'download']:
                record = dict(source)
                if args[-1] == 'all':
                    record.update(Path='example.com/library', Version='v1.2.3', Sum=H1, GoModSum=H1,
                                  Zip=str(Path(source['Zip']).parent / 'library.zip'))
                if args[-1] != 'all' and source_change: record.update(source_change)
                return json.dumps(record).encode()
            if args == ['go', 'mod', 'verify']:
                if fail_verify: raise inventory.InventoryError('verification failed')
                return b'all modules verified\n'
            if args == ['go', 'mod', 'edit', '-json']:
                return json.dumps({'Module': {'Path': source['Path']}, 'Go': '1.24.6',
                                   'Replace': [{'Old': {'Path': 'x'}}] if replace else None,
                                   'Exclude': None, 'Require': None}).encode()
            if args[:3] == ['go', 'list', '-m'] and args[-1] != 'all':
                return json.dumps({'Path': source['Path'], 'Version': source['Version'],
                                   'Time': '2025-09-26T17:24:36Z'}).encode()
            if args[-1] == 'all':
                if mutate: (cwd / 'go.mod').write_text('concurrent change\n')
                rows = [{'Path': source['Path'], 'Main': True},
                        {'Path': 'example.com/library', 'Version': 'v1.2.3', 'Time': '2025-09-26T17:24:36Z'}]
                return b'\n'.join(json.dumps(row).encode() for row in rows)
            self.fail('unexpected tool command')
        return run

    def test_root_and_graph_are_verified_before_license_reads_without_build_or_install(self):
        with tempfile.TemporaryDirectory() as folder:
            profile, cache, work, source, original = self.fixture(Path(folder)); calls = []
            with patch.object(inventory, '_run', side_effect=self.runner(source, calls)):
                rows, files, observation = inventory.standalone_tool(profile, work, {}, cache, 'go1.27.3')
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row['source']['verification'] == 'go-mod-verify' for row in rows))
            self.assertEqual(observation['module'], profile['module'])
            self.assertEqual(observation['commit'], profile['commit'])
            self.assertEqual(observation['go_mod_sha256'], hashlib.sha256(original).hexdigest())
            self.assertEqual(len(files), 2)
            self.assertEqual(calls.count(['go', 'mod', 'verify']), 2)
            self.assertFalse(any('build' in call or 'install' in call or 'run' in call for call in calls))
            self.assertNotIn(str(cache), json.dumps(observation))

    def test_wrong_source_checksums_revision_failed_verification_or_replacements_fail(self):
        cases = [{'source_change': {'Path': 'example.com/other'}},
                 {'source_change': {'Version': 'v0.0.0'}}, {'source_change': {'Sum': H1}},
                 {'source_change': {'GoModSum': H1}}, {'source_change': {'Origin': {'Hash': '0' * 40}}},
                 {'fail_verify': True}, {'replace': True}, {'mutate': True}]
        for settings in cases:
            with self.subTest(settings=settings), tempfile.TemporaryDirectory() as folder:
                profile, cache, work, source, _original = self.fixture(Path(folder)); calls = []
                with patch.object(inventory, '_run', side_effect=self.runner(source, calls, **settings)):
                    with self.assertRaises(inventory.InventoryError):
                        inventory.standalone_tool(profile, work, {}, cache, 'go1.27.3')

    def test_archive_manifest_limits_links_duplicate_entries_and_cache_escape_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            profile, cache, _work, source, _original = self.fixture(Path(folder))
            files = inventory.tool_manifest_files(cache, source)
            self.assertEqual(set(files), {'go.mod', 'go.sum'})
            changed = dict(source, Zip=str(cache.parent / 'other.zip'))
            with self.assertRaises(inventory.InventoryError): inventory.tool_manifest_files(cache, changed)
            (cache / 'link.zip').symlink_to(source['Zip'])
            with self.assertRaises(inventory.InventoryError): inventory.tool_manifest_files(cache, dict(source, Zip=str(cache / 'link.zip')))
            with zipfile.ZipFile(source['Zip'], 'w') as target:
                target.writestr(source['Path'] + '@' + source['Version'] + '/go.mod', b'x' * (1024 * 1024 + 1))
            with self.assertRaises(inventory.InventoryError): inventory.tool_manifest_files(cache, source)
            prefix = source['Path'] + '@' + source['Version'] + '/'
            with zipfile.ZipFile(source['Zip'], 'w') as target:
                target.writestr(prefix + 'go.mod', b'one')
                target.writestr(prefix + 'go.mod', b'two')
            with self.assertRaises(inventory.InventoryError): inventory.tool_manifest_files(cache, source)
            with zipfile.ZipFile(source['Zip'], 'w') as target:
                entry = zipfile.ZipInfo(prefix + 'go.mod'); entry.external_attr = 0o120777 << 16
                target.writestr(entry, b'/outside')
            with self.assertRaises(inventory.InventoryError): inventory.tool_manifest_files(cache, source)


if __name__ == '__main__':
    unittest.main()
