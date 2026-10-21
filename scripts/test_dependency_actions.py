#!/usr/bin/env python3
"""Offline Action discovery and pinned Git object/source boundary regressions."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_actions as actions

PIN = 'a' * 40
TREE = 'b' * 40


def workflow(uses='example/action@' + PIN):
    return ('on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ' + uses + '\n').encode()


class DiscoveryTests(unittest.TestCase):
    def test_workflows_examples_and_local_reusable_calls_have_complete_frozen_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ['.github/workflows/check.yml', 'docs/github-actions/example.yml']:
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(workflow())
            (root / '.github/workflows/reuse.yaml').write_bytes(b'on: workflow_call\njobs:\n  call:\n    uses: ./.github/workflows/check.yml\n')
            inputs = {}
            rows = actions.discover(root, inputs)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['name'], 'example/action')
            self.assertEqual(rows[0]['version'], PIN)
            self.assertEqual(rows[0]['origins'], ['ci', 'workflow-example'])
            self.assertEqual(len(rows[0]['locations']), 2)
            self.assertEqual(set(inputs), actions.workflow_paths(root))
            self.assertEqual(inputs['.github/workflows/check.yml'], workflow())

    def test_mutable_dynamic_unsafe_or_missing_local_references_fail_without_echoing_input(self):
        bad = ['example/action@main', 'example/action@v1', 'example/action@${{ inputs.ref }}',
               'https://SECRET_CANARY@example.invalid/action', 'example/../action@' + PIN,
               'example/action@' + 'a' * 39, 'example/action@' + PIN + '?SECRET_CANARY',
               './.github/workflows/missing.yml', './../../../SECRET_CANARY',
               'docker://example/image:latest']
        for value in bad:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); path = root / '.github/workflows/check.yml'
                path.parent.mkdir(parents=True); path.write_bytes(workflow(value))
                with self.assertRaises(actions.ActionSourceError) as failure:
                    actions.discover(root, {})
                self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_invalid_yaml_shapes_duplicate_keys_symlinks_and_input_budgets_fail(self):
        for raw in [b'jobs: {}\njobs: {}\n', b'jobs: []\n', b'jobs:\n  build:\n    steps: wrong\n',
                    b'jobs:\n  build:\n    steps: [{uses: 1}]\n', b'\xff']:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); path = root / '.github/workflows/check.yml'
                path.parent.mkdir(parents=True); path.write_bytes(raw)
                with self.assertRaises(actions.ActionSourceError):
                    actions.discover(root, {})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / '.github/workflows/check.yml'
            path.parent.mkdir(parents=True); path.write_bytes(workflow())
            for constant in ['MAX_WORKFLOW_BYTES', 'MAX_INPUT_BYTES', 'MAX_REFERENCES']:
                with self.subTest(constant=constant), patch.object(actions, constant, 0, create=True):
                    with self.assertRaises(actions.ActionSourceError):
                        actions.discover(root, {})
            (path.parent / 'escape.yml').symlink_to(path)
            with self.assertRaises(actions.ActionSourceError):
                actions.discover(root, {})

    def test_repository_workflows_and_examples_have_only_immutable_external_references(self):
        rows = actions.discover(Path(__file__).resolve().parents[1], {})
        self.assertEqual(len(rows), 14)
        self.assertTrue(any('workflow-example' in row['origins'] for row in rows))


def blob(raw):
    return {'sha': actions.git_blob(raw), 'size': len(raw), 'encoding': 'base64',
            'content': base64.b64encode(raw).decode()}


class Provider:
    def __init__(self):
        self.calls = []
        self.manifest = b'name: Synthetic\nruns:\n  using: composite\n  steps:\n    - uses: other/action@v2\n    - run: echo SECRET_CANARY\n      shell: bash\n'
        self.license = b'license observation'
        self.objects = {
            ('repository', None): {'full_name': 'example/action', 'private': False},
            ('commits', PIN): {'sha': PIN, 'tree': {'sha': TREE}},
            ('trees', TREE): {'sha': TREE, 'truncated': False, 'tree': [
                {'path': 'LICENSE', 'mode': '100644', 'type': 'blob', 'sha': actions.git_blob(self.license), 'size': len(self.license)},
                {'path': 'action.yml', 'mode': '100644', 'type': 'blob', 'sha': actions.git_blob(self.manifest), 'size': len(self.manifest)}]},
            ('blobs', actions.git_blob(self.license)): blob(self.license),
            ('blobs', actions.git_blob(self.manifest)): blob(self.manifest),
        }

    def get(self, repository, kind, sha=None):
        self.calls.append((repository, kind, sha))
        return copy.deepcopy(self.objects[(kind, sha)])


def row():
    return actions.references([('example/action@' + PIN, 'ci', 'workflow.yml#jobs/build/steps/0')])[0]


class SourceTests(unittest.TestCase):
    def test_public_pinned_commit_tree_and_blob_bytes_supply_scoped_notices_and_runtime_metadata(self):
        provider = Provider()
        with tempfile.TemporaryDirectory() as folder:
            client = actions.GitHubSources(Path(folder), query=provider.get)
            observation, files = client.fetch(row())
            again, repeated = client.fetch(row())
            self.assertEqual(observation, again)
            self.assertEqual(files, repeated)
            self.assertEqual(len(provider.calls), 5)
            self.assertEqual(len(list(Path(folder).iterdir())), 2)
        self.assertEqual(observation['verification'], 'github-git-objects')
        self.assertEqual(observation['root_tree'], TREE)
        self.assertEqual(observation['runtime']['using'], 'composite')
        self.assertEqual(observation['runtime']['dependencies'], [{'reference': 'other/action@v2', 'kind': 'github-action', 'pinned': False}])
        self.assertEqual(files[0]['content'], provider.license)
        self.assertNotIn('SECRET_CANARY', json.dumps(observation))

    def test_private_repository_identity_revision_truncation_symlinks_and_ambiguous_metadata_fail(self):
        for case in ['private', 'repository', 'commit', 'tree', 'truncated', 'symlink', 'duplicate']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                provider = Provider()
                if case == 'private': provider.objects[('repository', None)]['private'] = True
                if case == 'repository': provider.objects[('repository', None)]['full_name'] = 'other/repository'
                if case == 'commit': provider.objects[('commits', PIN)]['sha'] = 'c' * 40
                if case == 'tree': provider.objects[('trees', TREE)]['sha'] = 'c' * 40
                if case == 'truncated': provider.objects[('trees', TREE)]['truncated'] = True
                if case == 'symlink': provider.objects[('trees', TREE)]['tree'][0]['mode'] = '120000'
                if case == 'duplicate': provider.objects[('trees', TREE)]['tree'].append(provider.objects[('trees', TREE)]['tree'][0])
                client = actions.GitHubSources(Path(folder), query=provider.get)
                with self.assertRaises(actions.ActionSourceError):
                    client.fetch(row())
                if case in {'private', 'repository'}:
                    self.assertEqual(len(provider.calls), 1)

    def test_blob_digest_size_encoding_and_budget_mismatches_preserve_existing_data(self):
        for case in ['digest', 'size', 'encoding', 'request_budget', 'byte_budget', 'existing']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                provider = Provider(); key = ('blobs', actions.git_blob(provider.license))
                if case == 'digest': provider.objects[key]['content'] = base64.b64encode(b'WRONG').decode()
                if case == 'size': provider.objects[key]['size'] += 1
                if case == 'encoding': provider.objects[key]['encoding'] = 'utf-8'
                owner = Path(folder) / hashlib.sha256(provider.license).hexdigest()
                if case == 'existing': owner.write_bytes(b'owner data')
                client = actions.GitHubSources(Path(folder), query=provider.get)
                with patch.object(actions, 'MAX_REQUESTS', 1 if case == 'request_budget' else 256), patch.object(actions, 'MAX_TOTAL_BYTES', 10 if case == 'byte_budget' else 64 * 1024 * 1024):
                    with self.assertRaises(actions.ActionSourceError):
                        client.fetch(row())
                if case == 'existing': self.assertEqual(owner.read_bytes(), b'owner data')

    def test_runtime_entrypoints_cannot_escape_repository_and_nested_references_remain_explicit(self):
        using = actions.runtime(b'runs:\n  using: node24\n  main: ../lib/main.js\n', 'init')
        self.assertEqual(using['entrypoints'], {'main': 'lib/main.js'})
        docker = actions.runtime(b'runs:\n  using: docker\n  image: Dockerfile\n', '')
        self.assertEqual(docker['image'], 'Dockerfile')
        for raw in [b'runs: {using: node24, main: ../../escape}\n', b'runs: {using: unknown}\n',
                    b'runs: {using: composite, steps: wrong}\n', b'runs: {using: []}\n']:
            with self.subTest(raw=raw), self.assertRaises(actions.ActionSourceError):
                actions.runtime(raw, '')

    def test_subdirectory_action_keeps_ancestor_notices_and_normalizes_node_entrypoints(self):
        provider = Provider(); child = 'c' * 40
        raw = b'runs: {using: node24, main: ../lib/main.js}\n'
        provider.objects['trees', TREE]['tree'].append({'path': 'init', 'mode': '040000', 'type': 'tree', 'sha': child})
        provider.objects['trees', child] = {'sha': child, 'truncated': False, 'tree': [
            {'path': 'action.yaml', 'mode': '100644', 'type': 'blob', 'size': len(raw), 'sha': actions.git_blob(raw)}]}
        provider.objects['blobs', actions.git_blob(raw)] = blob(raw)
        selected = actions.references([('example/action/init@' + PIN, 'ci', 'check.yml')])[0]
        with tempfile.TemporaryDirectory() as folder:
            result, files = actions.GitHubSources(Path(folder), query=provider.get).fetch(selected)
        self.assertEqual([file['file'] for file in files], ['LICENSE'])
        self.assertEqual(result['files'][-1]['path'], 'init/action.yaml')
        self.assertEqual(result['runtime']['entrypoints'], {'main': 'lib/main.js'})

    def test_nested_tag_resolution_is_public_bounded_and_is_not_reported_as_a_pin(self):
        provider = Provider(); provider.objects['resolve', 'v2'] = {'sha': PIN}
        with tempfile.TemporaryDirectory() as folder:
            client = actions.GitHubSources(Path(folder), query=provider.get)
            self.assertEqual(client.resolve('example/action', 'v2'), PIN)
            self.assertEqual(client.resolve('example/action', 'v2'), PIN)
            self.assertEqual(len(provider.calls), 2)
        class Client:
            def __init__(self, *_args): pass
            def resolve(self, *_args): return 'c' * 40
            def fetch(self, row):
                dependencies = [] if row['name'] == 'other/action' else [{'kind': 'github-action', 'reference': 'other/action@v2', 'pinned': False}]
                return {'verification': 'github-git-objects', 'runtime': {'using': 'composite', 'dependencies': dependencies}}, []
        with tempfile.TemporaryDirectory() as folder, patch.object(actions, 'GitHubSources', Client):
            rows, files = actions.collect([row()], Path(folder))
        self.assertEqual(len(rows), 2)
        parent = next(item for item in rows if item['name'] == 'example/action')
        dependency = parent['source']['runtime']['dependencies'][0]
        self.assertFalse(dependency['pinned'])
        self.assertEqual(dependency['resolved_commit'], 'c' * 40)
        self.assertEqual(files, {('example/action', PIN): [], ('other/action', 'c' * 40): []})
        with tempfile.TemporaryDirectory() as folder, patch.object(actions, 'GitHubSources', Client), patch.object(actions, 'MAX_COMPONENTS', 1):
            with self.assertRaises(actions.ActionSourceError): actions.collect([row()], Path(folder))

    def test_reusable_workflow_nested_references_have_the_same_alias_expansion_budget(self):
        provider = Provider(); first, second = 'c' * 40, 'd' * 40
        raw = b'jobs:\n  one: &job\n    steps:\n      - uses: other/action@v2\n  two: *job\n'
        provider.objects['trees', TREE]['tree'].append({'path': '.github', 'mode': '040000', 'type': 'tree', 'sha': first})
        provider.objects['trees', first] = {'sha': first, 'truncated': False, 'tree': [
            {'path': 'workflows', 'mode': '040000', 'type': 'tree', 'sha': second}]}
        provider.objects['trees', second] = {'sha': second, 'truncated': False, 'tree': [
            {'path': 'check.yml', 'mode': '100644', 'type': 'blob', 'size': len(raw), 'sha': actions.git_blob(raw)}]}
        provider.objects['blobs', actions.git_blob(raw)] = blob(raw)
        selected = actions.references([('example/action/.github/workflows/check.yml@' + PIN, 'ci', 'check.yml')])[0]
        with tempfile.TemporaryDirectory() as folder:
            observed, files = actions.GitHubSources(Path(folder), query=provider.get).fetch(selected)
        self.assertEqual(observed['runtime']['using'], 'reusable-workflow')
        self.assertEqual(len(observed['runtime']['dependencies']), 2)
        self.assertEqual([file['file'] for file in files], ['LICENSE'])
        with tempfile.TemporaryDirectory() as folder, patch.object(actions, 'MAX_REFERENCES', 1):
            with self.assertRaises(actions.ActionSourceError):
                actions.GitHubSources(Path(folder), query=provider.get).fetch(selected)


class APITests(unittest.TestCase):
    def test_api_is_bounded_get_only_and_omits_unrelated_credentials(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin', 'HOME': '/owner', 'GH_TOKEN': 'SECRET_TOKEN', 'OTHER_SECRET': 'PRIVATE_CANARY'}, clear=True):
            with patch.object(actions, 'capture', return_value=b'{"sha":"value"}') as capture:
                self.assertEqual(actions.api('example/action', 'commits', PIN), {'sha': 'value'})
                args, cwd, environment, maximum, timeout = capture.call_args.args
                self.assertEqual(args[0:7], ['gh', 'api', '--hostname', 'github.com', '--method', 'GET', '-H'])
                self.assertEqual(args[-1], 'repos/example/action/git/commits/' + PIN)
                self.assertNotIn('OTHER_SECRET', environment)
                self.assertEqual((maximum, timeout), (4 * 1024 * 1024, 30))
        for repository, kind, sha in [('example/../PRIVATE_CANARY', 'commits', PIN), ('example/action', 'DELETE', PIN), ('example/action', 'blobs', 'main')]:
            with self.subTest(kind=kind), patch.object(actions, 'capture') as capture:
                with self.assertRaises(actions.ActionSourceError): actions.api(repository, kind, sha)
                capture.assert_not_called()


if __name__ == '__main__':
    unittest.main()
