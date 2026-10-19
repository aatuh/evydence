#!/usr/bin/env python3
"""Artifact comparison checks real fixture bytes without building or networking."""
import copy
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import reproducible_build as repro
import release_artifacts
import support_matrix


TAG = 'v0.0.0-rc.1402'
COMMIT = 'a' * 40


class ReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = support_matrix.load_policy()
        self.first = self.bundle('first')
        self.second = self.bundle('second')

    def bundle(self, name):
        directory = self.root / name
        for path in repro.artifact_paths(self.policy, TAG):
            output = directory / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(('fixture bytes ' + path).encode())
        report = dict(schema_version=repro.REPORT_SCHEMA, source_commit=COMMIT, tag=TAG,
                      source_date_epoch=1700000000, go_version='go1.27.2',
                      build_recipe_version=release_artifacts.RECIPE_VERSION,
                      artifacts=repro.artifact_inventory(directory, self.policy, TAG),
                      execution={'kind': 'local', 'slot': name})
        (directory / repro.REPORT_NAME).write_text(json.dumps(report))
        return directory

    def change_report(self, directory, change):
        path = directory / repro.REPORT_NAME
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def compare(self):
        return repro.compare_bundles(self.first, self.second, TAG, COMMIT)

    def test_matching_complete_artifacts_pass_with_explicit_equality_scope(self):
        result = self.compare()
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['source_commit'], COMMIT)
        self.assertEqual(result['scope'], 'artifact-byte-equality')
        self.assertEqual(result['artifact_count'], 14)
        self.assertEqual(result['differences'], [])
        self.assertNotIn('independent_runners_verified', result)

    def test_actual_artifact_tampering_cannot_pass_matching_reports(self):
        path = next(iter(repro.artifact_paths(self.policy, TAG)))
        (self.second / path).write_text('PRIVATE_TAMPERED_BYTES')
        result = self.compare()
        self.assertFalse(result['passed'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertTrue(result['differences'])

    def test_legitimate_but_different_reported_bytes_produce_diff_report(self):
        path = next(iter(repro.artifact_paths(self.policy, TAG)))
        (self.second / path).write_text('different artifact')
        self.change_report(self.second, lambda report: report.update(
            artifacts=repro.artifact_inventory(self.second, self.policy, TAG)))
        result = self.compare()
        self.assertFalse(result['passed'])
        self.assertIn(path, json.dumps(result['differences']))

    def test_source_tag_epoch_compiler_recipe_and_schema_mismatches_fail(self):
        original = json.loads((self.second / repro.REPORT_NAME).read_text())
        for key, value in [('source_commit', 'b' * 40), ('tag', 'v0.0.0-rc.2'),
                           ('source_date_epoch', True), ('go_version', 'go1.26.9'),
                           ('build_recipe_version', 'PRIVATE'), ('schema_version', 'PRIVATE')]:
            with self.subTest(key=key):
                data = copy.deepcopy(original)
                data[key] = value
                (self.second / repro.REPORT_NAME).write_text(json.dumps(data))
                result = self.compare()
                self.assertFalse(result['passed'])
                self.assertNotIn('PRIVATE', json.dumps(result))

    def test_missing_extra_duplicate_or_traversal_artifact_records_fail(self):
        original = json.loads((self.second / repro.REPORT_NAME).read_text())
        for mutation in ['missing', 'extra', 'traversal', 'malformed']:
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(original)
                path = next(iter(data['artifacts']))
                if mutation == 'missing':
                    del data['artifacts'][path]
                elif mutation in ['extra', 'traversal']:
                    data['artifacts']['../PRIVATE'] = data['artifacts'][path]
                else:
                    data['artifacts'][path]['sha256'] = 'PRIVATE'
                (self.second / repro.REPORT_NAME).write_text(json.dumps(data))
                result = self.compare()
                self.assertFalse(result['passed'])
                self.assertNotIn('PRIVATE', json.dumps(result))

    def test_symlink_artifacts_and_missing_reports_fail_without_path_leaks(self):
        path = next(iter(repro.artifact_paths(self.policy, TAG)))
        (self.second / path).unlink()
        (self.second / path).symlink_to(self.root / 'PRIVATE_OUTSIDE')
        self.assertFalse(self.compare()['passed'])
        (self.second / repro.REPORT_NAME).unlink()
        result = self.compare()
        self.assertFalse(result['passed'])
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_duplicate_json_fields_and_oversized_reports_are_rejected(self):
        path = self.second / repro.REPORT_NAME
        for content in ['{"schema_version":"PRIVATE","schema_version":"duplicate"}', 'PRIVATE' * 400000]:
            path.write_text(content)
            result = self.compare()
            self.assertFalse(result['passed'])
            self.assertNotIn('PRIVATE', json.dumps(result))

    def local_repeat_fixture(self, fail=False):
        source = self.root / ('source-failing' if fail else 'source-local')
        (source / 'release').mkdir(parents=True)
        policy_source = Path(support_matrix.__file__).resolve().parents[1] / 'release/support-matrix.json'
        shutil.copyfile(policy_source, source / 'release/support-matrix.json')
        caches, commands = [], []

        def git(arguments, **kwargs):
            commands.append(arguments)
            self.assertEqual(arguments[:2], ['git', 'worktree'])
            self.assertNotIn('--force', arguments)
            if arguments[2] == 'add':
                checkout = Path(arguments[4])
                (checkout / 'release').mkdir(parents=True)
                shutil.copyfile(policy_source, checkout / 'release/support-matrix.json')
            else:
                shutil.rmtree(Path(arguments[3]))
            return subprocess.CompletedProcess(arguments, 0)

        def build(root, tag, output, work, commit, *, parent_environment):
            caches.append(parent_environment['GOCACHE'])
            if fail:
                raise ValueError('synthetic build failure')
            bundle = Path(output).parent
            for path in repro.artifact_paths(self.policy, tag):
                target = bundle / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(('fixture bytes ' + path).encode())
            return {'go_version': 'go1.27.2', 'source_date_epoch': 1700000000,
                    'build_recipe_version': release_artifacts.RECIPE_VERSION}

        with mock.patch.object(repro.release_build, 'source_identity', return_value=COMMIT), \
                mock.patch.object(repro.release_build, 'build_release', side_effect=build), \
                mock.patch.object(repro.subprocess, 'run', side_effect=git), \
                contextlib.redirect_stderr(io.StringIO()):
            if fail:
                with self.assertRaises(ValueError):
                    repro.repeat_builds(source, self.root / 'failed-repeats', TAG, COMMIT)
                result = None
            else:
                result = repro.repeat_builds(source, self.root / 'repeats', TAG, COMMIT)
        return result, caches, commands

    def test_local_repetition_uses_distinct_caches_and_removes_only_clean_owned_worktrees(self):
        result, caches, commands = self.local_repeat_fixture()
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['execution_scope'], 'two-local-worktrees-with-separate-build-caches')
        self.assertEqual(len(caches), 2)
        self.assertNotEqual(caches[0], caches[1])
        self.assertEqual([command[2] for command in commands], ['add', 'remove', 'add', 'remove'])

    def test_failed_local_build_preserves_its_owned_worktree(self):
        _, caches, commands = self.local_repeat_fixture(fail=True)
        self.assertEqual(len(caches), 1)
        self.assertEqual([command[2] for command in commands], ['add'])
        self.assertTrue(Path(commands[0][4]).is_dir())

    def test_comparison_cli_exit_codes_diff_output_and_overwrite_protection(self):
        output = self.root / 'comparison.json'
        arguments = [sys.executable, str(Path(repro.__file__)), 'compare', '--first', str(self.first),
                     '--second', str(self.second), '--tag', TAG, '--expected-commit', COMMIT,
                     '--output', str(output)]
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(output.read_text())['passed'])
        original = output.read_bytes()
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_bytes(), original)
        output.unlink()
        (self.second / repro.REPORT_NAME).write_text('PRIVATE_INVALID')
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(output.read_text())['passed'])
        self.assertNotIn('PRIVATE', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
