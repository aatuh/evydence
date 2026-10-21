#!/usr/bin/env python3
"""Real local Git fixtures for changelog source coverage and provenance."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import change_fragments
from test_change_fragments import fragment
from test_release_lifecycle import policy as lifecycle_policy

SCRIPT = Path(__file__).with_name('release_history.py')
SPEC = importlib.util.spec_from_file_location('release_history', SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('cannot load release history checker')
HISTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HISTORY)


class ReleaseHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                                GIT_AUTHOR_NAME='fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                                GIT_COMMITTER_NAME='fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                                GIT_AUTHOR_DATE='2000-01-01T00:00:00Z',
                                GIT_COMMITTER_DATE='2000-01-01T00:00:00Z')
        self.git('init', '--initial-branch=master')
        self.write('CHANGELOG.md', '# Changelog\n\n## Unreleased\n\n- Released fixture.\n\n## v1.0.0-rc.1 - 2000-01-01\n\nPublished.\n')
        self.write('release/lifecycle-policy.json', json.dumps(lifecycle_policy()))
        self.write('internal/source.go', 'package fixture\n')
        self.release = self.commit('feat: released fixture')
        self.metadata = {'repository': 'aatuh/evydence', 'current_public_release': {
            'tag': 'v1.0.0-rc.1', 'source_commit': self.release}}
        self.write('release/current.json', json.dumps(self.metadata))
        self.write('CHANGELOG.md', '# Changelog\n\n## Unreleased\n\n- Earlier source work.\n\n## v1.0.0-rc.1 - 2000-01-01\n\nPublished.\n')
        self.write('internal/source.go', 'package fixture\n// earlier source\n')
        self.adoption = self.commit('feat: earlier source snapshot')
        body = change_fragments.section((self.root / 'CHANGELOG.md').read_text(), 'Unreleased')[0]
        self.policy = {'schema': 'evydence-change-policy.v1', 'adoption_commit': self.adoption,
                       'legacy_release_commit': self.release,
                       'legacy_section_sha256': hashlib.sha256(body.encode()).hexdigest()}
        self.write('changes/policy.json', json.dumps(self.policy))

    def git(self, *arguments):
        result = subprocess.run(['git', '-c', 'core.hooksPath=' + os.devnull, *arguments],
                                cwd=self.root, env=self.environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def commit(self, message):
        self.git('add', '--all')
        self.git('commit', '--quiet', '--message', message)
        return self.git('rev-parse', 'HEAD')

    def add_fragment(self, identifier='EVY-1408-release-history', detail=None):
        value = fragment(identifier)
        if detail:
            value['details'].append(detail)
        self.write('changes/fragments/' + identifier + '.json', json.dumps(value))
        return value

    def adopt(self):
        self.add_fragment()
        return self.commit('feat: introduce fragments')

    def test_source_changes_require_a_fragment_even_with_a_maintenance_subject(self):
        self.add_fragment()
        self.commit('feat: introduce fragment policy')
        self.write('internal/source.go', 'package fixture\n// material source change\n')
        missing = self.commit('chore: this is still user-visible source')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)
        seen = []
        plan = HISTORY.inspect(self.root, exemption=lambda sha: seen.append(sha) is None and sha == missing)
        self.assertEqual(seen, [missing])
        self.assertTrue(plan['include_legacy'])

    def test_worktree_source_and_untracked_fragment_are_checked_before_commit(self):
        self.write('scripts/operator.py', 'print("fixture")\n')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)
        value = self.add_fragment()
        plan = HISTORY.inspect(self.root)
        self.assertEqual(plan['fragments'], [value])
        self.assertIn('scripts/operator.py', plan['changed_paths'])
        self.assertEqual(plan['source_commit'], self.adoption)

    def test_changed_fragment_covers_its_delivery_but_an_older_fragment_does_not(self):
        self.adopt()
        self.write('internal/source.go', 'package fixture\n// changed with notes\n')
        value = self.add_fragment(detail='Document this delivery explicitly.')
        self.commit('feat: change with matching note update')
        self.assertEqual(HISTORY.inspect(self.root)['fragments'], [value])

    def test_test_only_and_tracking_changes_do_not_need_new_release_entries(self):
        self.adopt()
        self.write('internal/source_test.go', 'package fixture\n')
        self.write('scripts/test_fixture.py', '# fixture\n')
        self.write('.EVYDENCE_CODEX_BACKLOG.md', 'tracking fixture\n')
        self.commit('test: add characterization and tracking')
        self.assertEqual(len(HISTORY.inspect(self.root)['fragments']), 1)

    def test_unknown_paths_are_conservatively_user_visible(self):
        self.adopt()
        self.write('new-operator-interface.txt', 'new behavior\n')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)

    def test_provider_failure_cannot_turn_missing_notes_into_success(self):
        self.adopt()
        self.write('internal/source.go', 'package fixture\n// missing notes\n')
        self.commit('fix: source with no note')
        def unavailable(_sha):
            raise RuntimeError('PRIVATE_PROVIDER_CANARY')
        with self.assertRaises(HISTORY.HistoryError) as caught:
            HISTORY.inspect(self.root, exemption=unavailable)
        self.assertNotIn('PRIVATE_PROVIDER_CANARY', str(caught.exception))
        for value in [None, False, 'true', 1]:
            with self.subTest(value=value), self.assertRaises(HISTORY.HistoryError):
                HISTORY.inspect(self.root, exemption=lambda _sha: value)

    def test_git_blob_size_and_fragment_duplicate_keys_are_bounded(self):
        self.adopt()
        self.write('large.txt', 'x' * 200)
        commit = self.commit('feat: requires an explicit note')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.Repository(self.root).blob(commit, 'large.txt', limit=16)
        self.write('changes/fragments/EVY-1408-bad.json', '{"schema":"one","schema":"two"}')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)

    def test_cli_draft_then_atomic_write_and_exact_check(self):
        self.add_fragment()
        before = (self.root / 'CHANGELOG.md').read_bytes()
        base = ['python3', str(SCRIPT), '--root', str(self.root)]
        checked = subprocess.run([*base, 'check'], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 2)
        draft = subprocess.run([*base, 'render'], capture_output=True, text=True)
        self.assertEqual(draft.returncode, 0, draft.stderr)
        self.assertIn('Historical source snapshot', draft.stdout)
        self.assertEqual((self.root / 'CHANGELOG.md').read_bytes(), before)
        written = subprocess.run([*base, 'render', '--write'], capture_output=True, text=True)
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual((self.root / 'CHANGELOG.md').read_text(), draft.stdout)
        self.assertEqual(subprocess.run([*base, 'check'], capture_output=True).returncode, 0)

    def test_cli_invalid_notes_preserve_existing_changelog_and_hide_payload(self):
        self.add_fragment()
        path = self.root / 'changes/fragments/EVY-1408-release-history.json'
        path.write_text('PRIVATE_INVALID_JSON_CANARY')
        before = (self.root / 'CHANGELOG.md').read_bytes()
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root), 'render', '--write'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('PRIVATE_INVALID_JSON_CANARY', result.stdout + result.stderr)
        self.assertEqual((self.root / 'CHANGELOG.md').read_bytes(), before)

    def test_atomic_write_rejects_symlinks_and_concurrent_edits_and_cleans_own_temp(self):
        target = self.root / 'CHANGELOG.md'
        before = target.read_text()
        outside = self.root / 'untouched.txt'
        outside.write_text('untouched')
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.replace_changelog(self.root, before, 'replacement')
        self.assertEqual(outside.read_text(), 'untouched')
        target.unlink()
        target.write_text(before)
        reader = HISTORY.lifecycle.read_bytes
        def concurrent_edit(root, relative, limit):
            target.write_text('preserve concurrent edit')
            return reader(root, relative, limit)
        with patch.object(HISTORY.lifecycle, 'read_bytes', side_effect=concurrent_edit):
            with self.assertRaises(HISTORY.HistoryError):
                HISTORY.replace_changelog(self.root, before, 'replacement')
        self.assertEqual(target.read_text(), 'preserve concurrent edit')
        self.assertEqual(list(self.root.glob('.evydence-changelog-*')), [])

    def test_published_note_cannot_cover_delivery_even_if_later_reverted(self):
        published = self.adopt()
        self.metadata['current_public_release'].update(tag='v1.0.0-rc.2', source_commit=published)
        self.write('release/current.json', json.dumps(self.metadata))
        self.add_fragment('EVY-1408-next-delivery')
        self.commit('feat: start next release')
        old = (self.root / 'changes/fragments/EVY-1408-release-history.json').read_text()
        self.write('internal/source.go', 'package fixture\n// changed\n')
        self.add_fragment(detail='Misusing a published note to cover this change.')
        self.commit('feat: changes use an immutable old note')
        self.write('changes/fragments/EVY-1408-release-history.json', old)
        self.commit('chore: restore old note')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)

    def test_published_fragments_are_immutable_and_excluded_from_new_notes(self):
        published = self.adopt()
        self.metadata['current_public_release'].update(tag='v1.0.0-rc.2', source_commit=published)
        self.write('release/current.json', json.dumps(self.metadata))
        newer = self.add_fragment('EVY-1408-next-delivery')
        plan = HISTORY.inspect(self.root)
        self.assertFalse(plan['include_legacy'])
        self.assertEqual(plan['fragments'], [newer])
        self.add_fragment(detail='Trying to edit a published note.')
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)

    def test_symlinked_or_mismatched_fragment_identity_is_rejected(self):
        path = self.root / 'changes/fragments/EVY-1408-release-history.json'
        self.add_fragment()
        elsewhere = self.root / 'outside.json'
        elsewhere.write_text(path.read_text())
        path.unlink()
        path.symlink_to(elsewhere)
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)
        path.unlink()
        self.write(str(path.relative_to(self.root)), json.dumps(fragment('EVY-1408-another-identity')))
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)

    def test_policy_must_bind_available_ancestor_and_exact_legacy_bytes(self):
        self.add_fragment()
        self.policy['adoption_commit'] = '0' * 40
        self.write('changes/policy.json', json.dumps(self.policy))
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)
        self.policy['adoption_commit'] = self.adoption
        self.policy['legacy_section_sha256'] = '0' * 64
        self.write('changes/policy.json', json.dumps(self.policy))
        with self.assertRaises(HISTORY.HistoryError):
            HISTORY.inspect(self.root)


if __name__ == '__main__':
    unittest.main()
