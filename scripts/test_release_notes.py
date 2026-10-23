#!/usr/bin/env python3
"""Release notes from real source ranges; no builds or provider calls."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_release_history as history_fixture
import test_release_lifecycle as lifecycle_fixture
import release_notes as notes

TAG = 'v1.0.0-rc.2'
ROOT = Path(__file__).resolve().parents[1]


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.fixture = history_fixture.ReleaseHistoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.path = 'docs/reference/release-notes-' + TAG + '.md'
        self.fixture.write('docs/reference/release-notes-template.md',
                           (ROOT / 'docs/reference/release-notes-template.md').read_text())
        self.fixture.add_fragment()

    def record(self):
        plan = notes.history.inspect(self.root)
        self.fixture.write('CHANGELOG.md', notes.changes.update_changelog(
            plan['changelog'], plan['fragments'], plan['policy'], plan['include_legacy']))
        self.fixture.write(self.path, notes.generate(self.root, TAG))
        self.fixture.commit('feat: record matching release notes and fragments')

    def test_notes_are_deterministic_and_cover_compatibility_security_and_limits(self):
        first = notes.generate(self.root, TAG)
        self.assertEqual(first, notes.generate(self.root, TAG))
        for heading in ['Changes', 'API Compatibility', 'Database Migrations', 'SDK Compatibility',
                        'Security Notices', 'Known Limitations', 'Support Window']:
            self.assertIn('## ' + heading + '\n', first)
        self.assertIn('No database migration files changed', first)
        self.assertIn('No OpenAPI contract file change', first)
        self.assertIn('No SDK files changed', first)
        self.assertIn('Preserve release history', first)
        self.assertIn('not a certification', first)
        self.assertNotIn('No unreleased changes', first)
        self.assertNotIn('{{', first)
        self.assertNotIn('Full repository decomposition remains', first)
        self.assertIn(self.fixture.adoption, first)
        self.assertNotIn(str(self.root), first)

    def test_actual_api_sdk_and_migration_inventory_requires_matching_declarations(self):
        for path in ['openapi.yaml', 'sdk/client.py', 'migrations/002_new.sql']:
            self.fixture.write(path, '# changed fixture\n')
        with self.assertRaises(notes.NotesError):
            notes.generate(self.root, TAG)
        value = self.fixture.add_fragment()
        value['compatibility'].update(api='changed', sdk='changed', migrations='required')
        self.fixture.write('changes/fragments/' + value['id'] + '.json', json.dumps(value))
        result = notes.generate(self.root, TAG)
        for path in ['openapi.yaml', 'sdk/client.py', 'migrations/002_new.sql']:
            self.assertIn(path, result)
        self.assertIn('Review the upgrade', result)

    def test_prior_adoption_api_changes_are_inventory_without_forged_current_fragment_impact(self):
        self.fixture.write('openapi.yaml', '# changed public contract before adoption\n')
        self.fixture.adoption = self.fixture.commit('feat: legacy API work')
        self.fixture.policy['adoption_commit'] = self.fixture.adoption
        self.fixture.write('changes/policy.json', json.dumps(self.fixture.policy))
        self.fixture.add_fragment(detail='Document new post-adoption tooling delivery.')
        result = notes.generate(self.root, TAG)
        self.assertIn('openapi.yaml', result)
        self.assertIn('Earlier source changes', result)

    def test_missing_contradictory_or_injected_template_fails_without_payload_echo(self):
        template = self.root / 'docs/reference/release-notes-template.md'
        original = template.read_text()
        for changed in [original.replace('{{MIGRATIONS}}', ''), original + '\n{{PRIVATE_CANARY}}',
                        original.replace('## Database Migrations', '## Unknown Heading'),
                        original.replace('not a certification', 'a certification'),
                        original + '\nSBOM is complete\n']:
            template.write_text(changed)
            with self.assertRaises(notes.NotesError) as caught:
                notes.generate(self.root, TAG)
            self.assertNotIn('PRIVATE_CANARY', str(caught.exception))
        template.unlink()
        with self.assertRaises(notes.NotesError):
            notes.generate(self.root, TAG)

    def test_only_exact_matching_committed_notes_pass_release_preflight(self):
        with self.assertRaises(notes.NotesError):
            notes.validate_reviewed(self.root, TAG)
        self.record()
        self.assertEqual(notes.validate_reviewed(self.root, TAG), notes.generate(self.root, TAG))
        target = self.root / self.path
        target.write_text(target.read_text().replace('not a certification', 'a certification'))
        with self.assertRaises(notes.NotesError):
            notes.validate_reviewed(self.root, TAG)

    def test_notes_symlinks_and_dirty_source_cannot_be_used_for_tagging(self):
        self.record()
        self.fixture.write('sdk/client.py', '# pending unreviewed SDK change\n')
        with self.assertRaises(notes.NotesError):
            notes.validate_reviewed(self.root, TAG)
        target = self.root / self.path
        external = self.root / 'other-notes.md'
        external.write_text(target.read_text())
        target.unlink()
        target.symlink_to(external)
        with self.assertRaises(notes.NotesError):
            notes.validate_reviewed(self.root, TAG)

    def test_tag_command_defaults_to_no_mutation_and_missing_notes_create_no_tag(self):
        script = ROOT / 'scripts/release_notes.py'
        base = ['python3', str(script), '--root', str(self.root), '--tag', TAG, 'tag']
        missing = subprocess.run([*base, '--create'], capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.fixture.git('tag', '--list'), '')
        self.record()
        preview = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(self.fixture.git('tag', '--list'), '')
        created = subprocess.run([*base, '--create'], capture_output=True, text=True,
                                 env=self.fixture.environment)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(self.fixture.git('rev-parse', TAG + '^{commit}'), self.fixture.git('rev-parse', 'HEAD'))
        duplicate = subprocess.run([*base, '--create'], capture_output=True, text=True)
        self.assertEqual(duplicate.returncode, 2)

    def test_wrong_branch_and_withdrawn_tag_cannot_create_a_local_tag(self):
        self.record()
        self.fixture.git('checkout', '-b', 'handoff-documentation')
        base = ['python3', str(ROOT / 'scripts/release_notes.py'), '--root', str(self.root),
                '--tag', TAG, 'tag', '--create']
        self.assertEqual(subprocess.run(base, capture_output=True).returncode, 2)
        self.assertEqual(self.fixture.git('tag', '--list'), '')
        self.fixture.git('checkout', 'master')
        policy = lifecycle_fixture.policy()
        policy['withdrawals'].append(lifecycle_fixture.withdrawal(TAG))
        self.fixture.write('release/lifecycle-policy.json', json.dumps(policy))
        with self.assertRaises(notes.NotesError):
            notes.generate(self.root, TAG)
        self.assertEqual(subprocess.run(base, capture_output=True).returncode, 2)
        self.assertEqual(self.fixture.git('tag', '--list'), '')

    def test_packaged_notes_must_equal_the_exact_committed_generated_text(self):
        self.fixture.write('.gitignore', 'dist/\n')
        self.record()
        path = 'dist/' + TAG + '/release-notes.md'
        self.fixture.write(path, notes.generate(self.root, TAG))
        base = ['python3', str(ROOT / 'scripts/release_notes.py'), '--root', str(self.root),
                '--tag', TAG, 'check-artifact']
        valid = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.fixture.write(path, 'private invalid release notes CANARY')
        invalid = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn('CANARY', invalid.stdout + invalid.stderr)

    def test_source_commit_change_during_note_validation_is_rejected(self):
        self.record()
        original = notes.generate(self.root, TAG)
        def changed_source(*_args, **_kwargs):
            self.fixture.write('.EVYDENCE_CODEX_BACKLOG.md', 'concurrent tracking commit\n')
            self.fixture.commit('docs: concurrent tracking change')
            return original
        with patch.object(notes, 'generate', side_effect=changed_source):
            with self.assertRaises(notes.NotesError):
                notes.validate_reviewed(self.root, TAG)

    def test_input_check_needs_no_candidate_tag_and_allows_recorded_current_withdrawal(self):
        policy = lifecycle_fixture.policy()
        record = lifecycle_fixture.withdrawal('v1.0.0-rc.1')
        record['source_commit'] = self.fixture.release
        policy['withdrawals'].append(record)
        self.fixture.write('release/lifecycle-policy.json', json.dumps(policy))
        result = subprocess.run(['python3', str(ROOT / 'scripts/release_notes.py'), '--root', str(self.root),
                                 'check-inputs'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('inputs: OK', result.stdout)

    def test_local_tagging_disables_hooks_and_automatic_signing_commands(self):
        self.record()
        directory = self.root / '.git' / 'untrusted-hooks'
        directory.mkdir()
        hook = directory / 'reference-transaction'
        hook.write_text('#!/bin/sh\nprintf called > hook-ran\nexit 99\n')
        hook.chmod(0o700)
        self.fixture.git('config', 'core.hooksPath', str(directory))
        self.fixture.git('config', 'tag.gpgSign', 'true')
        self.fixture.git('config', 'gpg.program', str(hook))
        result = subprocess.run(['python3', str(ROOT / 'scripts/release_notes.py'), '--root', str(self.root),
                                 '--tag', TAG, 'tag', '--create'], capture_output=True, text=True,
                                env=self.fixture.environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'hook-ran').exists())

    def test_tagging_cannot_target_a_commit_changed_after_preflight(self):
        self.record()
        original = notes.validate_reviewed
        def changed_after_validation(*args, **kwargs):
            result = original(*args, **kwargs)
            self.fixture.write('.EVYDENCE_CODEX_BACKLOG.md', 'concurrent tracking update\n')
            self.fixture.commit('docs: concurrent tracking update')
            return result
        with patch.object(notes, 'validate_reviewed', side_effect=changed_after_validation):
            result = notes.main(['--root', str(self.root), '--tag', TAG, 'tag', '--create'])
        self.assertEqual(result, 2)
        self.assertEqual(self.fixture.git('tag', '--list'), '')


if __name__ == '__main__':
    unittest.main()
