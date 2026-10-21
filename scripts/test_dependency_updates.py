#!/usr/bin/env python3
"""Check Dependabot coverage and separate version/security update policies offline."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class DependencyUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = yaml.load((ROOT / '.github/dependabot.yml').read_text(), Loader=yaml.BaseLoader)
        cls.updates = cls.config['updates']

    def test_update_entries_cover_current_manifests_without_duplicate_scopes(self):
        expected = {
            ('gomod', '/'): 'go.mod',
            ('gomod', '/tools'): 'tools/go.mod',
            ('npm', '/site/marketing'): 'site/marketing/package-lock.json',
            ('pip', '/tools'): 'tools/requirements-qa.txt',
            ('github-actions', '/'): '.github/workflows/ci.yml',
            ('docker', '/'): 'Dockerfile',
            ('docker', '/deploy/local-dependencies'): 'deploy/local-dependencies/Dockerfile',
        }
        scopes = [(entry['package-ecosystem'], entry['directory']) for entry in self.updates]
        self.assertEqual(len(scopes), len(set(scopes)))
        self.assertEqual(set(scopes), set(expected))
        for path in expected.values():
            with self.subTest(manifest=path):
                self.assertTrue((ROOT / path).is_file())
        self.assertEqual(self.config['version'], '2')

    def test_routine_updates_have_a_bounded_weekly_queue(self):
        for entry in self.updates:
            with self.subTest(ecosystem=entry['package-ecosystem'], directory=entry['directory']):
                self.assertEqual(entry['schedule']['interval'], 'weekly')
                self.assertGreaterEqual(int(entry['open-pull-requests-limit']), 1)
                self.assertLessEqual(int(entry['open-pull-requests-limit']), 5)
                self.assertIn('dependencies', entry['labels'])

    def test_routine_groups_include_minor_and_patch_but_leave_major_updates_separate(self):
        for entry in self.updates:
            with self.subTest(ecosystem=entry['package-ecosystem'], directory=entry['directory']):
                groups = [group for group in entry.get('groups', {}).values()
                          if group.get('applies-to') == 'version-updates']
                self.assertEqual(len(groups), 1)
                self.assertEqual(groups[0]['patterns'], ['*'])
                self.assertCountEqual(groups[0]['update-types'], ['minor', 'patch'])
                self.assertNotIn('exclude-patterns', groups[0])
                self.assertNotIn('dependency-type', groups[0])

    def test_security_groups_include_major_fixes_and_development_dependencies(self):
        for entry in self.updates:
            with self.subTest(ecosystem=entry['package-ecosystem'], directory=entry['directory']):
                groups = [group for group in entry.get('groups', {}).values()
                          if group.get('applies-to') == 'security-updates']
                self.assertEqual(len(groups), 1)
                self.assertEqual(groups[0], {'applies-to': 'security-updates', 'patterns': ['*']})

    def test_updates_use_default_branch_and_do_not_suppress_or_execute_dependencies(self):
        self.assertEqual(set(self.config), {'version', 'updates'})
        allowed = {'package-ecosystem', 'directory', 'schedule', 'open-pull-requests-limit',
                   'labels', 'groups'}
        for entry in self.updates:
            with self.subTest(ecosystem=entry['package-ecosystem'], directory=entry['directory']):
                # No target-branch override, ignored versions, external code execution,
                # registry credentials or merge/check-bypass configuration.
                self.assertEqual(set(entry), allowed)
                self.assertEqual(len(entry['groups']), 2)


if __name__ == '__main__':
    unittest.main()
