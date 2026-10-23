#!/usr/bin/env python3
"""Structured changes and immutable legacy changelog regression tests."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).with_name('change_fragments.py')
SPEC = importlib.util.spec_from_file_location('change_fragments', SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('cannot load fragment parser')
FRAGMENTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FRAGMENTS)

LEGACY = 'Previously implemented source change.\n\n- Preserved evidence and [guide](docs/guide.md).\n\n'
PUBLISHED = '## v1.2.3-rc.1 - 2000-01-01\n\nOriginal published notes.\n'
CHANGELOG = '# Changelog\n\n## Unreleased\n\n' + LEGACY + PUBLISHED


def policy():
    return {'schema': 'evydence-change-policy.v1', 'adoption_commit': 'a' * 40,
            'legacy_release_commit': 'b' * 40,
            'legacy_section_sha256': hashlib.sha256(LEGACY.encode()).hexdigest()}


def fragment(identifier='EVY-1408-release-history'):
    return {'schema': 'evydence-change-fragment.v1', 'id': identifier,
            'category': 'changed', 'summary': 'Preserve release history with versioned changes',
            'details': ['Require source changes to carry an explicit fragment.'],
            'compatibility': {'api': 'unchanged', 'sdk': 'unchanged', 'migrations': 'none',
                              'notes': 'No HTTP or persistence contract change.'},
            'security': 'Release metadata checks preserve publisher verification.',
            'limitations': ['Source review and publication remain separate owner decisions.']}


class ChangeFragmentTests(unittest.TestCase):
    def test_valid_fragment_and_policy_have_no_claimed_external_review(self):
        self.assertEqual(FRAGMENTS.validate_fragment(fragment()), fragment())
        self.assertEqual(FRAGMENTS.validate_policy(policy()), policy())
        value = fragment()
        value['reviewed'] = True
        with self.assertRaises(FRAGMENTS.ChangeError):
            FRAGMENTS.validate_fragment(value)

    def test_invalid_identity_shape_impact_and_public_text_fail_closed(self):
        mutations = [
            lambda f: f.update(id='../escape'),
            lambda f: f.update(category='unknown'),
            lambda f: f.update(summary='No unreleased changes.'),
            lambda f: f.update(summary=' \t '),
            lambda f: f.update(summary='private\x1b[2J'),
            lambda f: f.update(summary='invalid\ud800'),
            lambda f: f.update(details=[]),
            lambda f: f.update(details=['x' * 4097]),
            lambda f: f['compatibility'].update(api='always-compatible'),
            lambda f: f['compatibility'].update(migrations='unknown'),
            lambda f: f.update(security=''),
            lambda f: f.update(limitations=['spoof\u202eorder']),
        ]
        for mutate in mutations:
            value = fragment()
            mutate(value)
            with self.subTest(fragment=value), self.assertRaises(FRAGMENTS.ChangeError):
                FRAGMENTS.validate_fragment(value)

    def test_filename_identity_and_duplicate_fragment_ids_are_rejected(self):
        with self.assertRaises(FRAGMENTS.ChangeError):
            FRAGMENTS.validate_fragment(fragment(), expected_id='EVY-1408-other')
        with self.assertRaises(FRAGMENTS.ChangeError):
            FRAGMENTS.render_unreleased([fragment(), fragment()], policy(), include_legacy=True)

    def test_update_preserves_exact_manual_history_and_published_notes(self):
        output = FRAGMENTS.update_changelog(CHANGELOG, [fragment()], policy(), include_legacy=True)
        heading = '## Historical source snapshot aaaaaaaa (not a release)'
        self.assertIn(heading + '\n\n' + LEGACY, output)
        self.assertTrue(output.endswith(PUBLISHED))
        self.assertIn('Preserve release history', output)
        self.assertIn('#historical-source-snapshot-aaaaaaaa-not-a-release', output)
        self.assertNotIn('No unreleased changes.', FRAGMENTS.section(output, 'Unreleased')[0])
        self.assertEqual(FRAGMENTS.update_changelog(output, [fragment()], policy(), include_legacy=True), output)

    def test_stale_manual_or_mutated_frozen_history_cannot_be_silently_rewritten(self):
        with self.assertRaises(FRAGMENTS.ChangeError):
            FRAGMENTS.update_changelog(CHANGELOG.replace('Previously', 'Changed'), [fragment()], policy())
        output = FRAGMENTS.update_changelog(CHANGELOG, [fragment()], policy())
        with self.assertRaises(FRAGMENTS.ChangeError):
            FRAGMENTS.update_changelog(output.replace('Previously', 'Changed'), [fragment()], policy())

    def test_new_entries_render_deterministically_without_input_mutation(self):
        first = fragment('EVY-1408-zeta')
        second = fragment('EVY-1408-alpha')
        second['category'] = 'security'
        original = copy.deepcopy([first, second])
        a = FRAGMENTS.update_changelog(CHANGELOG, [first, second], policy())
        b = FRAGMENTS.update_changelog(CHANGELOG, [second, first], policy())
        self.assertEqual(a, b)
        self.assertEqual([first, second], original)

    def test_no_changes_is_allowed_only_without_new_entries_or_legacy_range(self):
        text = FRAGMENTS.render_unreleased([], policy(), include_legacy=False)
        self.assertIn('- No unreleased changes.', text)
        self.assertNotIn('No unreleased changes.', FRAGMENTS.render_unreleased([], policy(), include_legacy=True))
        exempted = FRAGMENTS.render_unreleased([], policy(), include_legacy=False,
                                               exempt_commits=['c' * 40])
        self.assertNotIn('No unreleased changes.', exempted)
        self.assertIn('no-changelog', exempted)
        self.assertEqual(exempted, FRAGMENTS.render_unreleased([], policy(), include_legacy=False,
                                                               exempt_commits=['d' * 40]))

    def test_fragment_text_is_plain_markdown_without_html_or_link_execution(self):
        value = fragment()
        value['summary'] = '<img src=x> | [click](javascript:unsafe)'
        text = FRAGMENTS.render_unreleased([value], policy(), include_legacy=False)
        self.assertNotIn('<img', text)
        self.assertNotIn('[click](javascript:', text)

    def test_exempt_sources_are_bounded_commit_identities(self):
        for values in ['c' * 40, ['invalid'], [None], ['a' * 40] * 513]:
            with self.subTest(values=values), self.assertRaises(FRAGMENTS.ChangeError):
                FRAGMENTS.render_unreleased([], policy(), exempt_commits=values)


if __name__ == '__main__':
    unittest.main()
