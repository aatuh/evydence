#!/usr/bin/env python3
"""Offline provider fixtures for exact-source changelog exemptions."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

import release_change_provider as provider


BASE = 'b' * 40
HEAD = 'c' * 40
MERGE = 'd' * 40


def pull(merged=False, labelled=True):
    return {'number': 42, 'state': 'closed' if merged else 'open', 'merged': merged,
            'merged_at': '2000-01-01T00:00:00Z' if merged else None,
            'merge_commit_sha': MERGE,
            'base': {'sha': BASE, 'ref': 'master', 'repo': {'full_name': 'aatuh/evydence'}},
            'head': {'sha': HEAD, 'repo': {'full_name': 'contributor/evydence'}},
            'labels': [{'name': 'no-changelog'}] if labelled else []}


class FakeGitHub(provider.GitHub):
    def __init__(self, responses):
        self.responses = responses
        self.seen = []

    def get(self, endpoint):
        self.seen.append(endpoint)
        value = self.responses[endpoint]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


class ReleaseChangeProviderTests(unittest.TestCase):
    def test_open_pr_context_binds_source_repository_state_and_exact_label(self):
        client = FakeGitHub({'pulls/42': pull()})
        self.assertEqual(client.open_pull(42), {'number': 42, 'base_commit': BASE,
                         'head_commit': HEAD, 'no_changelog': True})
        client.responses['pulls/42']['labels'] = [{'name': 'No-Changelog'}]
        self.assertFalse(client.open_pull(42)['no_changelog'])

    def test_wrong_repository_branch_identity_state_and_labels_fail_closed(self):
        mutations = [lambda x: x.update(number=43), lambda x: x.update(number=True),
                     lambda x: x.update(state='closed'), lambda x: x.update(merged=True),
                     lambda x: x.update(merged_at='2000-01-01T00:00:00Z'),
                     lambda x: x['base']['repo'].update(full_name='attacker/evydence'),
                     lambda x: x['base'].update(ref='other', sha=BASE),
                     lambda x: x['head'].update(sha='HEAD'),
                     lambda x: x.update(labels=[{'name': None}])]
        for mutate in mutations:
            value = pull()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(provider.ProviderError):
                FakeGitHub({'pulls/42': value}).open_pull(42)
        for number in [True, 0, -1, '42;echo unsafe']:
            with self.subTest(number=number), self.assertRaises(provider.ProviderError):
                FakeGitHub({}).open_pull(number)

    def test_merged_exemption_uses_full_detail_and_exact_delivery_sha(self):
        listing = 'commits/' + MERGE + '/pulls?per_page=100&page=1'
        client = FakeGitHub({listing: [pull(True)], 'pulls/42': pull(True)})
        self.assertTrue(client.merged_exemption(MERGE))
        self.assertEqual(client.seen, [listing, 'pulls/42'])
        client.responses['pulls/42']['labels'] = []
        self.assertFalse(client.merged_exemption(MERGE))
        client.responses['pulls/42'] = pull(False)
        with self.assertRaises(provider.ProviderError):
            client.merged_exemption(MERGE)

    def test_associated_open_or_other_merge_pr_cannot_waive_a_delivery(self):
        listing = 'commits/' + MERGE + '/pulls?per_page=100&page=1'
        wrong = pull(True)
        wrong['merge_commit_sha'] = HEAD
        opened = pull(False)
        opened['number'] = 43
        client = FakeGitHub({listing: [wrong, opened]})
        self.assertFalse(client.merged_exemption(MERGE))
        self.assertEqual(client.seen, [listing])

    def test_provider_errors_and_invalid_bounded_collections_never_become_success(self):
        for data in [None, {}, [{'number': True}], [pull(True)] * 2, [pull(True)] * 101]:
            endpoint = 'commits/' + MERGE + '/pulls?per_page=100&page=1'
            with self.subTest(data=data), self.assertRaises(provider.ProviderError):
                FakeGitHub({endpoint: data, 'pulls/42': pull(True)}).merged_exemption(MERGE)

    def test_transport_has_fixed_get_host_bounded_output_and_closed_child_environment(self):
        captured = []
        def run(argv, workspace, environment, maximum, timeout):
            captured.append((argv, environment, maximum, timeout))
            return b'' if argv[1] == 'auth' else json.dumps(pull()).encode()
        with tempfile.TemporaryDirectory() as directory:
            environment = {'PATH': os.environ['PATH'], 'HOME': directory, 'GH_TOKEN': 'READ_TOKEN_CANARY',
                           'GH_HOST': 'attacker.invalid', 'GH_DEBUG': 'api',
                           'EVYDENCE_RELEASE_PUBLISH_TOKEN': 'PUBLISHER_CANARY'}
            with patch.dict(os.environ, environment, clear=True), patch.object(provider, 'capture', side_effect=run):
                self.assertEqual(provider.GitHub().open_pull(42)['head_commit'], HEAD)
        self.assertEqual(len(captured), 2)
        argv, child, maximum, timeout = captured[-1]
        self.assertIn('--method', argv)
        self.assertIn('GET', argv)
        self.assertEqual(argv[argv.index('--hostname') + 1], 'github.com')
        self.assertEqual(argv[-1], 'repos/aatuh/evydence/pulls/42')
        self.assertLessEqual(maximum, 1024 * 1024)
        self.assertLessEqual(timeout, 30)
        self.assertEqual(child['GH_TOKEN'], 'READ_TOKEN_CANARY')
        self.assertNotIn('GH_HOST', child)
        self.assertNotIn('GH_DEBUG', child)
        self.assertNotIn('EVYDENCE_RELEASE_PUBLISH_TOKEN', child)
        self.assertNotIn('READ_TOKEN_CANARY', ' '.join(argv))

    def test_transport_hides_malformed_private_responses_and_cli_failures(self):
        for raw in [b'{PRIVATE_PROVIDER_CANARY', b'{"number":1,"number":2}', b'{"number":NaN}']:
            with patch.object(provider, 'capture', return_value=raw):
                with self.assertRaises(provider.ProviderError) as caught:
                    provider.GitHub().get('pulls/42')
                self.assertNotIn('PRIVATE_PROVIDER_CANARY', str(caught.exception))
        with patch.object(provider, 'capture', side_effect=ValueError('PRIVATE_PROVIDER_CANARY')):
            with self.assertRaises(provider.ProviderError) as caught:
                provider.GitHub().get('pulls/42')
            self.assertNotIn('PRIVATE_PROVIDER_CANARY', str(caught.exception))

    def test_ci_label_events_keep_read_only_source_binding_and_full_history(self):
        workflow = yaml.load((provider.ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertNotIn('pull_request_target', workflow['on'])
        self.assertTrue({'labeled', 'unlabeled', 'synchronize'}.issubset(workflow['on']['pull_request']['types']))
        job = workflow['jobs']['production-check']
        self.assertEqual(job['permissions'], {'contents': 'read', 'pull-requests': 'read'})
        self.assertEqual(job['env']['GH_TOKEN'], '${{ github.token }}')
        self.assertEqual(job['env']['EVYDENCE_CHANGELOG_PULL_REQUEST'], '${{ github.event.pull_request.number }}')
        checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['fetch-depth'], '0')


if __name__ == '__main__':
    unittest.main()
