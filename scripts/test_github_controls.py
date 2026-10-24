#!/usr/bin/env python3
"""Repository-control assessment uses synthetic provider data, never the network."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import github_controls as controls


RELEASE_CHECKS = ['Production Check', 'CodeQL Analyze', 'Race and Stress']
CHECKS = RELEASE_CHECKS + ['Dependency Policy']


def protected_snapshot():
    checks = [{'context': name, 'app_id': 15368} for name in CHECKS]
    return {
        'repository': {'full_name': 'aatuh/evydence', 'default_branch': 'master',
                       'owner': {'type': 'User'},
                       'permissions': {'admin': True}, 'archived': False,
                       'security_and_analysis': {
                           'secret_scanning': {'status': 'enabled'},
                           'secret_scanning_push_protection': {'status': 'enabled'},
                           'dependabot_security_updates': {'status': 'enabled'}}},
        'branch': {'required_status_checks': {'strict': True, 'checks': checks},
                   'required_pull_request_reviews': {'required_approving_review_count': 0,
                       'dismiss_stale_reviews': True, 'require_code_owner_reviews': False,
                       'require_last_push_approval': False,
                       'bypass_pull_request_allowances': {'users': [], 'teams': [], 'apps': []}},
                   'enforce_admins': {'enabled': True},
                   'required_conversation_resolution': {'enabled': True},
                   'required_signatures': {'enabled': False},
                   'allow_force_pushes': {'enabled': False}, 'allow_deletions': {'enabled': False}},
        'collaborators': [{'login': 'aatuh', 'type': 'User', 'permissions': {'push': True}}],
        'rulesets': [{'id': 41, 'name': 'Evydence release tags', 'target': 'tag',
                     'enforcement': 'active', 'bypass_actors': [],
                     'conditions': {'ref_name': {'include': ['refs/tags/v*'], 'exclude': []}},
                     'rules': [{'type': 'update'}, {'type': 'deletion'},
                               {'type': 'required_status_checks', 'parameters': {
                                   'strict_required_status_checks_policy': False,
                                   'do_not_enforce_on_create': False,
                                   'required_status_checks': [{'context': name, 'integration_id': 15368}
                                                              for name in RELEASE_CHECKS]}}]}],
        'dependabot_alerts': {'state': 'enabled', 'http_status': 204},
        'private_reporting': {'state': 'enabled', 'http_status': 200},
        'code_scanning': {'state': 'enabled', 'http_status': 200,
                          'tool': 'CodeQL', 'commit': 'a' * 40, 'analysis_error': False},
        'remote_head': 'a' * 40,
        'observations': {},
    }


class ControlAssessmentTests(unittest.TestCase):
    def assess(self, snapshot=None):
        return controls.assess_controls(snapshot or protected_snapshot(), 'aatuh/evydence')

    def test_dependency_policy_is_a_branch_requirement_not_a_release_tag_gate(self):
        snapshot = protected_snapshot()
        checks = snapshot['branch']['required_status_checks']['checks']
        checks[:] = [row for row in checks if row['context'] != 'Dependency Policy']
        checks.append({'context': 'Dependency Policy', 'app_id': 15368})
        result = self.assess(snapshot)
        self.assertTrue(result['passed'], result)
        expected_tags = [{'context': name, 'app_id': 15368}
                         for name in ['Production Check', 'CodeQL Analyze', 'Race and Stress']]
        self.assertEqual(result['expected_required_checks'],
                         expected_tags + [{'context': 'Dependency Policy', 'app_id': 15368}])
        self.assertEqual(result.get('expected_release_tag_checks'), expected_tags)
        self.assertEqual(result['controls']['release_tags']['state'], 'passed')
        self.assertIn({'context': 'Dependency Policy', 'present': True, 'app_id': 15368},
                      result['observed_settings']['master']['required_checks'])
        for binding in ['missing', None, 7]:
            with self.subTest(binding=binding):
                changed = copy.deepcopy(snapshot)
                rows = changed['branch']['required_status_checks']['checks']
                if binding == 'missing':
                    rows[:] = [row for row in rows if row['context'] != 'Dependency Policy']
                else:
                    next(row for row in rows if row['context'] == 'Dependency Policy')['app_id'] = binding
                result = self.assess(changed)
                self.assertFalse(result['passed'])
                self.assertEqual(result['controls']['required_checks']['state'], 'failed')
                self.assertEqual(result['controls']['release_tags']['state'], 'passed')
        for missing in ['Production Check', 'CodeQL Analyze', 'Race and Stress']:
            with self.subTest(missing_release_gate=missing):
                changed = copy.deepcopy(snapshot)
                gate = changed['rulesets'][0]['rules'][-1]['parameters']['required_status_checks']
                gate[:] = [row for row in gate if row['context'] != missing]
                result = self.assess(changed)
                self.assertFalse(result['passed'])
                self.assertEqual(result['controls']['release_tags']['state'], 'failed')
                self.assertEqual(result['controls']['required_checks']['state'], 'passed')

    def test_solo_profile_requires_pull_requests_checks_and_immutable_checked_tags(self):
        result = self.assess()
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['maintainer_model']['mode'], 'solo')
        self.assertEqual(result['maintainer_model']['required_approvals'], 0)
        self.assertEqual(result['controls']['release_tags']['state'], 'passed')
        self.assertEqual(result['observed_settings']['master']['required_approvals'], 0)
        self.assertTrue(result['observed_settings']['master']['dismiss_stale_reviews'])
        self.assertEqual(result['observed_settings']['release_tags']['checked_ruleset_ids'], [41])

    def test_report_distinguishes_expected_from_observed_check_app_binding(self):
        snapshot = protected_snapshot()
        snapshot['branch']['required_status_checks']['checks'][0]['app_id'] = 7
        report = self.assess(snapshot)
        self.assertFalse(report['passed'])
        self.assertEqual(report['expected_required_checks'][0]['app_id'], 15368)
        self.assertEqual(report['observed_settings']['master']['required_checks'][0]['app_id'], 7)

    def test_second_writer_requires_an_independent_approval(self):
        snapshot = protected_snapshot()
        snapshot['collaborators'].append({'login': 'reviewer', 'type': 'User', 'permissions': {'push': True}})
        self.assertFalse(self.assess(snapshot)['passed'])
        snapshot['branch']['required_pull_request_reviews'].update(required_approving_review_count=1,
                                                                  require_last_push_approval=True)
        self.assertTrue(self.assess(snapshot)['passed'])

    def test_missing_pull_request_gate_and_admin_bypass_fail(self):
        for change, control in [('pull_request', 'pull_requests'), ('admin', 'administrator_enforcement')]:
            with self.subTest(change=change):
                snapshot = protected_snapshot()
                if change == 'pull_request':
                    snapshot['branch']['required_pull_request_reviews'] = None
                else:
                    snapshot['branch']['enforce_admins']['enabled'] = False
                self.assertEqual(self.assess(snapshot)['controls'][control]['state'], 'failed')

    def test_personal_repository_has_no_organization_bypass_allowances(self):
        snapshot = protected_snapshot()
        del snapshot['branch']['required_pull_request_reviews']['bypass_pull_request_allowances']
        self.assertTrue(self.assess(snapshot)['passed'])
        snapshot['repository']['owner']['type'] = 'Organization'
        self.assertFalse(self.assess(snapshot)['passed'])
        snapshot['repository']['owner']['type'] = 'User'
        snapshot['branch']['required_pull_request_reviews']['bypass_pull_request_allowances'] = None
        self.assertFalse(self.assess(snapshot)['passed'])

    def test_unknown_and_string_booleans_do_not_pass(self):
        for value in [None, 'true', 1, {}]:
            with self.subTest(value=value):
                snapshot = protected_snapshot()
                snapshot['branch']['enforce_admins']['enabled'] = value
                self.assertFalse(self.assess(snapshot)['passed'])

    def test_expected_check_names_app_bindings_and_strictness_are_required(self):
        for mutation in ['missing', 'wrong-app', 'loose', 'duplicate']:
            with self.subTest(mutation=mutation):
                snapshot = protected_snapshot()
                checks = snapshot['branch']['required_status_checks']
                if mutation == 'missing':
                    checks['checks'].pop()
                elif mutation == 'wrong-app':
                    checks['checks'][0]['app_id'] = 7
                elif mutation == 'duplicate':
                    checks['checks'].append(copy.deepcopy(checks['checks'][0]))
                else:
                    checks['strict'] = False
                self.assertFalse(self.assess(snapshot)['passed'])

    def test_release_rules_must_be_active_without_bypass_or_exclusions(self):
        for mutation in ['disabled', 'evaluate', 'bypass', 'missing-bypass', 'exclude', 'wrong-pattern']:
            with self.subTest(mutation=mutation):
                snapshot = protected_snapshot()
                ruleset = snapshot['rulesets'][0]
                if mutation in ['disabled', 'evaluate']:
                    ruleset['enforcement'] = mutation
                elif mutation == 'bypass':
                    ruleset['bypass_actors'] = [{'actor_type': 'RepositoryRole', 'actor_id': 5}]
                elif mutation == 'missing-bypass':
                    del ruleset['bypass_actors']
                elif mutation == 'exclude':
                    ruleset['conditions']['ref_name']['exclude'] = ['refs/tags/v0.*']
                else:
                    ruleset['conditions']['ref_name']['include'] = ['refs/tags/other*']
                self.assertFalse(self.assess(snapshot)['passed'])

    def test_tag_checks_apply_on_creation_and_cannot_be_replaced_by_immutability(self):
        for mutation in ['no-checks', 'skip-creation', 'wrong-app', 'no-update', 'no-delete']:
            with self.subTest(mutation=mutation):
                snapshot = protected_snapshot()
                rules = snapshot['rulesets'][0]['rules']
                if mutation == 'no-checks':
                    rules.pop()
                elif mutation == 'skip-creation':
                    rules[-1]['parameters']['do_not_enforce_on_create'] = True
                elif mutation == 'wrong-app':
                    rules[-1]['parameters']['required_status_checks'][0]['integration_id'] = None
                elif mutation == 'no-update':
                    rules.pop(0)
                else:
                    rules.pop(1)
                self.assertFalse(self.assess(snapshot)['passed'])

    def test_security_features_unknown_disabled_or_failed_codeql_do_not_pass(self):
        for field in ['dependabot_alerts', 'private_reporting', 'code_scanning']:
            for state in ['disabled', 'unknown']:
                with self.subTest(field=field, state=state):
                    snapshot = protected_snapshot()
                    snapshot[field] = {'state': state, 'http_status': 403}
                    self.assertFalse(self.assess(snapshot)['passed'])
        snapshot = protected_snapshot()
        snapshot['code_scanning']['analysis_error'] = True
        self.assertFalse(self.assess(snapshot)['passed'])
        snapshot = protected_snapshot()
        snapshot['code_scanning']['commit'] = 'b' * 40
        self.assertFalse(self.assess(snapshot)['passed'])

    def test_secret_scanning_push_protection_and_dependabot_updates_required(self):
        for feature in ['secret_scanning', 'secret_scanning_push_protection', 'dependabot_security_updates']:
            snapshot = protected_snapshot()
            snapshot['repository']['security_and_analysis'][feature]['status'] = 'disabled'
            self.assertFalse(self.assess(snapshot)['passed'])

    def test_wrong_repository_or_missing_admin_visibility_is_unknown(self):
        for key, value in [('full_name', 'somebody/other'), ('permissions', {'admin': False})]:
            snapshot = protected_snapshot()
            snapshot['repository'][key] = value
            self.assertFalse(self.assess(snapshot)['passed'])

    def test_provider_payload_secrets_and_extra_metadata_are_not_reported(self):
        snapshot = protected_snapshot()
        snapshot['repository']['description'] = 'PRIVATE_CANARY'
        snapshot['branch']['extra'] = {'token': 'PRIVATE_CANARY'}
        snapshot['rulesets'][0]['name'] = 'PRIVATE_CANARY'
        result = self.assess(snapshot)
        self.assertTrue(result['passed'], result)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_malformed_provider_field_types_fail_without_crashing(self):
        for mutation in ['name', 'feature', 'rule-type', 'state', 'collaborators', 'collaborator-type']:
            with self.subTest(mutation=mutation):
                snapshot = protected_snapshot()
                if mutation == 'name':
                    snapshot['repository']['full_name'] = {'PRIVATE': 'CANARY'}
                elif mutation == 'feature':
                    snapshot['repository']['security_and_analysis']['secret_scanning']['status'] = {}
                elif mutation == 'rule-type':
                    snapshot['rulesets'][0]['rules'][0]['type'] = []
                elif mutation == 'state':
                    snapshot['code_scanning']['state'] = {}
                elif mutation == 'collaborators':
                    snapshot['collaborators'] = 'PRIVATE_CANARY'
                else:
                    snapshot['collaborators'][0]['type'] = {}
                result = self.assess(snapshot)
                self.assertFalse(result['passed'])
                self.assertNotIn('PRIVATE_CANARY', json.dumps(result))


class VerifierCLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.requests = self.root / 'requests.jsonl'
        self.responses = self.root / 'responses.json'
        snapshot = protected_snapshot()
        prefix = 'repos/aatuh/evydence'
        data = {
            prefix: snapshot['repository'],
            prefix + '/branches/master/protection': snapshot['branch'],
            prefix + '/commits/master': {'sha': 'a' * 40},
            prefix + '/rulesets?includes_parents=true&per_page=100&page=1': [{'id': 41}],
            prefix + '/rulesets/41?includes_parents=true': snapshot['rulesets'][0],
            prefix + '/collaborators?affiliation=all&per_page=100&page=1': snapshot['collaborators'],
            prefix + '/code-scanning/analyses?tool_name=CodeQL&ref=refs%2Fheads%2Fmaster&per_page=1':
                [{'tool': {'name': 'CodeQL'}, 'commit_sha': 'a' * 40, 'ref': 'refs/heads/master', 'error': ''}],
            prefix + '/private-vulnerability-reporting': {'enabled': True},
        }
        self.fixture = {endpoint: {'status': 200, 'body': body} for endpoint, body in data.items()}
        self.fixture[prefix + '/vulnerability-alerts'] = {'status': 204, 'body': None}
        fake = self.bin / 'gh'
        fake.write_text('#!' + sys.executable + '\n' + '''import json,os,sys,time
from pathlib import Path
with open(os.environ['CONTROLS_REQUEST_LOG'],'a') as out:out.write(json.dumps(sys.argv[1:])+'\\n')
request=json.loads(Path(os.environ['CONTROLS_RESPONSES']).read_text()).get(sys.argv[-1])
if request is None:
 print('HTTP/2.0 500 Internal Server Error\\n\\n{"message":"PRIVATE_CANARY"}')
 sys.exit(1)
if request.get('sleep'):time.sleep(request['sleep'])
status=request['status'];print('HTTP/2.0 '+str(status)+' Fixture\\nContent-Type: application/json\\n')
if request.get('raw') is not None:print(request['raw'])
elif request.get('body') is not None:print(json.dumps(request['body']))
if status>=400:
 print('PRIVATE_CANARY provider error',file=sys.stderr);sys.exit(1)
''')
        fake.chmod(0o700)
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                                CONTROLS_RESPONSES=str(self.responses), CONTROLS_REQUEST_LOG=str(self.requests))
        self.script = Path(__file__).resolve().parent / 'verify_github_controls.sh'

    def run_verifier(self, *arguments):
        self.responses.write_text(json.dumps(self.fixture))
        return subprocess.run(['bash', str(self.script), *arguments], cwd=self.root,
                              env=self.environment, capture_output=True, text=True, timeout=20)

    def test_live_entrypoint_uses_only_get_requests_and_sanitized_json(self):
        self.fixture['repos/aatuh/evydence']['body']['description'] = 'PRIVATE_CANARY'
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['passed'])
        self.assertEqual(report['repository'], 'aatuh/evydence')
        self.assertIn('observed_at', report)
        self.assertIn('local_source', report)
        self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)
        for request in [json.loads(line) for line in self.requests.read_text().splitlines()]:
            self.assertEqual(request[request.index('--method') + 1], 'GET')
            self.assertEqual(request[request.index('--hostname') + 1], 'github.com')

    def test_invalid_repository_is_rejected_before_provider_calls(self):
        for name in ['../other/repo', 'aatuh/..', 'aatuh/.', 'aatuh/evydence;PRIVATE_CANARY', 'aatuh/evydence\nPRIVATE_CANARY']:
            with self.subTest(name=name):
                result = self.run_verifier('--repo', name)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.requests.exists())
                self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)

    def test_pagination_reads_all_collaborators_and_requires_team_review(self):
        endpoint = 'repos/aatuh/evydence/collaborators?affiliation=all&per_page=100&page='
        self.fixture[endpoint + '1']['body'] = [
            {'login': 'bot' + str(i), 'type': 'Bot', 'permissions': {'push': True}} for i in range(100)]
        self.fixture[endpoint + '2'] = {'status': 200, 'body': [
            {'login': 'aatuh', 'type': 'User', 'permissions': {'push': True}},
            {'login': 'reviewer', 'type': 'User', 'permissions': {'push': True}}]}
        result = self.run_verifier()
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report['maintainer_model']['mode'], 'team')
        self.assertEqual(report['controls']['pull_requests']['state'], 'failed')

    def test_missing_remote_head_cannot_produce_complete_verification(self):
        self.fixture['repos/aatuh/evydence/commits/master'] = {'status': 403, 'body': {'message': 'PRIVATE_CANARY'}}
        result = self.run_verifier()
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertFalse(report['passed'])
        self.assertIsNone(report['remote_head'])
        self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)

    def test_provider_permission_failure_is_unknown_and_not_leaked(self):
        self.fixture['repos/aatuh/evydence/private-vulnerability-reporting'] = {
            'status': 403, 'body': {'message': 'PRIVATE_CANARY'}}
        result = self.run_verifier()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['controls']['private_reporting']['state'], 'unknown')
        self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)

    def test_codeql_wrong_ref_cannot_verify_default_branch_analysis(self):
        endpoint = 'repos/aatuh/evydence/code-scanning/analyses?tool_name=CodeQL&ref=refs%2Fheads%2Fmaster&per_page=1'
        self.fixture[endpoint]['body'][0]['ref'] = 'refs/heads/other'
        result = self.run_verifier()
        self.assertEqual(result.returncode, 1)
        self.assertNotEqual(json.loads(result.stdout)['controls']['code_scanning']['state'], 'passed')

    def test_untrusted_git_output_does_not_leak_or_claim_local_provenance(self):
        fake_git = self.bin / 'git'
        fake_git.write_text('#!' + sys.executable + '\nprint("PRIVATE_CANARY")\n')
        fake_git.chmod(0o700)
        result = self.run_verifier()
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertIsNone(report['local_source']['commit'])
        self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)

    def test_api_timeout_terminates_owned_provider_process(self):
        self.fixture['repos/aatuh/evydence']['sleep'] = 2
        self.responses.write_text(json.dumps(self.fixture))
        with mock.patch.dict(os.environ, self.environment), mock.patch.object(controls, 'API_TIMEOUT_SECONDS', 0.1), \
                mock.patch.object(controls, 'stop_owned', wraps=controls.stop_owned) as stopped:
            result = controls.GitHubAPI().request('repos/aatuh/evydence')
        self.assertEqual(result['state'], 'unknown')
        stopped.assert_called_once()
        self.assertIsNotNone(stopped.call_args.args[0].poll())

    def test_duplicate_json_keys_and_oversized_provider_body_fail_closed(self):
        for raw in ['{"full_name":"aatuh/evydence","full_name":"PRIVATE_CANARY"}',
                    json.dumps({'padding': 'PRIVATE_CANARY' * 100000})]:
            with self.subTest(kind='duplicate' if len(raw) < 1000 else 'oversized'):
                self.fixture['repos/aatuh/evydence'] = {'status': 200, 'raw': raw}
                result = self.run_verifier()
                self.assertEqual(result.returncode, 1)
                self.assertFalse(json.loads(result.stdout)['passed'])
                self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
