#!/usr/bin/env python3
"""Inspect GitHub repository controls and emit an allowlisted assessment."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from urllib.parse import quote


REQUIRED_CHECKS = ('Production Check', 'CodeQL Analyze', 'Race and Stress')
ACTIONS_APP_ID = 15368
MAX_RESPONSE_BYTES = 1024 * 1024
API_TIMEOUT_SECONDS = 15


def valid_repository(value):
    return (isinstance(value, str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9_.-]{1,100}', value) is not None
            and value.split('/')[1] not in {'.', '..'})


def boolean(value):
    return value if type(value) is bool else None


def object_value(value):
    return value if isinstance(value, dict) else {}


def checks_match(items, app_field):
    if not isinstance(items, list):
        return False
    contexts = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('context'), str):
            return False
        if item['context'] in contexts:
            return False
        contexts[item['context']] = item.get(app_field)
    return all(contexts.get(name) == ACTIONS_APP_ID for name in REQUIRED_CHECKS)


def checked_release_ruleset(ruleset):
    if not isinstance(ruleset, dict) or ruleset.get('target') != 'tag' or ruleset.get('enforcement') != 'active':
        return False
    if ruleset.get('bypass_actors') != []:
        return False
    refs = object_value(object_value(ruleset.get('conditions')).get('ref_name'))
    includes = refs.get('include')
    if not isinstance(includes, list) or not any(value in includes for value in ['refs/tags/v*', '~ALL']):
        return False
    if refs.get('exclude') != []:
        return False
    rules = ruleset.get('rules')
    if not isinstance(rules, list) or not all(isinstance(item, dict) for item in rules):
        return False
    types = [item.get('type') for item in rules]
    if (not all(isinstance(value, str) for value in types) or len(types) != len(set(types))
            or not {'update', 'deletion', 'required_status_checks'}.issubset(types)):
        return False
    parameters = object_value(next(item for item in rules if item['type'] == 'required_status_checks').get('parameters'))
    return (parameters.get('do_not_enforce_on_create') is False
            and checks_match(parameters.get('required_status_checks'), 'integration_id'))


def assess_controls(snapshot, repository):
    """Assess only known provider fields; never echo raw payloads or errors."""
    if not valid_repository(repository):
        raise ValueError('invalid repository')
    repo = object_value(snapshot.get('repository'))
    branch = object_value(snapshot.get('branch'))
    collaborators = snapshot.get('collaborators')
    writers = []
    collaborator_visibility = isinstance(collaborators, list)
    if collaborator_visibility:
        for item in collaborators:
            item = object_value(item)
            permissions = object_value(item.get('permissions'))
            if not isinstance(item.get('type'), str) or item['type'] not in {'User', 'Bot'} or type(permissions.get('push')) is not bool:
                collaborator_visibility = False
            if item.get('type') == 'User' and permissions.get('push') is True:
                writers.append(item.get('login'))
    collaborator_visibility = collaborator_visibility and all(isinstance(name, str) for name in writers)
    collaborator_visibility = collaborator_visibility and len(writers) == len(set(writers)) and bool(writers)
    mode = 'solo' if collaborator_visibility and len(writers) == 1 else 'team' if collaborator_visibility else 'unknown'
    required_approvals = 0 if mode == 'solo' else 1
    controls = {}
    def add(name, condition, known=True):
        controls[name] = {'state': 'unknown' if not known else 'passed' if condition else 'failed'}
    identity_known = isinstance(repo.get('full_name'), str) and isinstance(repo.get('default_branch'), str)
    add('repository_identity', identity_known and repo['full_name'].casefold() == repository.casefold()
        and repo.get('default_branch') == 'master' and repo.get('archived') is False, identity_known)
    permissions = object_value(repo.get('permissions'))
    add('administration_visibility', permissions.get('admin') is True, type(permissions.get('admin')) is bool)
    remote_head = snapshot.get('remote_head')
    add('remote_source_identity', isinstance(remote_head, str) and re.fullmatch(r'[a-f0-9]{40,64}', remote_head) is not None,
        isinstance(remote_head, str))
    add('maintainer_model', collaborator_visibility, collaborator_visibility)
    required = object_value(branch.get('required_status_checks'))
    add('required_checks', required.get('strict') is True and checks_match(required.get('checks'), 'app_id'), bool(branch))
    for control, field, expected in [('administrator_enforcement', 'enforce_admins', True),
                                     ('force_pushes_blocked', 'allow_force_pushes', False),
                                     ('branch_deletion_blocked', 'allow_deletions', False),
                                     ('conversation_resolution', 'required_conversation_resolution', True)]:
        value = object_value(branch.get(field)).get('enabled')
        add(control, value is expected, type(value) is bool)
    reviews = branch.get('required_pull_request_reviews')
    review_object = object_value(reviews)
    count = review_object.get('required_approving_review_count')
    bypass = object_value(review_object.get('bypass_pull_request_allowances'))
    personal_without_allowances = (object_value(repo.get('owner')).get('type') == 'User'
                                  and 'bypass_pull_request_allowances' not in review_object)
    no_review_bypass = personal_without_allowances or all(bypass.get(key) == [] for key in ['users', 'teams', 'apps'])
    approval_gate = (isinstance(reviews, dict) and type(count) is int and count >= required_approvals
                     and review_object.get('dismiss_stale_reviews') is True
                     and no_review_bypass)
    if mode == 'team':
        approval_gate = approval_gate and review_object.get('require_last_push_approval') is True
    add('pull_requests', approval_gate, bool(branch) and collaborator_visibility)
    rulesets = snapshot.get('rulesets')
    add('release_tags', isinstance(rulesets, list) and any(checked_release_ruleset(item) for item in rulesets),
        isinstance(rulesets, list))
    security = object_value(repo.get('security_and_analysis'))
    for name in ['secret_scanning', 'secret_scanning_push_protection', 'dependabot_security_updates']:
        value = object_value(security.get(name)).get('status')
        add(name, value == 'enabled', isinstance(value, str) and value in {'enabled', 'disabled'})
    for name in ['dependabot_alerts', 'private_reporting', 'code_scanning']:
        observation = object_value(snapshot.get(name))
        state = observation.get('state')
        known = isinstance(state, str) and state in {'enabled', 'disabled'}
        good = observation.get('state') == 'enabled'
        if name == 'code_scanning':
            good = (good and observation.get('tool') == 'CodeQL' and observation.get('analysis_error') is False
                    and observation.get('commit') == remote_head)
        add(name, good, known)
    signatures = object_value(branch.get('required_signatures')).get('enabled')
    observed_checks = []
    actual_checks = required.get('checks') if isinstance(required.get('checks'), list) else []
    for name in REQUIRED_CHECKS:
        matches = [item for item in actual_checks if isinstance(item, dict) and item.get('context') == name]
        actual_app = matches[0].get('app_id') if len(matches) == 1 else None
        observed_checks.append({'context': name, 'present': bool(matches),
                                'app_id': actual_app if type(actual_app) is int else None})
    checked_tags = [item['id'] for item in rulesets if checked_release_ruleset(item)
                    and type(item.get('id')) is int] if isinstance(rulesets, list) else []
    observed = {'master': {'pull_requests_required': isinstance(reviews, dict) if branch else None,
                           'required_approvals': count if type(count) is int and 0 <= count <= 6 else None,
                           'dismiss_stale_reviews': boolean(review_object.get('dismiss_stale_reviews')),
                           'codeowner_approval': boolean(review_object.get('require_code_owner_reviews')),
                           'last_push_approval': boolean(review_object.get('require_last_push_approval')),
                           'administrator_enforcement': boolean(object_value(branch.get('enforce_admins')).get('enabled')),
                           'conversation_resolution': boolean(object_value(branch.get('required_conversation_resolution')).get('enabled')),
                           'strict_checks': boolean(required.get('strict')),
                           'required_checks': observed_checks},
                'release_tags': {'checked_ruleset_ids': checked_tags,
                                 'rulesets_inspected': len(rulesets) if isinstance(rulesets, list) else None},
                'security': {name: controls[name]['state'] for name in ['secret_scanning',
                    'secret_scanning_push_protection', 'dependabot_security_updates',
                    'dependabot_alerts', 'private_reporting', 'code_scanning']}}
    return {'passed': all(item['state'] == 'passed' for item in controls.values()),
            'repository': repository, 'branch': 'master',
            'maintainer_model': {'mode': mode, 'human_writers': len(writers) if collaborator_visibility else None,
                                 'required_approvals': required_approvals if collaborator_visibility else None},
            'controls': controls,
            'observed_optional_controls': {'signed_commits_required': signatures if type(signatures) is bool else None,
                                           'codeowner_approval_required': review_object.get('require_code_owner_reviews') is True},
            'expected_required_checks': [{'context': name, 'app_id': ACTIONS_APP_ID} for name in REQUIRED_CHECKS],
            'observed_settings': observed}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate provider field')
        result[key] = value
    return result


def stop_owned(child):
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


class GitHubAPI:
    """Bounded, synchronous GET transport through the operator's gh credentials."""
    def request(self, endpoint):
        environment = dict(os.environ)
        environment.pop('GH_DEBUG', None)
        command = ['gh', 'api', '--include', '--method', 'GET', '--hostname', 'github.com',
                   '-H', 'Accept: application/vnd.github+json',
                   '-H', 'X-GitHub-Api-Version: 2026-03-10', endpoint]
        result = {'http_status': None, 'data': None, 'state': 'unknown'}
        try:
            child = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            return result
        data = bytearray()
        deadline = time.monotonic() + API_TIMEOUT_SECONDS
        try:
            with selectors.DefaultSelector() as selected:
                selected.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    if not selected.select(remaining):
                        raise TimeoutError
                    chunk = os.read(child.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    if len(data) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError('provider response exceeds limit')
                    data.extend(chunk)
            code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            stop_owned(child)
            return result
        finally:
            child.stdout.close()
        raw = bytes(data)
        headers, separator, body = raw.partition(b'\r\n\r\n')
        if not separator:
            headers, separator, body = raw.partition(b'\n\n')
        if not separator or len(headers) > 32768:
            return result
        first = headers.splitlines()[0] if headers else b''
        status = re.fullmatch(rb'HTTP/[0-9.]+ ([1-5][0-9][0-9])(?: [^\r\n]*)?', first)
        if not status:
            return result
        result['http_status'] = int(status[1])
        if body.strip():
            try:
                result['data'] = json.loads(body, object_pairs_hook=unique_object)
            except (ValueError, UnicodeDecodeError, RecursionError):
                return result
        if code == 0 and result['http_status'] in {200, 204}:
            result['state'] = 'received'
        return result

    def collection(self, endpoint):
        collected = []
        separator = '&' if '?' in endpoint else '?'
        for page in range(1, 11):
            response = self.request(endpoint + separator + 'per_page=100&page=' + str(page))
            values = response['data']
            if response['state'] != 'received' or not isinstance(values, list) or len(values) > 100:
                return None
            collected.extend(values)
            if len(values) < 100:
                return collected
        return None


def collect_snapshot(api, repository):
    prefix = 'repos/' + repository
    snapshot = {'observations': {}}
    def get(name, endpoint):
        result = api.request(endpoint)
        snapshot['observations'][name] = {'http_status': result['http_status'], 'state': result['state']}
        return result
    repo = get('repository', prefix)
    snapshot['repository'] = repo['data'] if repo['state'] == 'received' else None
    if not isinstance(snapshot['repository'], dict):
        return snapshot
    branch = get('branch', prefix + '/branches/master/protection')
    snapshot['branch'] = branch['data'] if branch['state'] == 'received' else None
    head = get('remote_head', prefix + '/commits/master')
    sha = object_value(head['data']).get('sha')
    snapshot['remote_head'] = sha if head['state'] == 'received' and isinstance(sha, str) and re.fullmatch(r'[a-f0-9]{40,64}', sha) else None
    snapshot['collaborators'] = api.collection(prefix + '/collaborators?affiliation=all')
    summaries = api.collection(prefix + '/rulesets?includes_parents=true')
    snapshot['rulesets'] = [] if summaries == [] else None
    if isinstance(summaries, list) and summaries:
        identifiers = [object_value(row).get('id') for row in summaries]
        if all(type(identifier) is int and identifier > 0 for identifier in identifiers) and len(set(identifiers)) == len(identifiers):
            details = []
            for identifier in identifiers:
                result = get('ruleset_' + str(identifier), prefix + '/rulesets/' + str(identifier) + '?includes_parents=true')
                if (result['state'] != 'received' or not isinstance(result['data'], dict)
                        or type(result['data'].get('id')) is not int or result['data']['id'] != identifier):
                    break
                details.append(result['data'])
            else:
                snapshot['rulesets'] = details
    alerts = get('dependabot_alerts', prefix + '/vulnerability-alerts')
    snapshot['dependabot_alerts'] = {'http_status': alerts['http_status'], 'state':
        'enabled' if alerts['state'] == 'received' and alerts['http_status'] == 204
        else 'disabled' if alerts['http_status'] == 404 else 'unknown'}
    reporting = get('private_reporting', prefix + '/private-vulnerability-reporting')
    enabled = object_value(reporting['data']).get('enabled')
    snapshot['private_reporting'] = {'http_status': reporting['http_status'], 'state':
        ('enabled' if enabled else 'disabled') if reporting['state'] == 'received' and type(enabled) is bool else 'unknown'}
    analyses = get('code_scanning', prefix + '/code-scanning/analyses?tool_name=CodeQL&ref=' + quote('refs/heads/master', safe='') + '&per_page=1')
    scanning = {'state': 'unknown', 'http_status': analyses['http_status']}
    if analyses['state'] == 'received' and isinstance(analyses['data'], list):
        scanning['state'] = 'disabled'
        if len(analyses['data']) == 1:
            analysis = object_value(analyses['data'][0])
            tool = object_value(analysis.get('tool')).get('name')
            commit = analysis.get('commit_sha')
            if (tool == 'CodeQL' and analysis.get('ref') == 'refs/heads/master'
                    and isinstance(commit, str) and re.fullmatch(r'[a-f0-9]{40,64}', commit)
                    and isinstance(analysis.get('error'), str)):
                scanning.update(state='enabled', tool='CodeQL', commit=commit, analysis_error=bool(analysis['error']))
    snapshot['code_scanning'] = scanning
    return snapshot


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, 'invalid command arguments\n')


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='aatuh/evydence', help='GitHub owner/repository; master is inspected.')
    args = parser.parse_args()
    if not valid_repository(args.repo):
        parser.error('invalid repository')
    snapshot = collect_snapshot(GitHubAPI(), args.repo)
    report = assess_controls(snapshot, args.repo)
    root = Path(__file__).resolve().parents[1]
    def git(*arguments):
        try:
            result = subprocess.run(['git', '-C', str(root), *arguments], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout.strip() if result.returncode == 0 else None
    commit = git('rev-parse', '--verify', 'HEAD')
    if not isinstance(commit, str) or re.fullmatch(r'[a-f0-9]{40,64}', commit) is None:
        commit = None
    status = git('status', '--porcelain', '--untracked-files=all')
    known_source = commit is not None and re.fullmatch(r'[a-f0-9]{40,64}', commit) is not None and status is not None
    report['controls']['local_provenance'] = {'state': 'passed' if known_source else 'unknown'}
    report['passed'] = report['passed'] and known_source
    report.update(schema_version='evydence.repository-controls.v1',
                  observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  remote_head=snapshot.get('remote_head'),
                  local_source={'commit': commit,
                                'dirty': bool(status) if status is not None else None,
                                'verifier_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                  observations=snapshot['observations'])
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
