#!/usr/bin/env python3
"""Observe an authenticated exact-source PR diff without executing PR code."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import unicodedata

import dependency_actions as actions
import dependency_comparison as comparison
import dependency_inventory as inventory
import dependency_policy as policy
import dependency_reports as reports
from release_change_provider import number, validate_pull

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'aatuh/evydence'
SCHEMA = 'evydence-dependency-review-observation.v1'
MAX_REQUESTS = 48
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCE_REQUESTS = 768
MAX_SOURCE_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_FILES = 2048
MAX_TREE_ENTRIES = 8192
PER_PAGE = 100
SHA = comparison.SHA
MODES = {'040000': 'tree', '100644': 'blob', '100755': 'blob', '120000': 'blob', '160000': 'commit'}
STATUSES = {'added', 'removed', 'modified', 'renamed', 'copied', 'changed'}
ENDPOINT = re.compile(r'(?:pulls/[1-9][0-9]*|'
    r'issues/comments/[1-9][0-9]*|pulls/[1-9][0-9]*/reviews/[1-9][0-9]*|'
    r'pulls/[1-9][0-9]*/files\?per_page=100&page=[1-9][0-9]*|'
    r'compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1&page=1|'
    r'dependency-graph/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}|'
    r'git/commits/[0-9a-f]{40}|git/trees/[0-9a-f]{40}\?recursive=1|git/blobs/[0-9a-f]{40})\Z')


class ProviderError(ValueError):
    def __init__(self): super().__init__('invalid or unavailable authenticated exact-source dependency review observation')


def require(value):
    if not value: raise ProviderError()


def sha(value):
    require(isinstance(value, str) and SHA.fullmatch(value)); return value


def git_path(value):
    """Bounded UTF-8 Git names, kept as data and never passed to a shell."""
    try:
        require(isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 1024
                and not value.startswith('/') and '\\' not in value
                and all(not unicodedata.category(char).startswith('C') for char in value)
                and all(part not in {'', '.', '..'} and len(part.encode('utf-8')) <= 255 for part in value.split('/')))
        return value
    except (OSError, ValueError, TypeError): raise ProviderError() from None


def git_tree(value, expected):
    """Reconstruct Git tree objects, including Git's directory sorting rule."""
    try:
        expected = sha(expected)
        require(isinstance(value, dict) and value.get('sha') == expected and value.get('truncated') is False)
        rows = value.get('tree'); require(isinstance(rows, list) and len(rows) <= MAX_TREE_ENTRIES)
        entries, children = {}, defaultdict(list)
        for row in rows:
            require(isinstance(row, dict))
            path = git_path(row.get('path')); mode, kind = row.get('mode'), row.get('type')
            require(path not in entries and mode in MODES and MODES[mode] == kind and len(path.split('/')) <= 64)
            entries[path] = {'mode': mode, 'type': kind, 'sha': sha(row.get('sha'))}
            parent, _separator, name = path.rpartition('/')
            children[parent].append((name, path))
        for path in entries:
            parent = path.rpartition('/')[0]
            require(not parent or parent in entries and entries[parent]['type'] == 'tree')
        def assemble(folder):
            payload = bytearray()
            ordered = sorted(children[folder], key=lambda item: item[0].encode() + (b'/' if entries[item[1]]['type'] == 'tree' else b''))
            for name, path in ordered:
                row = entries[path]
                if row['type'] == 'tree': require(assemble(path) == row['sha'])
                payload.extend(row['mode'].lstrip('0').encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(row['sha']))
            # SHA-1 is Git's object identity here, not a password/signature scheme.
            return hashlib.sha1(b'tree ' + str(len(payload)).encode() + b'\0' + payload, usedforsecurity=False).hexdigest()
        require(assemble('') == expected)
        return {path: row for path, row in entries.items() if row['type'] != 'tree'}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError): raise ProviderError() from None


def pull_context(value, expected_number):
    try:
        context = validate_pull(value, number(expected_number), merged=False)
        count = value.get('changed_files')
        require(type(count) is int and 0 <= count <= MAX_FILES)
        return {'pull_request': context['number'], 'base': context['base_commit'], 'head': context['head_commit'],
                'head_repository': actions.repository(value['head']['repo']['full_name']), 'changed_files': count}
    except (OSError, ValueError, TypeError, KeyError, AttributeError): raise ProviderError() from None


def event_context(raw, event_name):
    try:
        require(event_name in {'pull_request', 'pull_request_target'})
        data = policy.parse_document(raw)
        require(isinstance(data, dict) and data['repository']['full_name'] == REPOSITORY)
        return pull_context(data['pull_request'], number(data['number']))
    except (OSError, ValueError, TypeError, KeyError, AttributeError): raise ProviderError() from None


class GitHub:
    """Read only fixed repository GET endpoints through gh's authenticated store."""
    def __init__(self, *, source_inputs=False):
        require(type(source_inputs) is bool)
        self.source_inputs = source_inputs
        self.authenticated = False; self.count = 0; self.total = 0; self.receipts = []

    def get(self, endpoint):
        try:
            require(isinstance(endpoint, str) and ENDPOINT.fullmatch(endpoint))
            self.count += 1; require(self.count <= (MAX_SOURCE_REQUESTS if self.source_inputs else MAX_REQUESTS))
            environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'GH_TOKEN', 'GITHUB_TOKEN') if key in os.environ}
            environment.update(GH_PROMPT_DISABLED='1', GH_PAGER='cat', LC_ALL='C.UTF-8')
            if not self.authenticated:
                inventory._run(['gh', 'auth', 'status', '--hostname', 'github.com'], ROOT, environment, timeout=20)
                self.authenticated = True
            raw = inventory._run(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2026-03-10',
                'repos/' + REPOSITORY + '/' + endpoint], ROOT, environment, timeout=45)
            self.total += len(raw); require(self.total <= (MAX_SOURCE_RESPONSE_BYTES if self.source_inputs else MAX_TOTAL_BYTES))
            value = policy.parse_document(raw)
            self.receipts.append({'endpoint': endpoint, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            return value
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError): raise ProviderError() from None

    def snapshot(self, pull_number, *, base, head, head_repository):
        try:
            pull_number = number(pull_number); base, head = sha(base), sha(head)
            require(base != head); head_repository = actions.repository(head_repository)
            first = pull_context(self.get('pulls/' + str(pull_number)), pull_number)
            require(all(first[key] == value for key, value in {'base': base, 'head': head, 'head_repository': head_repository}.items()))
            commits = self.get('compare/' + base + '...' + head + '?per_page=1&page=1')
            require(commits['base_commit']['sha'] == base)
            base_tree = sha(commits['base_commit']['commit']['tree']['sha'])
            merge = sha(commits['merge_base_commit']['sha']); merge_tree = sha(commits['merge_base_commit']['commit']['tree']['sha'])
            source = self.get('git/commits/' + head); require(source['sha'] == head)
            head_tree = sha(source['tree']['sha'])
            old = git_tree(self.get('git/trees/' + merge_tree + '?recursive=1'), merge_tree)
            new = git_tree(self.get('git/trees/' + head_tree + '?recursive=1'), head_tree)
            files, covered, seen = [], set(), set()
            for page in range(1, (MAX_FILES + PER_PAGE - 1) // PER_PAGE + 1):
                rows = self.get('pulls/' + str(pull_number) + '/files?per_page=' + str(PER_PAGE) + '&page=' + str(page))
                require(isinstance(rows, list) and len(rows) <= PER_PAGE)
                for row in rows:
                    require(isinstance(row, dict) and row.get('status') in STATUSES)
                    path = git_path(row.get('filename')); blob = sha(row.get('sha')); status = row['status']
                    require(path not in seen); seen.add(path); covered.add(path)
                    previous = row.get('previous_filename')
                    item = {'filename': path, 'status': status, 'sha': blob}
                    if status in {'renamed', 'copied'}:
                        previous = git_path(previous); require(previous != path and previous in old)
                        item['previous_filename'] = previous
                        if status == 'renamed':
                            require(previous not in new); covered.add(previous)
                    else: require(previous is None)
                    if status == 'removed': require(path in old and path not in new and old[path]['sha'] == blob)
                    else:
                        require(path in new and new[path]['sha'] == blob)
                        item.update(mode=new[path]['mode'], type=new[path]['type'])
                        if status == 'added': require(path not in old)
                        if status in {'modified', 'changed'}: require(path in old)
                    files.append(item)
                require(len(files) <= first['changed_files'])
                if len(files) == first['changed_files']: break
                require(len(rows) == PER_PAGE)
            require(len(files) == first['changed_files'])
            differences = {path for path in set(old) | set(new) if old.get(path) != new.get(path)}
            require(covered == differences)
            raw_rows = self.get('dependency-graph/compare/' + base + '...' + head)
            require(isinstance(raw_rows, list) and len(raw_rows) <= comparison.MAX_ROWS)
            dependency_rows = []
            for row in raw_rows:
                parsed = comparison.component(row); path = comparison.manifest(row.get('manifest'))
                tree = old if row['change_type'] == 'removed' else new
                require(path in tree and tree[path]['type'] == 'blob' and tree[path]['mode'] in {'100644', '100755'})
                dependency_rows.append({key: row[key] for key in ('change_type', 'manifest', 'ecosystem', 'name', 'version', 'package_url', 'license')})
                dependency_rows[-1]['vulnerabilities'] = [{'advisory_ghsa_id': entry['id'], 'severity': entry['severity']} for entry in parsed['vulnerabilities']]
            last = pull_context(self.get('pulls/' + str(pull_number)), pull_number)
            require(first == last and self.authenticated)
            return {'schema': SCHEMA, 'observed_at': datetime.now(timezone.utc).isoformat(),
                    'repository': REPOSITORY, **first, 'comparison_base': merge,
                    'base_tree': base_tree, 'comparison_base_tree': merge_tree, 'head_tree': head_tree,
                    'provider_authenticated': True, 'file_listing_verified': True,
                    'dependency_coverage_verified': False, 'files': sorted(files, key=lambda row: row['filename']),
                    'dependency_rows': dependency_rows, 'receipts': list(self.receipts)}
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError): raise ProviderError() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT, help='Root for the relative output file.')
    parser.add_argument('--pull-request', type=int)
    parser.add_argument('--base'); parser.add_argument('--head'); parser.add_argument('--head-repository')
    parser.add_argument('--event', type=Path); parser.add_argument('--event-name', choices=['pull_request', 'pull_request_target'])
    parser.add_argument('--output', required=True); parser.add_argument('--replace', action='store_true')
    args = parser.parse_args(argv); handlers = {}
    try:
        def interrupted(_signum, _frame): raise ProviderError()
        for signum in (signal.SIGINT, signal.SIGTERM): handlers[signum] = signal.signal(signum, interrupted)
        if args.event is not None:
            require(args.event_name is not None and all(value is None for value in [args.pull_request, args.base, args.head, args.head_repository]))
            with inventory.regular_stream(args.event.parent, args.event.name) as stream:
                context = event_context(stream.read(inventory.MAX_BYTES + 1), args.event_name)
        else:
            require(args.event_name is None and all(value is not None for value in [args.pull_request, args.base, args.head, args.head_repository]))
            context = {'pull_request': args.pull_request, 'base': args.base, 'head': args.head, 'head_repository': args.head_repository}
        directory, old = reports.directory(args.root, args.output, SCHEMA, args.replace); os.close(directory)
        snapshot = GitHub().snapshot(context['pull_request'], base=context['base'], head=context['head'], head_repository=context['head_repository'])
        reports.write(args.root, args.output, snapshot, SCHEMA, replace=args.replace, expected=old)
        print('dependency-review-provider: authenticated exact-source observation; complete dependency coverage remains unverified')
        return 0
    except (OSError, ValueError, TypeError):
        print('dependency-review-provider: operation failed; inspect source identities and bounded provider availability', file=sys.stderr); return 2
    finally:
        for signum, handler in handlers.items(): signal.signal(signum, handler)


if __name__ == '__main__': sys.exit(main())
