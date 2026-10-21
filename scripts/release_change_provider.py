#!/usr/bin/env python3
"""Read authenticated GitHub PR labels with exact repository and source binding."""
from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re

from change_fragments import COMMIT
from release_lifecycle import reject_duplicates, reject_nonfinite
from release_scanner import capture

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'repos/aatuh/evydence/'


class ProviderError(ValueError):
    """Safe failure without provider payload, tokens or CLI diagnostics."""


def number(value):
    if type(value) is not int or not 1 <= value <= 2**31 - 1:
        raise ProviderError('invalid pull request number')
    return value


def identity(value):
    if not isinstance(value, str) or not COMMIT.fullmatch(value):
        raise ProviderError('invalid provider source identity')
    return value


def validate_pull(value, expected_number, merged):
    try:
        if (not isinstance(value, dict) or number(value['number']) != expected_number
                or value['state'] != ('closed' if merged else 'open')
                or value['merged'] is not merged
                or value['base']['repo']['full_name'] != 'aatuh/evydence'
                or value['base']['ref'] != 'master'):
            raise ProviderError('unexpected pull request repository or state')
        base = identity(value['base']['sha'])
        head = identity(value['head']['sha'])
        head_repository = value['head']['repo']['full_name']
        if not isinstance(head_repository, str) or not re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9_.-]{1,100}', head_repository):
            raise ProviderError('invalid pull request head repository')
        if merged:
            identity(value['merge_commit_sha'])
            timestamp = value['merged_at']
            if not isinstance(timestamp, str) or not re.fullmatch(
                    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', timestamp):
                raise ProviderError('invalid merged pull request timestamp')
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        elif value['merged_at'] is not None:
            raise ProviderError('open pull request must not have a merge timestamp')
        labels = value['labels']
        if (not isinstance(labels, list) or len(labels) > 100
                or any(not isinstance(item, dict) or not isinstance(item.get('name'), str)
                       or not 1 <= len(item['name']) <= 100 for item in labels)):
            raise ProviderError('invalid pull request labels')
        return {'number': expected_number, 'base_commit': base, 'head_commit': head,
                'no_changelog': any(item['name'] == 'no-changelog' for item in labels)}
    except (KeyError, TypeError, ValueError):
        raise ProviderError('cannot validate exact-source pull request metadata') from None


class GitHub:
    """Use only GET requests through gh's authenticated credential store/token."""
    def __init__(self):
        self.authenticated = False

    def get(self, endpoint):
        if not re.fullmatch(r'(?:pulls/[1-9][0-9]*|commits/[0-9a-f]{40}/pulls\?per_page=100&page=[1-9][0-9]*)', endpoint):
            raise ProviderError('invalid changelog provider endpoint')
        environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'GH_TOKEN', 'GITHUB_TOKEN')
                       if key in os.environ}
        environment.update({'GH_PROMPT_DISABLED': '1', 'GH_PAGER': 'cat', 'LC_ALL': 'C.UTF-8'})
        try:
            if not self.authenticated:
                capture(['gh', 'auth', 'status', '--hostname', 'github.com'], ROOT, environment, 16384, 20)
                self.authenticated = True
            raw = capture(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                           '-H', 'Accept: application/vnd.github+json',
                           '-H', 'X-GitHub-Api-Version: 2026-03-10', PREFIX + endpoint],
                          ROOT, environment, 1024 * 1024, 20)
            return json.loads(raw.decode('utf-8'), object_pairs_hook=reject_duplicates,
                              parse_constant=reject_nonfinite)
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise ProviderError('cannot authenticate or read bounded GitHub changelog metadata') from None

    def open_pull(self, pull_number):
        pull_number = number(pull_number)
        return validate_pull(self.get('pulls/' + str(pull_number)), pull_number, merged=False)

    def merged_exemption(self, commit):
        commit = identity(commit)
        seen = set()
        approved = False
        for page in range(1, 11):
            rows = self.get('commits/' + commit + '/pulls?per_page=100&page=' + str(page))
            if not isinstance(rows, list) or len(rows) > 100:
                raise ProviderError('invalid associated pull request collection')
            for row in rows:
                if not isinstance(row, dict):
                    raise ProviderError('invalid associated pull request')
                pull_number = number(row.get('number'))
                if pull_number in seen or row.get('state') not in ('open', 'closed'):
                    raise ProviderError('invalid associated pull request identity or state')
                seen.add(pull_number)
                if row.get('state') != 'closed' or row.get('merge_commit_sha') != commit:
                    continue
                detail = self.get('pulls/' + str(pull_number))
                context = validate_pull(detail, pull_number, merged=True)
                if detail['merge_commit_sha'] != commit:
                    raise ProviderError('pull request does not bind the source delivery')
                approved = approved or context['no_changelog']
            if len(rows) < 100:
                return approved
        raise ProviderError('associated pull request collection exceeds its page budget')
