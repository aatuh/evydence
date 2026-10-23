#!/usr/bin/env python3
"""Validate release support and withdrawals without publication or network calls."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import html
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 256 * 1024
TAG = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.(?:0|[1-9][0-9]*))?\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SUPPORT = {
    'development_ref': 'refs/heads/master',
    'release_selector': 'current_public_release',
    'window': {'starts': 'publication', 'ends': 'superseded-or-withdrawn'},
    'older_releases': 'best-effort-unless-commercial-agreement',
    'response_sla': None,
    'fixed_end_date': None,
}
WITHDRAWAL_KEYS = {'tag', 'source_commit', 'recorded_at', 'reason', 'notice_url', 'replacement_tag'}


class PolicyError(ValueError):
    """Safe operator error; never include raw input values or provider content."""


def valid_tag(value):
    return isinstance(value, str) and len(value) <= 96 and TAG.fullmatch(value) is not None


def validate_policy(value):
    if not isinstance(value, dict) or set(value) != {'schema', 'security_support', 'withdrawals'}:
        raise PolicyError('invalid lifecycle policy shape')
    if value['schema'] != 'evydence-release-lifecycle.v1' or value['security_support'] != SUPPORT:
        raise PolicyError('unsupported lifecycle policy or support commitment')
    withdrawals = value['withdrawals']
    if not isinstance(withdrawals, list) or len(withdrawals) > 256:
        raise PolicyError('invalid withdrawal list')
    tags = set()
    for row in withdrawals:
        if not isinstance(row, dict) or set(row) != WITHDRAWAL_KEYS:
            raise PolicyError('invalid withdrawal entry shape')
        if not valid_tag(row['tag']) or row['tag'] in tags:
            raise PolicyError('invalid or duplicate withdrawn tag')
        tags.add(row['tag'])
        if not isinstance(row['source_commit'], str) or not COMMIT.fullmatch(row['source_commit']):
            raise PolicyError('invalid withdrawn source commit')
        timestamp = row['recorded_at']
        if not isinstance(timestamp, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', timestamp):
            raise PolicyError('invalid withdrawal timestamp')
        try:
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            raise PolicyError('invalid withdrawal timestamp') from None
        reason = row['reason']
        if (not isinstance(reason, str) or not reason.strip()
                or any(unicodedata.category(c).startswith('C') for c in reason)
                or len(reason.encode('utf-8')) > 2048):
            raise PolicyError('invalid public withdrawal reason')
        notice = row['notice_url']
        if not isinstance(notice, str) or len(notice) > 512:
            raise PolicyError('invalid withdrawal notice link')
        try:
            url = urlsplit(notice)
            safe = url.scheme == 'https' and url.netloc == 'github.com' and not url.query and not url.fragment
        except ValueError:
            safe = False
        if not safe or not re.fullmatch(r'/aatuh/evydence/(?:releases/tag/v[0-9A-Za-z.\-]+|issues/[1-9][0-9]*|security/advisories/GHSA-[a-z0-9\-]+)', url.path):
            raise PolicyError('invalid withdrawal notice link')
        replacement = row['replacement_tag']
        if replacement is not None and (not valid_tag(replacement) or replacement == row['tag']):
            raise PolicyError('invalid replacement tag')
    if any(row['replacement_tag'] in tags for row in withdrawals):
        raise PolicyError('a replacement release must not also be withdrawn')
    return copy.deepcopy(value)


def current_release(metadata):
    if not isinstance(metadata, dict) or metadata.get('repository') != 'aatuh/evydence':
        raise PolicyError('unexpected release repository')
    current = metadata.get('current_public_release')
    if not isinstance(current, dict) or not valid_tag(current.get('tag')):
        raise PolicyError('invalid current release metadata')
    commit = current.get('source_commit')
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise PolicyError('invalid current source commit')
    return current


def assert_not_withdrawn(policy, tag):
    policy = validate_policy(policy)
    if not valid_tag(tag):
        raise PolicyError('invalid release tag')
    if any(row['tag'] == tag for row in policy['withdrawals']):
        raise PolicyError('release is withdrawn; see the release support reference')


def installable_tag(policy, metadata):
    policy = validate_policy(policy)
    current = current_release(metadata)
    for row in policy['withdrawals']:
        if row['tag'] == current['tag']:
            if row['source_commit'] != current['source_commit']:
                raise PolicyError('current withdrawal conflicts with recorded release source')
            return None
    return current['tag']


def default_tag(policy, metadata):
    selected = installable_tag(policy, metadata)
    if selected is None:
        raise PolicyError('current release is withdrawn; no default install is available')
    return selected


def public_text(value):
    value = html.escape(value, quote=False)
    return ''.join('\\' + c if c in '\\|`[]()' else c for c in value)


def render_reference(policy, metadata):
    policy = validate_policy(policy)
    current = current_release(metadata)
    withdrawn = installable_tag(policy, metadata) is None
    selection = f"No default install is available. `{current['tag']}` is WITHDRAWN." if withdrawn else f"Current default: `{current['tag']}` at `{current['source_commit']}`."
    lines = [
        '<!-- Generated by scripts/release_lifecycle.py render; edit release/lifecycle-policy.json and release/current.json. -->',
        '# Release Support And Withdrawal Reference', '',
        'This reference records the existing security support scope for maintainers and operators.',
        'It does not establish release security, legal compliance, certification or a service guarantee.', '',
        '## Support Window', '', selection, '',
        '- Development security support focuses on `refs/heads/master`.',
        '- The current public release window runs from publication until superseded or withdrawn.',
        '- Older releases are best effort unless a separate commercial support agreement says otherwise.',
        '- No fixed security support end date or response SLA is promised by this policy.', '',
        'The machine-readable policy is [release/lifecycle-policy.json](../../release/lifecycle-policy.json).',
        'The selected public release comes from [release/current.json](../../release/current.json).',
        'Security reporting and scope remain in [SECURITY.md](../../SECURITY.md).', '',
        '## Withdrawn Release History', '',
        'Withdrawal records preserve historical tags and source identities; they do not rewrite or remove artifacts.',
        'All recorded withdrawals take effect immediately for selection and verification, regardless of record order.', '',
    ]
    if not policy['withdrawals']:
        lines += ['No withdrawals are recorded. This is not evidence that every historical release is supported or safe.', '']
    else:
        lines += ['| Release | Status | Recorded UTC | Source | Reason | Public notice | Replacement |',
                  '|---|---|---|---|---|---|---|']
        for row in sorted(policy['withdrawals'], key=lambda x: (x['recorded_at'], x['tag']), reverse=True):
            replacement = '`' + row['replacement_tag'] + '`' if row['replacement_tag'] else 'None selected'
            lines.append(f"| `{row['tag']}` | **WITHDRAWN** | {row['recorded_at']} | `{row['source_commit']}` | {public_text(row['reason'])} | [Notice]({row['notice_url']}) | {replacement} |")
        lines += ['']
    return '\n'.join(lines)


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError('duplicate metadata key')
        result[key] = value
    return result


def read_bytes(root, relative, limit=MAX_JSON_BYTES):
    """Read only a bounded regular file beneath root without following symlinks."""
    if not isinstance(relative, (str, Path)):
        raise PolicyError('release input path must be relative')
    path = Path(relative)
    if path.is_absolute() or not path.parts or '..' in path.parts:
        raise PolicyError('release input path must stay within its root')
    directory = None
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        parts = path.parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise PolicyError('release metadata must be a bounded regular file')
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise PolicyError('release metadata exceeds its byte budget')
        return raw
    except OSError:
        raise PolicyError('cannot read bounded release input') from None
    finally:
        if directory is not None:
            os.close(directory)


def reject_nonfinite(_value):
    raise PolicyError('non-finite metadata number')


def read_json(root, relative):
    try:
        return json.loads(read_bytes(root, relative).decode('utf-8'),
                          object_pairs_hook=reject_duplicates, parse_constant=reject_nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise PolicyError('cannot read valid release metadata') from None


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise PolicyError('invalid lifecycle command arguments')


def main(argv=None):
    parser = Arguments(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check').add_argument('--reference', action='store_true')
    sub.add_parser('default-tag')
    sub.add_parser('check-tag').add_argument('tag')
    sub.add_parser('render')
    try:
        args = parser.parse_args(argv)
        policy = validate_policy(read_json(args.root, 'release/lifecycle-policy.json'))
        metadata = read_json(args.root, 'release/current.json')
        current_release(metadata)
        if args.command == 'render':
            print(render_reference(policy, metadata), end='')
        elif args.command == 'check-tag':
            assert_not_withdrawn(policy, args.tag)
            print('release lifecycle tag check passed; signature and support checks remain separate')
        elif args.command == 'default-tag':
            print(default_tag(policy, metadata))
        else:
            selected = installable_tag(policy, metadata)
            if args.reference and read_bytes(args.root, 'docs/reference/release-support.md', 8 * MAX_JSON_BYTES) != render_reference(policy, metadata).encode('utf-8'):
                raise PolicyError('generated release support reference is stale')
            print('release-lifecycle-check: passed' + ('; no default install is available' if selected is None else ''))
        return 0
    except PolicyError as error:
        print('release-lifecycle-check: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
