#!/usr/bin/env python3
"""Bounded public change fragments and deterministic changelog formatting."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata

from release_lifecycle import public_text

CATEGORIES = ('security', 'added', 'changed', 'fixed', 'deprecated', 'removed')
IDENTIFIER = re.compile(r'EVY-[0-9]{3,6}-[a-z0-9]+(?:-[a-z0-9]+)*\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
FRAGMENT_KEYS = {'schema', 'id', 'category', 'summary', 'details', 'compatibility',
                 'security', 'limitations'}


class ChangeError(ValueError):
    """Safe validation error without raw fragment or Git/provider payloads."""


def text(value, maximum):
    if (not isinstance(value, str) or not value.strip()
            or any(unicodedata.category(c).startswith('C') for c in value)
            or len(value.encode('utf-8')) > maximum):
        raise ChangeError('change text must be bounded public text without control characters')
    return value


def validate_policy(value):
    if not isinstance(value, dict) or set(value) != {
            'schema', 'adoption_commit', 'legacy_release_commit', 'legacy_section_sha256'}:
        raise ChangeError('invalid change policy shape')
    if value['schema'] != 'evydence-change-policy.v1':
        raise ChangeError('unsupported change policy')
    for key in ('adoption_commit', 'legacy_release_commit'):
        if not isinstance(value[key], str) or not COMMIT.fullmatch(value[key]):
            raise ChangeError('invalid change policy source identity')
    if not isinstance(value['legacy_section_sha256'], str) or not DIGEST.fullmatch(value['legacy_section_sha256']):
        raise ChangeError('invalid historical section digest')
    return copy.deepcopy(value)


def validate_fragment(value, expected_id=None):
    if not isinstance(value, dict) or set(value) != FRAGMENT_KEYS:
        raise ChangeError('invalid change fragment shape')
    if value['schema'] != 'evydence-change-fragment.v1':
        raise ChangeError('unsupported change fragment schema')
    identifier = value['id']
    if (not isinstance(identifier, str) or len(identifier) > 96
            or not IDENTIFIER.fullmatch(identifier)
            or expected_id is not None and identifier != expected_id):
        raise ChangeError('invalid fragment identity or filename binding')
    if not isinstance(value['category'], str) or value['category'] not in CATEGORIES:
        raise ChangeError('invalid change category')
    summary = text(value['summary'], 240)
    if summary.casefold().strip(' .!') in ('no changes', 'no unreleased changes', 'none'):
        raise ChangeError('a change fragment cannot claim no changes')
    for name, maximum in [('details', 32), ('limitations', 16)]:
        items = value[name]
        if not isinstance(items, list) or not 1 <= len(items) <= maximum:
            raise ChangeError('change details and limitations must be bounded nonempty lists')
        for item in items:
            text(item, 4096)
    compatibility = value['compatibility']
    if not isinstance(compatibility, dict) or set(compatibility) != {'api', 'sdk', 'migrations', 'notes'}:
        raise ChangeError('invalid compatibility declaration')
    if (compatibility['api'] not in ('unchanged', 'changed')
            or compatibility['sdk'] not in ('unchanged', 'changed')
            or compatibility['migrations'] not in ('none', 'required')):
        raise ChangeError('invalid compatibility impact state')
    text(compatibility['notes'], 4096)
    text(value['security'], 4096)
    return copy.deepcopy(value)


def section(document, title):
    """Read the versioned changelog's level-two section, preserving its body."""
    if not isinstance(document, str) or '\r' in document:
        raise ChangeError('changelog must use canonical UTF-8/LF text')
    pattern = rf'^## {re.escape(title)}[ \t]*\n(?:[ \t]*\n)?([\s\S]*?)(?=^## |\Z)'
    matches = list(re.finditer(pattern, document, re.MULTILINE))
    if len(matches) != 1:
        raise ChangeError('expected exactly one canonical changelog section')
    match = matches[0]
    return match.group(1), match.start(1), match.end(1)


def legacy_heading(policy):
    return 'Historical source snapshot ' + policy['adoption_commit'][:8] + ' (not a release)'


def render_unreleased(fragments, policy, include_legacy=True, exempt_commits=None):
    policy = validate_policy(policy)
    if not isinstance(fragments, list) or len(fragments) > 512:
        raise ChangeError('too many change fragments')
    values = [validate_fragment(value) for value in fragments]
    if len({value['id'] for value in values}) != len(values):
        raise ChangeError('duplicate change fragment identity')
    if sum(len(json.dumps(value, ensure_ascii=False).encode('utf-8')) for value in values) > 1024 * 1024:
        raise ChangeError('change fragment set exceeds its byte budget')
    exempt_commits = [] if exempt_commits is None else exempt_commits
    if (not isinstance(exempt_commits, list) or len(exempt_commits) > 512
            or any(not isinstance(value, str) or not COMMIT.fullmatch(value)
                   for value in exempt_commits)):
        raise ChangeError('invalid verified exemption source identities')
    lines = ['<!-- Generated by scripts/release_history.py; edit changes/fragments/*.json. -->', '']
    if include_legacy:
        anchor = 'historical-source-snapshot-' + policy['adoption_commit'][:8] + '-not-a-release'
        lines += ['### Previous Source Development', '',
                  '- Earlier source changes remain in the [historical source snapshot](#' + anchor + ').',
                  '  That snapshot is development history, not a published release or independent review evidence.', '']
    for category in CATEGORIES:
        selected = sorted((value for value in values if value['category'] == category), key=lambda x: x['id'])
        if not selected:
            continue
        lines += ['### ' + category.capitalize(), '']
        for value in selected:
            lines.append('- ' + public_text(value['summary']) + ' (`' + value['id'] + '`).')
            lines.append('  ' + ' '.join(public_text(item) for item in value['details']))
        lines.append('')
    if exempt_commits:
        lines += ['### Other Source Changes', '',
                  '- Additional source deliveries have a verified `no-changelog` pull-request label.',
                  '  Their source coverage is checked against authenticated GitHub metadata.', '']
    if not values and not include_legacy and not exempt_commits:
        lines += ['- No unreleased changes.', '']
    return '\n'.join(lines).rstrip() + '\n\n'


def update_changelog(document, fragments, policy, include_legacy=True, exempt_commits=None):
    policy = validate_policy(policy)
    body, start, end = section(document, 'Unreleased')
    heading = legacy_heading(policy)
    history_marker = '## ' + heading + '\n'
    if history_marker in document:
        historical, _start, _end = section(document, heading)
        suffix = document[end:]
    else:
        historical = body
        suffix = history_marker + '\n' + historical + document[end:]
    if hashlib.sha256(historical.encode('utf-8')).hexdigest() != policy['legacy_section_sha256']:
        raise ChangeError('manual or historical changelog does not match the adoption source')
    return document[:start] + render_unreleased(fragments, policy, include_legacy, exempt_commits) + suffix
