#!/usr/bin/env python3
"""Bounded, offline dependency admission rules; no provider or filesystem effects.

Call assess_component for admission. license_allowed evaluates only an SPDX
expression; it does not validate exception approval or admit a dependency.
The caller must supply trusted policy and authenticated/verified component data.
Review-link syntax is not proof that a person approved an exception.
"""
from __future__ import annotations

import copy
from datetime import date, datetime, timezone
import json
import math
import re
import unicodedata
from urllib.parse import urlsplit

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
ECOSYSTEMS = {'gomod', 'npm', 'pypi', 'github-actions', 'docker', 'fixture', 'generic'}
UNKNOWN_LICENSES = {'', 'NOASSERTION', 'NONE', 'UNKNOWN', 'UNLICENSED'}
OPERATORS = {'AND', 'OR', 'WITH'}
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,126}\+?\Z')
ADVISORY = re.compile(r'(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|'
                      r'(?:GO|CVE)-[0-9]{4}-[0-9]{4,10})\Z')
EXCEPTION_KEYS = {'id', 'ecosystem', 'name', 'version', 'kind', 'value',
                  'owner', 'reason', 'reviewed_on', 'expires_on', 'review_url'}


class PolicyError(ValueError):
    """Public operator error; never include raw manifests or provider responses."""


def parse_document(raw):
    """Parse bounded JSON without duplicate keys or non-JSON numbers."""
    if not isinstance(raw, bytes) or len(raw) > MAX_DOCUMENT_BYTES:
        raise PolicyError('dependency document exceeds its byte budget')

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise PolicyError('duplicate dependency document key')
            result[key] = value
        return result

    def constant(_value):
        raise PolicyError('non-JSON dependency document number')

    def finite_number(value):
        if len(value) > 128:
            raise PolicyError('dependency document number exceeds its budget')
        result = float(value)
        if not math.isfinite(result):
            raise PolicyError('nonfinite dependency document number')
        return result

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite_number)
    except (UnicodeError, ValueError, RecursionError):
        raise PolicyError('invalid dependency JSON document') from None


def _text(value, maximum):
    if (not isinstance(value, str) or not value.strip()
            or len(value) > maximum
            or any(unicodedata.category(c).startswith('C') for c in value)
            or len(value.encode('utf-8')) > maximum):
        raise PolicyError('dependency text must be bounded public text')
    return value


def _license_id(value):
    return (isinstance(value, str) and ID.fullmatch(value) is not None
            and value.upper() not in OPERATORS | UNKNOWN_LICENSES
            and not value.casefold().startswith(('licenseref-', 'documentref-')))


def _exception_id(value):
    return _license_id(value) and '+' not in value


def _license_rules(rules):
    if not isinstance(rules, dict):
        raise PolicyError('invalid dependency license policy')
    licenses = rules.get('allowed_licenses')
    pairs = rules.get('allowed_with')
    if (not isinstance(licenses, list) or not 1 <= len(licenses) <= 128
            or any(not _license_id(value) for value in licenses)
            or len(licenses) != len({value.casefold() for value in licenses})
            or not isinstance(pairs, list) or len(pairs) > 64):
        raise PolicyError('invalid allowed dependency licenses')
    seen = set()
    for value in pairs:
        if not isinstance(value, str) or len(value) > 270:
            raise PolicyError('invalid allowed license-exception pair')
        parts = value.split(' ')
        if (len(parts) != 3 or parts[1] != 'WITH'
                or not _license_id(parts[0]) or not _exception_id(parts[2])):
            raise PolicyError('invalid allowed license-exception pair')
        normalized = parts[0].casefold() + ' WITH ' + parts[2].casefold()
        if normalized in seen:
            raise PolicyError('duplicate allowed license-exception pair')
        seen.add(normalized)
    return {value.casefold() for value in licenses}, seen


class _Expression:
    def __init__(self, expression, allowed, pairs):
        if (not isinstance(expression, str) or len(expression) > 2048
                or not expression.isascii()
                or any(ord(c) < 32 or ord(c) == 127 for c in expression)):
            raise PolicyError('invalid or oversized SPDX expression')
        self.tokens = []
        position = 0
        while position < len(expression):
            if expression[position] == ' ':
                position += 1
                continue
            match = re.match(r'[A-Za-z0-9][A-Za-z0-9.+-]*|[()]', expression[position:])
            if match is None or len(self.tokens) >= 128:
                raise PolicyError('invalid or oversized SPDX expression')
            self.tokens.append(match.group())
            position += len(match.group())
        self.position = 0
        self.allowed, self.pairs = allowed, pairs

    def _peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _primary(self, depth):
        if depth > 16:
            raise PolicyError('SPDX expression nesting exceeds its budget')
        token = self._peek()
        self.position += 1
        if token == '(':
            result = self._or(depth + 1)
            if self._peek() != ')':
                raise PolicyError('invalid SPDX expression grouping')
            self.position += 1
            return result
        if token is None or not ID.fullmatch(token) or token in OPERATORS:
            raise PolicyError('invalid SPDX license operand')
        if self._peek() == 'WITH':
            self.position += 1
            exception = self._peek()
            if exception is None or not _exception_id(exception):
                raise PolicyError('invalid SPDX license exception')
            self.position += 1
            return token.casefold() + ' WITH ' + exception.casefold() in self.pairs
        return token.casefold() in self.allowed

    def _and(self, depth):
        result = self._primary(depth)
        while self._peek() == 'AND':
            self.position += 1
            other = self._primary(depth)
            result = result and other
        return result

    def _or(self, depth):
        result = self._and(depth)
        while self._peek() == 'OR':
            self.position += 1
            other = self._and(depth)
            result = result or other
        return result

    def evaluate(self):
        result = self._or(0)
        if self.position != len(self.tokens):
            raise PolicyError('trailing SPDX expression input')
        return result


def license_allowed(expression, rules):
    allowed, pairs = _license_rules(rules)
    if expression is None:
        return False
    parsed = _Expression(expression, allowed, pairs)
    if expression.strip().upper() in UNKNOWN_LICENSES:
        return False
    return parsed.evaluate()


def _coordinates(value):
    ecosystem, name, version = (value.get(key) for key in ('ecosystem', 'name', 'version'))
    if (not isinstance(ecosystem, str) or ecosystem not in ECOSYSTEMS
            or not isinstance(name, str)
            or not re.fullmatch(r'[A-Za-z0-9@][A-Za-z0-9._/@!+-]{0,255}', name)
            or any(part in {'', '.', '..'} for part in name.split('/'))
            or not isinstance(version, str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+!:-]{0,127}', version)):
        raise PolicyError('invalid exact dependency coordinates')
    return ecosystem, name, version


def _day(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value):
        raise PolicyError('invalid dependency exception date')
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise PolicyError('invalid dependency exception date') from None


def _review_url(value):
    if not isinstance(value, str) or len(value) > 512:
        raise PolicyError('invalid dependency review reference')
    try:
        url = urlsplit(value)
        good = (url.scheme == 'https' and url.netloc == 'github.com' and not url.query
                and re.fullmatch(r'/aatuh/evydence/(?:pull/[1-9][0-9]*|commit/[a-f0-9]{40})', url.path)
                and (not url.fragment or re.fullmatch(
                    r'(?:issuecomment-|pullrequestreview-|discussion_r)[1-9][0-9]*', url.fragment)))
    except ValueError:
        good = False
    if not good or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PolicyError('invalid dependency review reference')


def validate_policy(value, today=None):
    if (not isinstance(value, dict) or set(value) != {
            'schema', 'allowed_licenses', 'allowed_with', 'exceptions'}
            or value['schema'] != 'evydence-dependency-policy.v1'):
        raise PolicyError('invalid dependency policy shape or schema')
    _license_rules(value)
    today = datetime.now(timezone.utc).date() if today is None else today
    if type(today) is not date:
        raise PolicyError('invalid dependency assessment date')
    rows = value['exceptions']
    if not isinstance(rows, list) or len(rows) > 128:
        raise PolicyError('invalid dependency exception list')
    ids, scopes = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != EXCEPTION_KEYS:
            raise PolicyError('invalid dependency exception shape')
        coordinates = _coordinates(row)
        identifier, kind = row['id'], row['kind']
        if (not isinstance(identifier, str) or not re.fullmatch(r'DEP-[0-9]{4,8}', identifier)
                or identifier in ids or kind not in ('license', 'vulnerability')):
            raise PolicyError('invalid dependency exception identity or kind')
        owner = row['owner']
        if not isinstance(owner, str) or not re.fullmatch(
                r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', owner):
            raise PolicyError('invalid dependency exception owner')
        _text(row['reason'], 2048)
        _review_url(row['review_url'])
        reviewed, expires = _day(row['reviewed_on']), _day(row['expires_on'])
        if not reviewed <= today < expires or not 1 <= (expires - reviewed).days <= 90:
            raise PolicyError('dependency exception is expired, future reviewed or exceeds 90 days')
        target = row['value']
        if kind == 'license':
            _text(target, 2048)
            if target != 'NOASSERTION':
                _Expression(target, set(), set()).evaluate()
        elif not isinstance(target, str) or not ADVISORY.fullmatch(target):
            raise PolicyError('invalid dependency exception advisory')
        scope = coordinates + (kind, target)
        if scope in scopes:
            raise PolicyError('duplicate dependency exception scope')
        ids.add(identifier)
        scopes.add(scope)
    return copy.deepcopy(value)


def _component(value):
    if not isinstance(value, dict) or set(value) != {
            'ecosystem', 'name', 'version', 'license', 'vulnerabilities'}:
        raise PolicyError('invalid dependency component shape')
    _coordinates(value)
    expression = value['license']
    if expression is not None:
        _Expression(expression, set(), set())
        if expression.strip().upper() not in UNKNOWN_LICENSES:
            _Expression(expression, set(), set()).evaluate()
    vulnerabilities = value['vulnerabilities']
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 128:
        raise PolicyError('invalid dependency vulnerability list')
    seen = set()
    for row in vulnerabilities:
        if (not isinstance(row, dict) or set(row) != {'id', 'severity'}
                or not isinstance(row['id'], str) or not ADVISORY.fullmatch(row['id'])
                or row['id'] in seen
                or row['severity'] not in ('low', 'moderate', 'high', 'critical', 'unknown')):
            raise PolicyError('invalid dependency vulnerability record')
        seen.add(row['id'])


def assess_component(component, rules, today=None):
    """Evaluate exact coordinates against trusted policy; return no raw input data."""
    rules = validate_policy(rules, today)
    _component(component)
    coordinates = _coordinates(component)
    matched, violations = [], []

    def excepted(kind, target):
        matches = [row['id'] for row in rules['exceptions']
                   if _coordinates(row) == coordinates and row['kind'] == kind and row['value'] == target]
        matched.extend(matches)
        return bool(matches)

    expression = component['license']
    if not license_allowed(expression, rules):
        unknown = expression is None or expression.strip().upper() in UNKNOWN_LICENSES
        target = 'NOASSERTION' if unknown else expression
        if not excepted('license', target):
            violations.append('unknown_license' if unknown else 'disallowed_license')
    for row in component['vulnerabilities']:
        if row['severity'] in ('high', 'critical', 'unknown') and not excepted('vulnerability', row['id']):
            violations.append('blocked_vulnerability')
    return {'passed': not violations, 'violations': violations, 'exceptions': sorted(matched)}
