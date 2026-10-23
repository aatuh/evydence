#!/usr/bin/env python3
"""Project untrusted GitHub comparison rows into strict offline admission rules.

The caller must authenticate the provider, bind the immutable comparison and
prove coverage. This pure adapter does not fetch data, prove review approval,
or establish that an empty dependency graph is complete.
"""
import re
from urllib.parse import unquote, urlsplit
import dependency_policy as policy

MAX_ROWS = 4096
ECOSYSTEMS = {'gomod': ('gomod', 'golang'), 'npm': ('npm', 'npm'),
              'pip': ('pypi', 'pypi'), 'pypi': ('pypi', 'pypi'),
              'github-actions': ('github-actions', 'githubactions'),
              'actions': ('github-actions', 'githubactions'), 'docker': ('docker', 'docker')}
SHA = re.compile(r'[0-9a-f]{40}\Z')


class ComparisonError(ValueError):
    def __init__(self): super().__init__('invalid dependency comparison identity, coverage data or policy input')


def require(value):
    if not value: raise ComparisonError()


def manifest(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024 and not value.startswith('/')
            and all(part not in {'', '.', '..'} and re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', part) for part in value.split('/')))
    return value


def component(row):
    require(isinstance(row, dict) and row.get('change_type') in {'added', 'removed'}
            and row.get('ecosystem') in ECOSYSTEMS and 'license' in row)
    ecosystem, purl_type = ECOSYSTEMS[row['ecosystem']]
    name, version, purl = row.get('name'), row.get('version'), row.get('package_url')
    require(isinstance(purl, str) and 0 < len(purl) <= 2048 and all(32 < ord(char) < 127 for char in purl))
    parsed = urlsplit(purl)
    require(parsed.scheme == 'pkg' and not parsed.netloc and not parsed.fragment and not parsed.query
            and parsed.path.startswith(purl_type + '/'))
    coordinate = unquote(parsed.path[len(purl_type) + 1:], errors='strict')
    if '@' in coordinate:
        require(coordinate.rsplit('@', 1) == [name, version])
    else:
        # Observed GitHub legacy Go removals omit the URL's version. They are
        # never admitted; keep the separate explicit version and exact name.
        require(ecosystem == 'gomod' and row['change_type'] == 'removed' and coordinate == name)
    if ecosystem == 'gomod':
        require(isinstance(version, str) and re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', version))
        version = 'v' + version.removeprefix('v')
    values = row.get('vulnerabilities'); require(isinstance(values, list) and len(values) <= 128)
    vulnerabilities = []
    for value in values:
        require(isinstance(value, dict))
        severity = value.get('severity')
        # Unknown/missing provider severity blocks; it never becomes low risk.
        severity = severity if severity in {'low', 'moderate', 'high', 'critical'} else 'unknown'
        vulnerabilities.append({'id': value.get('advisory_ghsa_id'), 'severity': severity})
    result = {'ecosystem': ecosystem, 'name': name, 'version': version,
              'license': row['license'], 'vulnerabilities': vulnerabilities}
    policy._component(result)
    return result


def assess(raw, rules, today, *, repository, base, head):
    """Assess additions with trusted caller-supplied policy; validate removals too."""
    try:
        require(repository == 'aatuh/evydence' and isinstance(base, str) and SHA.fullmatch(base)
                and isinstance(head, str) and SHA.fullmatch(head) and base != head)
        rules = policy.validate_policy(rules, today)
        rows = policy.parse_document(raw); require(isinstance(rows, list) and len(rows) <= MAX_ROWS)
        seen, additions = set(), {}
        for row in rows:
            value = component(row); source = manifest(row.get('manifest'))
            identity = tuple(value[key] for key in ('ecosystem', 'name', 'version'))
            observation = identity + (source, row['change_type'])
            require(observation not in seen); seen.add(observation)
            if row['change_type'] == 'removed': continue
            if identity not in additions: additions[identity] = {'component': value, 'manifests': set()}
            previous = additions[identity]
            require(previous['component']['license'] == value['license'])
            merged = {entry['id']: entry['severity'] for entry in previous['component']['vulnerabilities']}
            for entry in value['vulnerabilities']:
                require(entry['id'] not in merged or merged[entry['id']] == entry['severity'])
                merged[entry['id']] = entry['severity']
            previous['component']['vulnerabilities'] = [{'id': identifier, 'severity': merged[identifier]} for identifier in sorted(merged)]
            previous['manifests'].add(source)
        results = []
        for key in sorted(additions):
            row = additions[key]; value = row['component']
            result = policy.assess_component(value, rules, today)
            results.append({**value, 'manifests': sorted(row['manifests']), **result})
        return {'repository': repository, 'base': base, 'head': head, 'components': results,
                'passed': all(row['passed'] for row in results)}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ComparisonError() from None
