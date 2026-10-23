#!/usr/bin/env python3
"""Bounded public maintenance metadata; no package execution or provider mutations."""
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from urllib.parse import quote, unquote, urlsplit

import dependency_actions as actions
import dependency_inventory as inventory
import dependency_policy as policy

MAX_BYTES = 4 * 1024 * 1024
MAX_REPOSITORIES = 2048
BATCH_SIZE = 40
SHA = re.compile(r'[0-9a-f]{40}\Z')
TAG = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}\Z')


class SourceError(ValueError):
    def __init__(self):
        super().__init__('invalid or unavailable bounded maintenance provider metadata')


def require(value):
    if not value: raise SourceError()


def timestamp(value):
    if value is None: return None
    try:
        require(isinstance(value, str) and 0 < len(value) <= 64)
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None)
        return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except (ValueError, TypeError, OverflowError):
        raise SourceError() from None


def github_repository(value):
    if not isinstance(value, str) or len(value) > 1024: return None
    match = re.fullmatch(r'(?:https://|git\+https://|git://)github\.com/([^?#]+?)(?:\.git)?/?', value)
    if not match: match = re.fullmatch(r'git@github\.com:([^?#]+?)(?:\.git)?', value)
    if not match: return None
    try: return actions.repository(match[1])
    except ValueError: return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args): raise SourceError()


def read_json(url):
    try:
        parsed = urlsplit(url)
        require(parsed.scheme == 'https' and parsed.netloc in {'registry.npmjs.org', 'proxy.golang.org', 'pypi.org'}
                and not parsed.query and not parsed.fragment and 0 < len(url) <= 2048
                and all(32 < ord(char) < 127 for char in url))
        decoded = unquote(parsed.path, errors='strict')
        require(all(part not in {'.', '..'} for part in decoded.split('/')) and '\\' not in decoded
                and all(32 < ord(char) < 127 for char in decoded))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(url, headers={'Accept': 'application/json', 'Accept-Encoding': 'identity',
                                                     'User-Agent': 'evydence-maintenance-inventory/1'}, method='GET')
        deadline = time.monotonic() + 120
        with opener.open(request, timeout=20) as response:
            require(response.status == 200 and response.geturl() == url
                    and response.headers.get('Content-Encoding', 'identity') == 'identity')
            declared = response.headers.get('Content-Length')
            require(declared is None or re.fullmatch(r'[0-9]{1,12}', declared))
            if declared is not None and int(declared) > MAX_BYTES: return {'unavailable': 'over-budget'}
            raw = bytearray()
            while True:
                require(time.monotonic() <= deadline)
                chunk = response.read(min(65536, MAX_BYTES - len(raw) + 1))
                if not chunk: break
                raw.extend(chunk)
                if len(raw) > MAX_BYTES: return {'unavailable': 'over-budget'}
            require(declared is None or len(raw) == int(declared))
            result = policy.parse_document(bytes(raw)); require(isinstance(result, dict) and 'unavailable' not in result)
            return result
    except urllib.error.HTTPError as error:
        code = error.code; error.close()
        if code in {404, 410}: return {'unavailable': 'not-found'}
        raise SourceError() from None
    except (OSError, ValueError, TypeError, urllib.error.URLError):
        raise SourceError() from None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def observation(data):
    unavailable = data.get('unavailable')
    require(unavailable in {None, 'not-found', 'over-budget'})
    return {'metadata_status': unavailable or 'observed', 'metadata_sha256': digest(data),
            'repository': None, 'version_timestamp': None, 'deprecated': None}


def go_metadata(name, version):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/~!-]{0,1023}', name)
            and '.' in name.split('/')[0] and all(part not in {'', '.', '..'} for part in name.split('/'))
            and isinstance(version, str) and re.fullmatch(r'v[0-9][A-Za-z0-9.+-]{0,126}', version))
    escaped = lambda value: ''.join('!' + char.lower() if char.isupper() else char for char in value)
    url = 'https://proxy.golang.org/' + quote(escaped(name), safe='/!') + '/@v/' + quote(escaped(version), safe='!') + '.info'
    data = read_json(url); result = observation(data)
    if result['metadata_status'] != 'observed': return result
    require(data.get('Version') == version)
    result['version_timestamp'] = timestamp(data.get('Time'))
    origin = data.get('Origin')
    if isinstance(origin, dict) and origin.get('VCS') == 'git': result['repository'] = github_repository(origin.get('URL'))
    return result


def npm_package(name, versions):
    require(isinstance(name, str) and re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]{0,213}', name)
            and isinstance(versions, list) and 0 < len(versions) <= 128
            and len(versions) == len(set(versions))
            and all(isinstance(value, str) and re.fullmatch(r'[0-9][A-Za-z0-9.+-]{0,126}', value) for value in versions))
    data = read_json('https://registry.npmjs.org/' + quote(name, safe=''))
    result = {}
    for version in versions:
        row = observation(data)
        if row['metadata_status'] == 'observed':
            require(data.get('name') == name and isinstance(data.get('versions'), dict) and isinstance(data.get('time'), dict))
            package = data['versions'].get(version)
            require(isinstance(package, dict) and package.get('name') == name and package.get('version') == version)
            row['version_timestamp'] = timestamp(data['time'].get(version))
            repo = package.get('repository')
            row['repository'] = github_repository(repo.get('url') if isinstance(repo, dict) else repo)
            deprecated = package.get('deprecated', '')
            require(isinstance(deprecated, str) and len(deprecated.encode()) <= 65536)
            row['deprecated'] = bool(deprecated.strip())
        result[version] = row
    return result


def npm_metadata(name, version):
    return npm_package(name, [version])[version]


def pypi_metadata(name, version):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name)
            and isinstance(version, str) and re.fullmatch(r'[0-9][A-Za-z0-9.+!-]{0,126}', version))
    data = read_json('https://pypi.org/pypi/' + quote(name, safe='') + '/' + quote(version, safe='') + '/json')
    result = observation(data)
    if result['metadata_status'] != 'observed': return result
    info = data.get('info'); require(isinstance(info, dict))
    normalize = lambda text: re.sub(r'[-_.]+', '-', text).lower()
    require(isinstance(info.get('name'), str) and normalize(info['name']) == normalize(name) and info.get('version') == version)
    urls = info.get('project_urls'); require(urls is None or isinstance(urls, dict) and len(urls) <= 64)
    candidates = {github_repository(value) for value in (urls or {}).values()} - {None}
    result['repository'] = next(iter(candidates)) if len(candidates) == 1 else None
    return result


def graphql(query):
    try:
        require(isinstance(query, str) and query.startswith('query {') and len(query) <= 65536)
        environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'GH_TOKEN', 'GITHUB_TOKEN') if key in os.environ}
        environment.update(GH_PROMPT_DISABLED='1', GH_PAGER='cat', LC_ALL='C.UTF-8')
        # gh exits 1 for partial GraphQL NOT_FOUND responses. Retain that bounded
        # JSON; repositories() accepts only exact missing aliases, rejecting
        # auth, rate-limit and other errors. Query arguments never enter shell code.
        raw = inventory._run(['/bin/sh', '-c', 'gh "$@"; code=$?; [ "$code" -eq 0 ] || [ "$code" -eq 1 ]',
                       'maintenance-public-query', 'api', '--hostname', 'github.com', '--method', 'POST', 'graphql', '-f', 'query=' + query],
                      actions.ROOT, environment, timeout=45)
        result = policy.parse_document(raw); require(isinstance(result, dict)); return result
    except (OSError, ValueError, TypeError): raise SourceError() from None


def repositories(requests):
    try:
        require(isinstance(requests, dict) and 0 < len(requests) <= MAX_REPOSITORIES)
        names = sorted(requests)
        for repo in names:
            require(actions.repository(repo) == repo)
            row = requests[repo]; require(isinstance(row, dict) and set(row) == {'commits', 'releases'})
            for key, pattern in [('commits', SHA), ('releases', TAG)]:
                values = row[key]
                require(isinstance(values, list) and len(values) <= 64 and len(values) == len(set(values))
                        and all(isinstance(value, str) and pattern.fullmatch(value) for value in values))
        result = {}
        for offset in range(0, len(names), BATCH_SIZE):
            batch = names[offset:offset + BATCH_SIZE]; aliases = {f'r{index}': repo for index, repo in enumerate(batch)}
            fields = []
            for alias, repo in aliases.items():
                owner, name = repo.split('/')
                selections = ['nameWithOwner isPrivate isArchived isDisabled pushedAt']
                selections += [f'c{index}:object(expression:{json.dumps(sha)}) {{ ... on Commit {{ oid committedDate }} }}'
                               for index, sha in enumerate(requests[repo]['commits'])]
                selections += [f'v{index}:release(tagName:{json.dumps(tag)}) {{ tagName publishedAt isDraft }}'
                               for index, tag in enumerate(requests[repo]['releases'])]
                fields.append(f'{alias}:repository(owner:{json.dumps(owner)},name:{json.dumps(name)}) {{ ' + ' '.join(selections) + ' }')
            response = graphql('query { ' + ' '.join(fields) + ' }')
            errors = response.get('errors', []); require(isinstance(errors, list) and len(errors) <= len(batch))
            missing = set()
            for error in errors:
                require(isinstance(error, dict) and error.get('type') == 'NOT_FOUND'
                        and isinstance(error.get('path'), list) and len(error['path']) == 1 and error['path'][0] in aliases)
                missing.add(error['path'][0])
            data = response.get('data'); require(isinstance(data, dict) and set(data) == set(aliases))
            for alias, repo in aliases.items():
                value = data[alias]
                if value is None:
                    require(alias in missing)
                    result[repo] = {'metadata_status': 'not-found', 'canonical_repository': None,
                                    'archived': None, 'disabled': None, 'last_push': None, 'commits': {}, 'releases': {}}
                    continue
                require(alias not in missing and isinstance(value, dict) and value.get('isPrivate') is False
                        and type(value.get('isArchived')) is bool and type(value.get('isDisabled')) is bool)
                row = {'metadata_status': 'observed', 'canonical_repository': actions.repository(value.get('nameWithOwner')),
                       'archived': value['isArchived'], 'disabled': value['isDisabled'],
                       'last_push': timestamp(value.get('pushedAt')), 'commits': {}, 'releases': {}}
                for index, sha in enumerate(requests[repo]['commits']):
                    commit = value.get(f'c{index}')
                    require(commit is None or isinstance(commit, dict) and commit.get('oid') == sha)
                    row['commits'][sha] = timestamp(commit.get('committedDate')) if commit else None
                for index, tag in enumerate(requests[repo]['releases']):
                    release = value.get(f'v{index}')
                    require(release is None or isinstance(release, dict) and release.get('tagName') == tag and release.get('isDraft') is False)
                    row['releases'][tag] = timestamp(release.get('publishedAt')) if release else None
                result[repo] = row
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError): raise SourceError() from None
