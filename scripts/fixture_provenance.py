#!/usr/bin/env python3
"""Check fixture coverage, immutable bytes and recorded upstream license sources."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

import dependency_policy as policy
from release_lifecycle import read_bytes
from release_scanner import capture

ROOT = Path(__file__).resolve().parents[1]
CATALOG = 'testdata/fixture-provenance.v1.json'
CORPUS = 'testdata/parser-corpus.v1.json'
SCHEMA = 'evydence-fixture-provenance.v1'
MAX_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
ROOTS = ('testdata', 'scripts/testdata', 'internal/app/parsers',
         'internal/adapters/verification/sigstore/testdata', 'internal/platform/config/testdata')
REF = {'repository', 'commit', 'path', 'sha256', 'git_blob'}
PROJECT_CC0 = {'internal/app/parsers/scanners/testdata/generic.json',
               'internal/app/parsers/scanners/testdata/grype.json'}


class ProvenanceError(ValueError):
    def __init__(self):
        super().__init__('invalid fixture coverage, source binding or license record')


def require(condition):
    if not condition:
        raise ProvenanceError()


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    # Git object identity only; SHA-256 independently binds the source bytes.
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw, usedforsecurity=False).hexdigest()


def hex_value(value, length):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None)


def path_value(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._/-]{1,1024}', value) is not None
            and all(part not in {'', '.', '..'} for part in value.split('/')))
    return value


def notice_path(value):
    path_value(value)
    require(value == 'LICENSE' or re.fullmatch(r'testdata/licenses/[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value) is not None)
    return value


def note_path(value):
    path_value(value)
    require(Path(value).name in {'SOURCE.md', 'SOURCES.md'}
            and all(not part.startswith('.') for part in value.split('/'))
            and any(value.startswith(root + '/') for root in ROOTS))
    return value


def license_value(value):
    require(isinstance(value, str) and value.upper() not in {'NONE', 'UNKNOWN', 'NOASSERTION', 'UNLICENSED'})
    policy.license_allowed(value, {'allowed_licenses': ['MIT'], 'allowed_with': []})


def reference(source):
    keys(source, REF)
    require(isinstance(source['repository'], str) and re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', source['repository']) is not None)
    require(all(part not in {'.', '..'} for part in source['repository'].split('/')))
    path_value(source['path'])
    hex_value(source['commit'], 40); hex_value(source['git_blob'], 40); hex_value(source['sha256'], 64)
    return source


def canonical_json(raw):
    try:
        return json.dumps(policy.parse_document(raw), sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProvenanceError() from None


def json_block(raw, index):
    require(type(index) is int and 0 <= index < 128 and len(raw) <= MAX_BYTES)
    blocks, fence, language, lines = [], None, None, []
    try:
        for line in raw.decode('utf-8').splitlines():
            if fence is None and line.startswith('```'):
                require(not line.startswith('````'))
                fence, language, lines = '```', line[3:].strip(), []
            elif fence and line.strip() == fence:
                if language == 'json':
                    blocks.append('\n'.join(lines).encode())
                    require(len(blocks) <= 128)
                fence = None
            elif fence:
                lines.append(line)
        require(fence is None and index < len(blocks))
        return blocks[index]
    except (UnicodeError, ValueError):
        raise ProvenanceError() from None


def check_transform(source, local):
    kind = source['kind']
    if kind == 'bytes':
        require(digest(local) == source['sha256'] and git_blob(local) == source['git_blob'])
    elif kind in {'json', 'markdown-json'}:
        require(digest(canonical_json(local)) == source['canonical_sha256'])
    else:
        raise ProvenanceError()


def fixture_paths(root):
    result = set()
    for name in ROOTS:
        directory = Path(root) / name
        require(not directory.is_symlink())
        if not directory.exists():
            continue
        for path in directory.rglob('*'):
            require(not path.is_symlink())
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if (relative in {CATALOG, CORPUS} or relative.startswith('testdata/licenses/')
                    or path.suffix == '.md' or name == 'internal/app/parsers' and '/testdata/' not in relative and '/schema/' not in relative):
                continue
            result.add(relative)
            require(len(result) <= 512)
    return result


def load(root):
    try:
        return policy.parse_document(read_bytes(root, CATALOG, MAX_BYTES))
    except (OSError, ValueError, UnicodeError):
        raise ProvenanceError() from None


def validate(root, catalog, *, read_file=read_bytes):
    try:
        keys(catalog, {'schema', 'notices', 'fixtures'})
        require(catalog['schema'] == SCHEMA and isinstance(catalog['notices'], list)
                and 1 <= len(catalog['notices']) <= 64 and isinstance(catalog['fixtures'], list)
                and 1 <= len(catalog['fixtures']) <= 512)
        notices, rows, covered, identities, total = {}, [], set(), set(), 0

        def read(row):
            nonlocal total
            path_value(row['path']); hex_value(row['sha256'], 64)
            raw = read_file(root, row['path'], MAX_BYTES)
            total += len(raw)
            require(total <= MAX_TOTAL_BYTES and digest(raw) == row['sha256'])
            return raw

        for notice in catalog['notices']:
            keys(notice, {'id', 'license', 'path', 'sha256', 'source'})
            require(isinstance(notice['id'], str) and re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', notice['id']) is not None
                    and notice['id'] not in notices)
            notice_path(notice['path'])
            license_value(notice['license']); raw = read(notice)
            if notice['source'] is None:
                require(notice['id'] == 'evydence' and notice['path'] == 'LICENSE' and notice['license'] == 'AGPL-3.0-only')
            else:
                source = reference(notice['source'])
                require(digest(raw) == source['sha256'] and git_blob(raw) == source['git_blob'])
            notices[notice['id']] = notice

        for item in catalog['fixtures']:
            keys(item, {'id', 'license', 'notices', 'files', 'source'})
            require(isinstance(item['id'], str) and re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', item['id']) is not None
                    and item['id'] not in identities and isinstance(item['files'], list) and 1 <= len(item['files']) <= 64)
            identities.add(item['id']); license_value(item['license'])
            require(isinstance(item['notices'], list) and 1 <= len(item['notices']) <= 16
                    and all(isinstance(value, str) and value in notices for value in item['notices'])
                    and len(set(item['notices'])) == len(item['notices'])
                    and any(notices[value]['license'] == item['license'] for value in item['notices']))
            parts = []
            for file in item['files']:
                keys(file, {'path', 'sha256'})
                require(file['path'] not in covered)
                covered.add(file['path']);parts.append(read(file))
            raw = b''.join(parts); source = item['source']
            require(isinstance(source, dict))
            kind = source.get('kind')
            if kind in {'bytes', 'json', 'markdown-json'}:
                extras = {'canonical_sha256'} if kind in {'json', 'markdown-json'} else set()
                if kind == 'markdown-json':extras.add('json_block')
                keys(source, REF | {'kind'} | extras)
                reference({key: source[key] for key in REF})
                scoped_notices = [notices[identity] for identity in item['notices']
                                  if notices[identity]['source'] is not None
                                  and notices[identity]['license'] == item['license']]
                require(any(notice['source']['repository'] == source['repository']
                            and notice['source']['commit'] == source['commit']
                            and re.fullmatch(r'(?i:licen[sc]e|unlicense)(?:[._-][A-Za-z0-9._-]+)?',
                                             notice['source']['path'].rsplit('/', 1)[-1]) is not None
                            and source['path'].split('/')[:len(notice['source']['path'].split('/')) - 1]
                                == notice['source']['path'].split('/')[:-1]
                            for notice in scoped_notices))
                if extras:hex_value(source['canonical_sha256'], 64)
                if kind == 'markdown-json':require(type(source['json_block']) is int and 0 <= source['json_block'] < 128)
                check_transform(source, raw)
            elif kind == 'project':
                require(set(source) in ({'kind'}, {'kind', 'introduced_commit'}))
                if 'introduced_commit' in source:hex_value(source['introduced_commit'], 40)
                expected = {'CC0-1.0' if file['path'] in PROJECT_CC0 else 'AGPL-3.0-only' for file in item['files']}
                require(expected == {item['license']})
            elif kind == 'recorded-generated':
                keys(source, {'kind', 'note', 'introduced_commit'})
                hex_value(source['introduced_commit'], 40)
                note = read_file(root, note_path(source['note']), MAX_BYTES).decode('utf-8')
                require(len(item['files']) == 1 and Path(item['files'][0]['path']).name in note
                        and policy.parse_document(raw).get('dataLicense') == item['license'])
            else:
                raise ProvenanceError()
            rows.append({'ecosystem': 'fixture', 'name': item['id'], 'version': digest(raw),
                         'origins': ['fixtures'], 'license': item['license'],
                         'license_status': 'recorded-declaration', 'license_evidence': [],
                         'source': dict(source, files=item['files'], notices=item['notices'], verification='local-digests-checked')})
        require(covered == fixture_paths(root))
        corpus = policy.parse_document(read_file(root, CORPUS, MAX_BYTES))
        require(isinstance(corpus, dict) and isinstance(corpus.get('fixtures'), list) and len(corpus['fixtures']) <= 128)
        by_path = {file['path']: row for row in rows for file in row['source']['files']}
        seen = set()
        for entry in corpus['fixtures']:
            path = path_value(entry['path'])
            require(path in by_path and path not in seen and by_path[path]['license'] == entry['license'])
            seen.add(path)
            file = next(file for file in by_path[path]['source']['files'] if file['path'] == path)
            require(file['sha256'] == entry['sha256'])
            note = read_file(root, note_path(entry['source']), MAX_BYTES).decode('utf-8')
            require(Path(path).name in note)
        return sorted(rows, key=lambda row: row['name'])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise ProvenanceError() from None


def github_source(source):
    try:
        reference(source)
        endpoint = 'repos/' + source['repository'] + '/contents/' + quote(source['path'], safe='/') + '?ref=' + source['commit']
        environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'GH_TOKEN', 'GITHUB_TOKEN') if key in os.environ}
        environment.update(GH_PROMPT_DISABLED='1', GH_PAGER='cat', LC_ALL='C.UTF-8')
        raw = capture(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                       '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2026-03-10', endpoint],
                      ROOT, environment, MAX_BYTES, 30)
        reply = policy.parse_document(raw)
        require(isinstance(reply, dict) and reply.get('type') == 'file' and reply.get('path') == source['path']
                and reply.get('sha') == source['git_blob'] and type(reply.get('size')) is int
                and 0 < reply['size'] <= MAX_BYTES and reply.get('encoding') == 'base64' and isinstance(reply.get('content'), str))
        content = base64.b64decode(reply['content'].replace('\n', ''), validate=True)
        require(len(content) == reply['size'] and digest(content) == source['sha256'] and git_blob(content) == source['git_blob'])
        return content
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise ProvenanceError() from None


def verify_upstream(catalog, fetch=github_source):
    sources = [notice['source'] for notice in catalog['notices'] if notice['source'] is not None]
    sources += [item['source'] for item in catalog['fixtures'] if item['source']['kind'] in {'bytes', 'json', 'markdown-json'}]
    fetched, total = {}, 0
    for source in sources:
        ref = {key: source[key] for key in REF}
        identity = (ref['repository'], ref['commit'], ref['path'])
        if identity not in fetched:
            raw = fetch(ref)
            total += len(raw)
            require(total <= MAX_TOTAL_BYTES)
            fetched[identity] = raw
        raw = fetched[identity]
        require(digest(raw) == ref['sha256'] and git_blob(raw) == ref['git_blob'])
        if source.get('kind') in {'json', 'markdown-json'}:
            selected = json_block(raw, source['json_block']) if source['kind'] == 'markdown-json' else raw
            require(digest(canonical_json(selected)) == source['canonical_sha256'])
    return len(fetched)


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, 'fixture-provenance: invalid arguments\n')


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--upstream', action='store_true')
    args = parser.parse_args(argv)
    try:
        catalog = load(args.root); rows = validate(args.root, catalog)
        count = verify_upstream(catalog) if args.upstream else 0
        print('fixture-provenance: ' + str(len(rows)) + ' fixture records checked; ' + str(count) + ' live upstream files checked')
        return 0
    except (OSError, ValueError, UnicodeError):
        print('fixture-provenance: validation failed; check recorded coverage, digests and source references', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
