#!/usr/bin/env python3
"""Collect source-bound dependency observations; admission and publication are separate."""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit
import uuid
import zipfile

import dependency_policy as policy
import dependency_node_sources as node_sources
import dependency_python_sources as python_sources
import fixture_provenance as fixture_sources
from release_lifecycle import read_bytes

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'evydence-dependency-inventory.v1'
MAX_BYTES = 4 * 1024 * 1024
MAX_LICENSE_SET_BYTES = 128 * 1024 * 1024
GRAPHS = (
    ('application', 'go.mod', 'go.sum', 'github.com/aatuh/evydence'),
    ('qa', 'tools/go.mod', 'tools/go.sum', 'github.com/aatuh/evydence/tools'),
    ('scanner', 'release/tools/syft.go.mod', 'release/tools/syft.go.sum', 'github.com/anchore/syft'),
)
GENERATOR_FILES = ('scripts/dependency_inventory.py', 'scripts/dependency_node_sources.py',
                   'scripts/dependency_python_sources.py', 'scripts/python_qa.py', 'scripts/dependency_policy.py',
                   'scripts/fixture_provenance.py',
                   'scripts/release_lifecycle.py', 'scripts/support_matrix.py',
                   'tools/cmd/license-inventory/main.go')
LICENSE_NAME = re.compile(r'(?:licen[sc]e|copying|copyright|unlicense)(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
NOTICE_NAME = re.compile(r'notice(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


class InventoryError(ValueError):
    """Safe error without raw paths, command output or registry payloads."""


def parse_go_stream(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise InventoryError('module metadata exceeds its byte budget or is empty')
    try:
        text, position, result = raw.decode('utf-8'), 0, []
        decoder = json.JSONDecoder()
        while position < len(text):
            if text[position] in ' \r\n\t':
                position += 1
                continue
            _value, end = decoder.raw_decode(text, position)
            row = policy.parse_document(text[position:end].encode('utf-8'))
            if not isinstance(row, dict) or len(result) >= 4096:
                raise InventoryError('invalid module metadata record')
            result.append(row)
            position = end
        if not result:
            raise InventoryError('empty module metadata stream')
        return result
    except (UnicodeError, ValueError, RecursionError):
        raise InventoryError('invalid module JSON stream') from None


def coordinates(row):
    try:
        return policy._coordinates(row)
    except (ValueError, TypeError, AttributeError):
        raise InventoryError('invalid dependency coordinates') from None


def checksum(value, prefix, size):
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) > 128:
        raise InventoryError('missing or unsupported source integrity')
    try:
        raw = base64.b64decode(value[len(prefix):], validate=True)
    except (ValueError, binascii.Error):
        raise InventoryError('invalid source integrity encoding') from None
    if len(raw) != size or prefix + base64.b64encode(raw).decode() != value:
        raise InventoryError('invalid source integrity length or encoding')
    return value


def published_at(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise InventoryError('invalid version publication time')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError()
        return result.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except ValueError:
        raise InventoryError('invalid version publication time') from None


def go_components(rows, downloads, scope, expected_main):
    if not isinstance(rows, list) or not rows or not isinstance(downloads, list) or scope not in {x[0] for x in GRAPHS}:
        raise InventoryError('invalid module graph shape or scope')
    sources = {}
    for row in downloads:
        if not isinstance(row, dict) or row.get('Error') is not None:
            raise InventoryError('failed module source retrieval')
        key = coordinates({'ecosystem': 'gomod', 'name': row.get('Path'), 'version': row.get('Version')})
        if key in sources:
            raise InventoryError('duplicate module source identity')
        sources[key] = {'sum': checksum(row.get('Sum'), 'h1:', 32),
                        'go_mod_sum': checksum(row.get('GoModSum'), 'h1:', 32)}
    result, seen, mains = [], set(), 0
    for row in rows:
        if (not isinstance(row, dict) or row.get('Error') is not None or row.get('Replace') is not None
                or 'Main' in row and type(row['Main']) is not bool):
            raise InventoryError('failed or replaced module graph record')
        if row.get('Main') is True:
            if row.get('Path') != expected_main:
                raise InventoryError('unexpected main module identity')
            mains += 1
            continue
        key = coordinates({'ecosystem': 'gomod', 'name': row.get('Path'), 'version': row.get('Version')})
        if key in seen or key not in sources:
            raise InventoryError('duplicate or missing selected module source')
        seen.add(key)
        result.append({'ecosystem': key[0], 'name': key[1], 'version': key[2],
                       'origins': [scope], 'license': None, 'license_status': 'unobserved',
                       'license_evidence': [], 'source': sources[key],
                       'version_published_at': published_at(row.get('Time'))})
    if mains != 1 or seen != set(sources):
        raise InventoryError('incomplete or unexpected module graph/source set')
    return result


def node_name(location):
    if not isinstance(location, str) or len(location) > 1024:
        raise InventoryError('invalid npm package location')
    parts, position, name = location.split('/'), 0, None
    if len(parts) > 64 or any(part in {'', '.', '..'} for part in parts):
        raise InventoryError('invalid npm package location')
    while position < len(parts):
        if parts[position] != 'node_modules' or position + 1 >= len(parts):
            raise InventoryError('invalid npm package location')
        position += 1
        name = parts[position]
        position += 1
        if name.startswith('@'):
            if position >= len(parts):
                raise InventoryError('incomplete scoped npm package location')
            name += '/' + parts[position]
            position += 1
    return name


def node_components(manifest, lock):
    if (not isinstance(manifest, dict) or not isinstance(lock, dict)
            or type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] != 3
            or not isinstance(lock.get('packages'), dict) or not 1 <= len(lock['packages']) <= 4096
            or not isinstance(lock['packages'].get(''), dict)):
        raise InventoryError('unsupported npm manifest or lock format')
    root = lock['packages']['']
    for key in ('name', 'version'):
        if not isinstance(manifest.get(key), str) or root.get(key) != manifest[key] or lock.get(key) != manifest[key]:
            raise InventoryError('npm root manifest/lock identity mismatch')
    for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
        if manifest.get(key, {}) != root.get(key, {}) or not isinstance(manifest.get(key, {}), dict):
            raise InventoryError('npm direct dependency declarations differ')
        for name, version in manifest.get(key, {}).items():
            if not isinstance(name, str) or not isinstance(version, str) or 'node_modules/' + name not in lock['packages']:
                raise InventoryError('missing npm direct dependency')
    result = []
    for location, entry in lock['packages'].items():
        if location == '':
            continue
        if (not isinstance(entry, dict)
                or 'link' in entry and (type(entry['link']) is not bool or entry['link'])):
            raise InventoryError('unsupported npm package link')
        name, version = node_name(location), entry.get('version')
        coordinates({'ecosystem': 'npm', 'name': name, 'version': version})
        if (not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', version)
                or 'name' in entry and entry['name'] != name
                or any(key in entry and type(entry[key]) is not bool for key in ('dev', 'optional', 'hasInstallScript'))):
            raise InventoryError('unsupported npm package version or flags')
        url = entry.get('resolved')
        if not isinstance(url, str) or len(url) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in url):
            raise InventoryError('invalid npm source URL')
        try:
            parsed = urlsplit(url)
            expected = '/' + name + '/-/' + name.rsplit('/', 1)[-1] + '-' + version + '.tgz'
            valid = (parsed.scheme == 'https' and parsed.netloc == 'registry.npmjs.org'
                     and not parsed.query and not parsed.fragment
                     and unquote(parsed.path, errors='strict') == expected)
        except (ValueError, UnicodeError):
            valid = False
        if not valid:
            raise InventoryError('unsupported or mismatched npm source URL')
        expression = entry.get('license')
        try:
            policy.license_allowed(expression, {'allowed_licenses': ['MIT'], 'allowed_with': []})
        except policy.PolicyError:
            raise InventoryError('unsupported npm license expression') from None
        result.append({'ecosystem': 'npm', 'name': name, 'version': version,
                       'origins': ['marketing'], 'locations': [location],
                       'license': expression, 'license_status': 'declared' if expression else 'unknown',
                       'license_evidence': [], 'version_published_at': None,
                       'source': {'url': url, 'integrity': checksum(entry.get('integrity'), 'sha512-', 64),
                                  'verification': 'lockfile-declared'}})
    return merge_components(result)


def merge_components(rows):
    merged = {}
    for row in rows:
        key = coordinates(row)
        if key not in merged:
            merged[key] = copy.deepcopy(row)
            continue
        previous = merged[key]
        excluded = {'origins', 'locations'}
        if {k: v for k, v in previous.items() if k not in excluded} != {k: v for k, v in row.items() if k not in excluded}:
            raise InventoryError('conflicting observations for one dependency identity')
        for field in ('origins', 'locations'):
            if field in row:
                previous[field] = sorted(set(previous.get(field, []) + row[field]))
    return [merged[key] for key in sorted(merged)]


def regular_stream(root, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or '..' in path.parts:
        raise InventoryError('source path must remain beneath its root')
    directory = None
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        stream = os.fdopen(fd, 'rb')
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            stream.close()
            raise InventoryError('source must be a regular file')
        return stream
    except (OSError, ValueError):
        raise InventoryError('cannot open bounded module source') from None
    finally:
        if directory is not None:
            os.close(directory)


def license_files(cache_root, record):
    try:
        coordinates({'ecosystem': 'gomod', 'name': record.get('Path'), 'version': record.get('Version')})
        path = Path(record['Zip'])
        relative = path.relative_to(cache_root)
        prefix = record['Path'] + '@' + record['Version'] + '/'
        result, seen = [], set()
        with regular_stream(cache_root, relative) as stream:
            if os.fstat(stream.fileno()).st_size > 500 * 1024 * 1024:
                raise InventoryError('module archive exceeds its byte budget')
            with zipfile.ZipFile(stream) as archive:
                if len(archive.infolist()) > 65536:
                    raise InventoryError('module archive exceeds its entry budget')
                for info in archive.infolist():
                    if not info.filename.startswith(prefix):
                        raise InventoryError('unexpected module archive identity')
                    name = info.filename[len(prefix):]
                    if '/' in name or not (LICENSE_NAME.fullmatch(name) or NOTICE_NAME.fullmatch(name)):
                        continue
                    if (name in seen or len(result) >= 32 or info.file_size > 1024 * 1024
                            or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)):
                        raise InventoryError('unsupported or oversized module license entry')
                    seen.add(name)
                    with archive.open(info) as member:
                        raw = member.read(1024 * 1024 + 1)
                    if len(raw) > 1024 * 1024:
                        raise InventoryError('module license exceeds its byte budget')
                    result.append({'file': name, 'kind': 'notice' if NOTICE_NAME.fullmatch(name) else 'license',
                                   'sha256': hashlib.sha256(raw).hexdigest(), 'content': raw})
        return sorted(result, key=lambda row: row['file'])
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError):
        raise InventoryError('cannot read valid bounded module license entries') from None


def classifications(raw, expected):
    try:
        document = policy.parse_document(raw)
        if (not isinstance(document, dict) or set(document) != {'schema', 'results'}
                or document['schema'] != 'evydence-license-classification.v1'
                or not isinstance(document['results'], list) or len(document['results']) != len(expected)):
            raise InventoryError('invalid classifier result set')
        result = {}
        for digest, row in zip(expected, document['results']):
            if (not isinstance(row, dict) or set(row) != {'sha256', 'license', 'coverage_percent', 'ids', 'status'}
                    or row['sha256'] != digest or digest in result or not SHA256.fullmatch(digest)
                    or type(row['coverage_percent']) not in (int, float)
                    or not math.isfinite(row['coverage_percent']) or not 0 <= row['coverage_percent'] <= 100
                    or not isinstance(row['ids'], list) or len(row['ids']) > 128
                    or any(not isinstance(value, str) or not policy.ID.fullmatch(value) for value in row['ids'])
                    or row['ids'] != sorted(set(row['ids']))):
                raise InventoryError('invalid or mismatched classifier result')
            candidate = row['status'] == 'candidate'
            if (row['status'] not in ('candidate', 'ambiguous', 'unknown')
                    or candidate and (len(row['ids']) != 1 or row['license'] != row['ids'][0] or row['coverage_percent'] < 95)
                    or not candidate and row['license'] is not None
                    or row['status'] == 'ambiguous' and len(row['ids']) < 2):
                raise InventoryError('contradictory classifier result')
            result[digest] = copy.deepcopy(row)
        return result
    except (ValueError, TypeError, KeyError):
        raise InventoryError('invalid classifier observations') from None


def attach_licenses(component, files, matches):
    result = copy.deepcopy(component)
    evidence = []
    for row in files:
        match = matches[row['sha256']]
        evidence.append(dict(file=row['file'], kind=row['kind'], **match))
    result['license_evidence'] = evidence
    primary = [row for row in evidence if row['kind'] == 'license']
    ids = {row['license'] for row in primary if row['status'] == 'candidate'}
    result['license'], result['license_status'] = None, 'unknown'
    if not primary:
        result['license_status'] = 'not-found'
    elif len(ids) > 1 or any(row['status'] == 'ambiguous' for row in evidence):
        result['license_status'] = 'ambiguous'
    elif len(ids) == 1 and all(row['status'] == 'candidate' for row in primary):
        result['license'], result['license_status'] = next(iter(ids)), 'candidate'
        if any(row['license'] not in (None, result['license']) for row in evidence):
            result['license'], result['license_status'] = None, 'ambiguous'
    return result


def attach_declared_licenses(item, files, matches):
    result = attach_licenses(item, files, matches)
    result['license_text_status'] = result.pop('license_status')
    result['license_text_candidate'] = result.pop('license')
    result['license'], result['license_status'] = item['license'], item['license_status']
    return result


def attach_node_licenses(item, observation, files, matches):
    result = attach_declared_licenses(item, files, matches)
    result['lockfile_license'] = item['license']
    result['artifact_license'] = observation['license']
    result['source'].update({key: value for key, value in observation.items() if key != 'license'})
    matched = observation['declaration_status'] == 'matched' and observation['license'] is not None
    result['license'] = observation['license'] if matched else None
    result['license_status'] = 'artifact-declared' if matched else (
        'ambiguous' if observation['declaration_status'] == 'different' else 'unknown')
    return result


def tool_environment(parent):
    environment = {key: parent[key] for key in ('PATH', 'HOME', 'TMPDIR', 'GOTMPDIR', 'GOCACHE',
                                               'GOMODCACHE', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if parent.get(key)}
    environment.update(GOTOOLCHAIN='local', GOENV='off', GOWORK='off', GOFLAGS='-p=1 -mod=readonly',
                       GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOGC='50', CGO_ENABLED='0',
                       GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org',
                       GONOPROXY='none', GONOSUMDB='none', GOPRIVATE='', GOINSECURE='',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    return environment


def _run(args, cwd, environment, *, data=None, timeout=900, log=None):
    if data is not None and (not isinstance(data, bytes) or len(data) > 8 * 1024 * 1024):
        raise InventoryError('tool input exceeds its byte budget')
    with tempfile.TemporaryFile() as source:
        if data is not None:
            source.write(data)
        source.seek(0)
        try:
            process = subprocess.Popen(args, cwd=cwd, env=environment, stdin=source,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        except OSError:
            raise InventoryError('cannot start dependency tool') from None
        buffers = {'out': bytearray(), 'err': bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selected:
                selected.register(process.stdout, selectors.EVENT_READ, 'out')
                selected.register(process.stderr, selectors.EVENT_READ, 'err')
                while selected.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    events = selected.select(remaining)
                    if not events:
                        raise TimeoutError()
                    for key, _mask in events:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selected.unregister(key.fileobj)
                            continue
                        limit = MAX_BYTES if key.data == 'out' else 256 * 1024
                        if len(buffers[key.data]) + len(chunk) > limit:
                            raise InventoryError('dependency tool output exceeds its byte budget')
                        buffers[key.data].extend(chunk)
            if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise InventoryError('dependency tool failed; inspect its retained private log')
            return bytes(buffers['out'])
        except (OSError, TimeoutError, subprocess.TimeoutExpired):
            raise InventoryError('dependency tool failed or timed out') from None
        finally:
            # The parent may have exited while a descendant still owns a pipe.
            # Kill the owned group rather than using only the parent's status.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()
            if log is not None:
                with Path(log).open('xb') as target:
                    target.write(buffers['err'])
                with Path(log).with_suffix('.stdout').open('xb') as target:
                    target.write(buffers['out'])


def output_directory(root, relative, replace):
    path, directory = Path(relative), None
    if path.is_absolute() or not path.parts or '..' in path.parts:
        raise InventoryError('invalid inventory output path')
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        try:
            old = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None:
            if not replace or not stat.S_ISREG(old.st_mode):
                raise InventoryError('inventory output exists or is not a regular file')
            previous = policy.parse_document(read_bytes(root, relative, MAX_BYTES))
            if not isinstance(previous, dict) or previous.get('schema') != SCHEMA:
                raise InventoryError('refusing to replace an unrelated file')
        return directory, old
    except (OSError, ValueError):
        if directory is not None:
            os.close(directory)
        raise InventoryError('cannot use inventory output path') from None


def write_report(root, relative, report, *, replace=False):
    if not isinstance(report, dict) or report.get('schema') != SCHEMA:
        raise InventoryError('invalid inventory schema')
    raw = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()
    if len(raw) > MAX_BYTES:
        raise InventoryError('inventory exceeds its output budget')
    path, temporary = Path(relative), None
    directory, old = output_directory(root, relative, replace)
    try:
        candidate = '.dependency-inventory-' + uuid.uuid4().hex
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=directory)
        temporary = candidate
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if old is None:
            os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        else:
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
    except (OSError, ValueError):
        raise InventoryError('cannot atomically write inventory output') from None
    finally:
        if directory is not None:
            if temporary is not None:
                os.unlink(temporary, dir_fd=directory)
            os.close(directory)


def _classify_files(files, executable, root, environment, work):
    unique, total = {}, 0
    for item in files:
        digest, content = item['sha256'], item['content']
        if hashlib.sha256(content).hexdigest() != digest:
            raise InventoryError('license bytes changed before classification')
        if digest not in unique:
            total += len(content)
            unique[digest] = content
    if total > MAX_LICENSE_SET_BYTES:
        raise InventoryError('license set exceeds its byte budget')
    result, batch, index = {}, [], 0

    def flush():
        nonlocal batch, index
        if not batch:
            return
        raw = json.dumps(batch, separators=(',', ':')).encode()
        output = _run([str(executable)], root, environment, data=raw, timeout=120,
                      log=work / ('classify-' + str(index) + '.log'))
        result.update(classifications(output, [row['sha256'] for row in batch]))
        index += 1
        batch = []

    for digest in sorted(unique):
        row = {'sha256': digest, 'content_base64': base64.b64encode(unique[digest]).decode()}
        if batch and (len(batch) == 64 or len(json.dumps(batch + [row], separators=(',', ':'))) > 8 * 1024 * 1024):
            flush()
        batch.append(row)
    flush()
    return result


def fixture_components(root, inputs):
    """Bind fixture records and notice bytes to the collector's frozen inputs."""
    seen, total = set(), 0

    def capture(folder, name, maximum):
        nonlocal total
        if name not in inputs:
            inputs[name] = read_bytes(folder, name, maximum)
        raw = inputs[name]
        if not isinstance(raw, bytes) or len(raw) > maximum:
            raise InventoryError('invalid fixture snapshot input')
        if name not in seen:
            total += len(raw)
            seen.add(name)
            if total > fixture_sources.MAX_TOTAL_BYTES:
                raise InventoryError('fixture snapshot exceeds its byte budget')
        return raw

    try:
        catalog = policy.parse_document(capture(root, fixture_sources.CATALOG, MAX_BYTES))
        rows = fixture_sources.validate(root, catalog, read_file=capture)
        notices = {item['id']: item for item in catalog['notices']}
        observations = {}
        for row in rows:
            row['license_notices'] = [copy.deepcopy(notices[identity]) for identity in row['source']['notices']]
            files = []
            for notice in row['license_notices']:
                name = (notice['source'] or notice)['path'].rsplit('/', 1)[-1]
                kind = 'notice' if NOTICE_NAME.fullmatch(name) or name.lower().startswith('copyright') else 'license'
                files.append({'file': notice['path'], 'kind': kind, 'sha256': notice['sha256'],
                              'content': inputs[notice['path']]})
            observations[row['name']] = files
        return rows, observations
    except (OSError, ValueError, KeyError, TypeError):
        raise InventoryError('cannot bind valid fixture records and notice bytes') from None


def collect(root, work_root, parent_environment):
    """Verify Go/Node/Python source bytes; retain explicit scope gaps."""
    import support_matrix
    root, work_root = Path(root).resolve(), Path(work_root)
    if work_root.is_symlink() or not work_root.is_dir():
        raise InventoryError('inventory work root must be an existing directory')
    names = set(GENERATOR_FILES) | {fixture_sources.CATALOG, 'release/support-matrix.json', 'tools/requirements-qa.txt',
                                    'site/marketing/package.json', 'site/marketing/package-lock.json'}
    for _scope, mod, sums, _main in GRAPHS:
        names.update((mod, sums))
    try:
        inputs = {name: read_bytes(root, name, MAX_BYTES) for name in sorted(names)}
        for name in GENERATOR_FILES:
            if name.endswith('.py') and inputs[name] != read_bytes(ROOT, name, MAX_BYTES):
                raise InventoryError('collector implementation differs from its source record')
        expected_go = 'go' + support_matrix.load_policy(root)['go']['current']
        node = node_components(policy.parse_document(inputs['site/marketing/package.json']),
                               policy.parse_document(inputs['site/marketing/package-lock.json']))
        fixtures, fixture_files = fixture_components(root, inputs)
    except (ValueError, OSError):
        raise InventoryError('cannot read valid inventory inputs') from None
    environment = tool_environment(parent_environment)
    version = _run(['go', 'version'], root, environment, timeout=30).decode().strip()
    if re.fullmatch(r'go version ' + re.escape(expected_go) + r' [a-z0-9]+/[a-z0-9]+', version) is None:
        raise InventoryError('inventory requires the declared current Go compiler with switching disabled')
    cache_text = _run(['go', 'env', 'GOMODCACHE'], root, environment, timeout=30).decode().strip()
    cache = Path(cache_text)
    if not cache.is_absolute() or not cache.is_dir():
        raise InventoryError('invalid Go source cache root')
    work = Path(tempfile.mkdtemp(prefix='evydence-dependency-inventory-', dir=work_root))
    components, observations, raw_files, license_bytes = [], {}, [], {}
    license_total = 0

    def register_files(files):
        nonlocal license_total
        for file in files:
            digest, content = file['sha256'], file['content']
            if digest not in license_bytes:
                license_total += len(content)
                if license_total > MAX_LICENSE_SET_BYTES:
                    raise InventoryError('license set exceeds its byte budget')
                license_bytes[digest] = content
            file['content'] = license_bytes[digest]
        raw_files.extend(files)

    for files in fixture_files.values():
        register_files(files)
    python_work = work / 'python'; python_work.mkdir()
    try:
        python_component, python_files = python_sources.fetch(inputs['tools/requirements-qa.txt'], python_work)
        register_files(python_files)
    except python_sources.PythonSourceError:
        raise InventoryError('cannot verify bounded Python source artifacts') from None
    node_observations = {}
    node_work = work / 'npm'; node_work.mkdir()
    try:
        for index, item in enumerate(node):
            observation, files = node_sources.fetch(item, node_work)
            register_files(files)
            node_observations[(item['name'], item['version'])] = (observation, files)
            if (index + 1) % 25 == 0 or index + 1 == len(node):
                print('dependency-inventory: verified ' + str(index + 1) + '/' + str(len(node)) +
                      ' npm source archives', file=sys.stderr, flush=True)
    except node_sources.NodeSourceError:
        print('dependency-inventory: npm source observation failed for ' + item['name'] + '@' +
              item['version'], file=sys.stderr, flush=True)
        raise InventoryError('cannot verify bounded npm source archives') from None
    for scope, mod, sums, main_module in GRAPHS:
        folder = work / scope; folder.mkdir()
        (folder / 'go.mod').write_bytes(inputs[mod])
        (folder / 'go.sum').write_bytes(inputs[sums])
        rows = parse_go_stream(_run(['go', 'list', '-m', '-mod=readonly', '-json', 'all'], folder,
                                    environment, log=folder / 'resolve.log'))
        if any(row.get('Replace') is not None or row.get('Error') is not None for row in rows):
            raise InventoryError('module graph contains replacements or unresolved records')
        print('dependency-inventory: fetching ' + scope + ' graph sources', file=sys.stderr, flush=True)
        downloads = parse_go_stream(_run(['go', 'mod', 'download', '-json', 'all'], folder,
                                         environment, log=folder / 'download.log', timeout=1800))
        selected = go_components(rows, downloads, scope, main_module)
        _run(['go', 'mod', 'verify'], folder, environment, log=folder / 'verify.log')
        if (folder / 'go.mod').read_bytes() != inputs[mod]:
            raise InventoryError('isolated module manifest changed during resolution')
        sources = {(row['Path'], row['Version']): row for row in downloads}
        for item in selected:
            item['source']['verification'] = 'go-mod-verify'
            files = license_files(cache, sources[(item['name'], item['version'])])
            register_files(files)
            observations[(scope, item['name'], item['version'])] = files
        components.extend(selected)
        print('dependency-inventory: verified ' + scope + ' source graph', file=sys.stderr, flush=True)
    executable = work / 'license-classifier'
    _run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(executable), './cmd/license-inventory'],
         root / 'tools', environment, log=work / 'classifier-build.log')
    matches = _classify_files(raw_files, executable, root, environment, work)
    components = [attach_licenses(item, observations[(item['origins'][0], item['name'], item['version'])], matches)
                  for item in components]
    node = [attach_node_licenses(item, *node_observations[(item['name'], item['version'])], matches)
            for item in node]
    python_component = attach_declared_licenses(python_component, python_files, matches)
    fixtures = [attach_declared_licenses(item, fixture_files[item['name']], matches) for item in fixtures]
    merged = merge_components(components + node + [python_component] + fixtures)
    try:
        expected = {file['path'] for item in fixtures for file in item['source']['files']}
        if (any(read_bytes(root, name, MAX_BYTES) != raw for name, raw in inputs.items())
                or fixture_sources.fixture_paths(root) != expected):
            raise InventoryError('inventory source changed during collection')
    except (OSError, ValueError):
        raise InventoryError('inventory source or fixture coverage changed during collection') from None
    return {
        'schema': SCHEMA, 'complete': False,
        'generator': {'go_version': version.split()[2], 'python_version': sys.version.split()[0],
                      'files': {name: hashlib.sha256(inputs[name]).hexdigest() for name in GENERATOR_FILES}},
        'inputs': {name: hashlib.sha256(raw).hexdigest() for name, raw in inputs.items() if name not in GENERATOR_FILES},
        'components': merged,
        'remaining_scopes': ['build-tool-archives', 'actions', 'images'],
        'limitations': [
            'Go module graphs describe available dependencies, not only code linked into an artifact.',
            'Go root license bytes are checksum-bound observations; candidates are not approval or legal compatibility conclusions.',
            'Nested third-party notices and license obligations may require additional review.',
            'Node artifact license declarations and root text candidates are separate observations, not license approval.',
            'Python observations cover the pinned PyYAML distributions, not the interpreter, installer bootstrap or all bundled third-party obligations.',
            'Fixture byte/notice checks cover the declared catalog roots; pinned upstream references are recorded declarations, with separate live verification.',
            'This is not an artifact SBOM, vulnerability scan or complete dependency inventory.',
        ],
    }


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, 'dependency-inventory: invalid command arguments\n')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--work-root', type=Path, required=True)
    parser.add_argument('--output', required=True, help='Output path relative to root; unrelated files are never replaced.')
    parser.add_argument('--replace', action='store_true')
    args = parser.parse_args(argv)
    old_handlers = {}
    try:
        def interrupted(_signum, _frame):
            raise InventoryError('inventory interrupted')
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, interrupted)
        directory, _old = output_directory(args.root, args.output, args.replace)
        os.close(directory)
        report = collect(args.root, args.work_root, os.environ)
        write_report(args.root, args.output, report, replace=args.replace)
        print('dependency-inventory: wrote ' + str(len(report['components'])) + ' partial-scope observations')
        return 0
    except (InventoryError, ValueError, OSError, UnicodeError):
        print('dependency-inventory: operation failed; inspect the output and retained private work logs', file=sys.stderr)
        return 2
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    sys.exit(main())
