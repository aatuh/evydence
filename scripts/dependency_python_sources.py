#!/usr/bin/env python3
"""Observe every pinned PyYAML source/wheel artifact without installing code."""
from datetime import datetime
from email.parser import Parser
import gzip
import hashlib
import io
import re
import stat
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile
import zlib

import dependency_policy as policy
from python_qa import parse_requirements

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_MEMBERS = 65536
MAX_SELECTED_FILES = 32
MAX_LICENSE_SET_BYTES = 128 * 1024 * 1024
LICENSE = re.compile(r'(?:licen[sc]e|copying|copyright|unlicense)(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
NOTICE = re.compile(r'notice(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


class PythonSourceError(ValueError):
    def __init__(self):
        super().__init__('invalid or unavailable pinned Python source observations')


def select_artifacts(raw, version, hashes):
    try:
        body = policy.parse_document(raw)
        if (not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)
                or not isinstance(hashes, list) or not 1 <= len(hashes) <= 128
                or any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in hashes)
                or len(set(hashes)) != len(hashes) or not isinstance(body, dict)
                or not isinstance(body.get('info'), dict) or body['info'].get('name') != 'PyYAML'
                or body['info'].get('version') != version or body['info'].get('requires_dist') not in (None, [])
                or not isinstance(body.get('urls'), list) or not 1 <= len(body['urls']) <= 128):
            raise PythonSourceError()
        selected, seen = [], set()
        for row in body['urls']:
            digest = row['digests']['sha256']
            if not isinstance(digest, str) or not SHA256.fullmatch(digest) or digest in seen:
                raise PythonSourceError()
            seen.add(digest)
            if digest not in hashes:
                continue
            name, kind, url = row['filename'], row['packagetype'], row['url']
            if (not isinstance(name, str) or len(name) > 256 or not isinstance(url, str) or len(url) > 1024
                    or not (kind == 'sdist' and name.lower() == 'pyyaml-' + version + '.tar.gz'
                            or kind == 'bdist_wheel' and re.fullmatch(r'(?i:pyyaml)-' + re.escape(version) + r'-[A-Za-z0-9_.-]+\.whl', name))
                    or row.get('yanked') is not False or type(row.get('size')) is not int
                    or not 0 < row['size'] <= MAX_ARCHIVE_BYTES):
                raise PythonSourceError()
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.netloc != 'files.pythonhosted.org'
                    or parsed.query or parsed.fragment or any(ord(c) <= 32 or ord(c) == 127 for c in url)
                    or not re.fullmatch(r'/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/' + re.escape(name), parsed.path)):
                raise PythonSourceError()
            published = row['upload_time_iso_8601']
            if not isinstance(published, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z', published):
                raise PythonSourceError()
            datetime.fromisoformat(published)
            selected.append({'filename': name, 'kind': kind, 'url': url, 'sha256': digest,
                             'size': row['size'], 'published_at': published})
        if {item['sha256'] for item in selected} != set(hashes):
            raise PythonSourceError()
        return sorted(selected, key=lambda item: item['filename'])
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise PythonSourceError() from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _file, _code, _message, _headers, _url):
        raise PythonSourceError()


def _open(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={'Accept-Encoding': 'identity',
                                                  'User-Agent': 'evydence-dependency-inventory/1'})
    return opener.open(request, timeout=20)


def download(url, limit):
    """Call only with the fixed PyPI API URL or a validated artifact URL."""
    try:
        deadline, content = time.monotonic() + 120, bytearray()
        with _open(url) as response:
            if (response.status != 200 or response.geturl() != url
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                raise PythonSourceError()
            declared = response.headers.get('Content-Length')
            if declared is not None and (not re.fullmatch(r'[0-9]{1,10}', declared) or not 0 < int(declared) <= limit):
                raise PythonSourceError()
            while True:
                if time.monotonic() > deadline:
                    raise PythonSourceError()
                chunk = response.read(min(65536, limit - len(content) + 1))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > limit:
                    raise PythonSourceError()
            if declared is not None and len(content) != int(declared):
                raise PythonSourceError()
        return bytes(content)
    except (OSError, ValueError, TypeError):
        raise PythonSourceError() from None


def _metadata(raw, version):
    message = Parser().parsestr(raw.decode('utf-8'))
    if (message.defects or message.get_all('Name') != ['PyYAML'] or message.get_all('Version') != [version]
            or message.get_all('Metadata-Version') not in [[value] for value in ('1.0', '1.1', '1.2', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6')]
            or message.get_all('Requires-Dist') or len(message.get_all('License', [])) > 1
            or len(message.get_all('License-Expression', [])) > 1
            or message.get('License') is not None and message.get('License-Expression') is not None):
        raise PythonSourceError()
    expression = message.get('License-Expression', message.get('License'))
    try:
        policy.license_allowed(expression, {'allowed_licenses': ['MIT'], 'allowed_with': []})
    except policy.PolicyError:
        expression = None
    if expression and expression.upper() in {'UNKNOWN', 'UNLICENSED', 'NOASSERTION', 'NONE'}:
        expression = None
    return {'metadata_sha256': hashlib.sha256(raw).hexdigest(), 'license': expression}


class _Expanded:
    def __init__(self, stream):
        self.stream, self.total = stream, 0
    def read(self, size):
        if not 0 <= size <= MAX_FILE_BYTES:
            raise PythonSourceError()
        content = self.stream.read(min(size, MAX_EXPANDED_BYTES - self.total + 1))
        self.total += len(content)
        if self.total > MAX_EXPANDED_BYTES:
            raise PythonSourceError()
        return content


def _parts(name):
    parts = [part for part in name.split('/') if part != '.']
    if (not parts or len(name) > 1024 or any(part in {'', '..'} for part in parts)
            or '\\' in name or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise PythonSourceError()
    return parts


def observe(raw, artifact, version):
    """Digest-first bounded ZIP/tar reads; no extract or package imports."""
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARCHIVE_BYTES
            or len(raw) != artifact['size'] or hashlib.sha256(raw).hexdigest() != artifact['sha256']):
        raise PythonSourceError()
    metadata, files, seen = None, [], set()

    def wanted(parts, kind):
        if kind == 'sdist':
            if parts[0].lower() != 'pyyaml-' + version:
                raise PythonSourceError()
            return len(parts) == 2 and (parts[1] == 'PKG-INFO' or LICENSE.fullmatch(parts[1]) or NOTICE.fullmatch(parts[1]))
        prefix = 'pyyaml-' + version + '.dist-info'
        return (parts[0].lower() == prefix and (len(parts) == 2 and (parts[1] == 'METADATA' or LICENSE.fullmatch(parts[1]) or NOTICE.fullmatch(parts[1]))
                or len(parts) == 3 and parts[1] == 'licenses' and (LICENSE.fullmatch(parts[2]) or NOTICE.fullmatch(parts[2]))))

    def store(parts, content):
        nonlocal metadata
        path, leaf = '/'.join(parts), parts[-1]
        if path in seen or len(seen) >= MAX_SELECTED_FILES or len(content) > MAX_FILE_BYTES:
            raise PythonSourceError()
        seen.add(path)
        if leaf in ('PKG-INFO', 'METADATA'):
            if metadata is not None:
                raise PythonSourceError()
            metadata = _metadata(content, version)
        else:
            files.append({'file': artifact['filename'] + ':' + path, 'kind': 'notice' if NOTICE.fullmatch(leaf) else 'license',
                          'sha256': hashlib.sha256(content).hexdigest(), 'content': content})
    try:
        if artifact['kind'] == 'sdist':
            with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
                stream = _Expanded(compressed)
                with tarfile.open(fileobj=stream, mode='r|') as archive:
                    for index, member in enumerate(archive):
                        parts = _parts(member.name)
                        if index >= MAX_MEMBERS or member.issparse() or not 0 <= member.size <= MAX_EXPANDED_BYTES:
                            raise PythonSourceError()
                        if not wanted(parts, 'sdist'):
                            continue
                        if not member.isreg() or member.size > MAX_FILE_BYTES:
                            raise PythonSourceError()
                        with archive.extractfile(member) as source:
                            content = source.read(MAX_FILE_BYTES + 1)
                        if len(content) != member.size:
                            raise PythonSourceError()
                        store(parts, content)
                while stream.read(65536):
                    pass
        elif artifact['kind'] == 'bdist_wheel':
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_MEMBERS or sum(item.file_size for item in entries) > MAX_EXPANDED_BYTES:
                    raise PythonSourceError()
                for entry in entries:
                    parts = _parts(entry.filename.rstrip('/') if entry.is_dir() else entry.filename)
                    if not wanted(parts, 'bdist_wheel'):
                        continue
                    mode = stat.S_IFMT(entry.external_attr >> 16)
                    if entry.is_dir() or mode not in (0, stat.S_IFREG) or entry.file_size > MAX_FILE_BYTES:
                        raise PythonSourceError()
                    with archive.open(entry) as source:
                        content = source.read(MAX_FILE_BYTES + 1)
                    if len(content) != entry.file_size:
                        raise PythonSourceError()
                    store(parts, content)
        else:
            raise PythonSourceError()
        if metadata is None:
            raise PythonSourceError()
        return metadata, sorted(files, key=lambda item: item['file'])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, RuntimeError,
            tarfile.TarError, zipfile.BadZipFile, zlib.error):
        raise PythonSourceError() from None


def fetch(requirements, work):
    try:
        version, hashes = parse_requirements(requirements)
        metadata_url = 'https://pypi.org/pypi/PyYAML/' + version + '/json'
        raw_metadata = download(metadata_url, 4 * 1024 * 1024)
        artifacts = select_artifacts(raw_metadata, version, hashes)
        observations, files, unique, license_bytes = [], [], {}, 0
        for index, artifact in enumerate(artifacts):
            raw = download(artifact['url'], MAX_ARCHIVE_BYTES)
            observation, selected = observe(raw, artifact, version)
            for file in selected:
                digest = file['sha256']
                if digest not in unique:
                    license_bytes += len(file['content'])
                    if license_bytes > MAX_LICENSE_SET_BYTES:
                        raise PythonSourceError()
                    unique[digest] = file['content']
                file['content'] = unique[digest]
            with (work / artifact['filename']).open('xb') as target:
                target.write(raw)
            observations.append(dict(artifact, **observation))
            files.extend(selected)
            if (index + 1) % 10 == 0 or index + 1 == len(artifacts):
                import sys
                print('dependency-inventory: verified ' + str(index + 1) + '/' + str(len(artifacts)) +
                      ' Python artifacts', file=sys.stderr, flush=True)
        with (work / 'registry.json').open('xb') as target:
            target.write(raw_metadata)
        licenses = {item['license'] for item in observations}
        expression = next(iter(licenses)) if len(licenses) == 1 and None not in licenses else None
        component = {'ecosystem': 'pypi', 'name': 'PyYAML', 'version': version, 'origins': ['qa'],
                     'license': expression, 'license_status': 'artifact-declared' if expression else 'ambiguous' if len(licenses) > 1 else 'unknown',
                     'license_evidence': [], 'version_published_at': min(item['published_at'] for item in observations),
                     'source': {'verification': 'sha256-verified', 'metadata_url': metadata_url,
                                'registry_metadata_sha256': hashlib.sha256(raw_metadata).hexdigest(), 'artifacts': observations}}
        return component, files
    except (OSError, ValueError, KeyError, TypeError):
        raise PythonSourceError() from None
