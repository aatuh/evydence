#!/usr/bin/env python3
"""Observe SHA-512-pinned npm source archives without installing package code."""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import re
import tarfile
import time
import urllib.error
import urllib.request
import zlib
from urllib.parse import unquote, urlsplit

import dependency_policy as policy

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_MEMBERS = 65536
MAX_SELECTED_FILES = 32
LICENSE_NAME = re.compile(r'(?:licen[sc]e|copying|copyright|unlicense)(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
NOTICE_NAME = re.compile(r'notice(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)


class NodeSourceError(ValueError):
    """Errors never include archive paths, raw provider data or credentials."""


def _source(row):
    try:
        ecosystem, name, version = policy._coordinates(row)
        url, integrity = row['source']['url'], row['source']['integrity']
        if (ecosystem != 'npm' or not isinstance(url, str) or len(url) > 1024
                or not isinstance(integrity, str) or not integrity.startswith('sha512-')
                or len(integrity) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in url)):
            raise ValueError
        parsed = urlsplit(url)
        expected = '/' + name + '/-/' + name.rsplit('/', 1)[-1] + '-' + version + '.tgz'
        if (parsed.scheme != 'https' or parsed.netloc != 'registry.npmjs.org'
                or parsed.query or parsed.fragment or unquote(parsed.path, errors='strict') != expected):
            raise ValueError
        digest = base64.b64decode(integrity[7:], validate=True)
        if len(digest) != 64 or integrity != 'sha512-' + base64.b64encode(digest).decode():
            raise ValueError
        return url, digest
    except (ValueError, KeyError, TypeError, AttributeError, binascii.Error):
        raise NodeSourceError('invalid npm archive coordinates or integrity') from None


class _Expanded:
    """Bound tar payloads and oversized metadata before tarfile allocates them."""
    def __init__(self, stream):
        self.stream, self.total = stream, 0

    def read(self, size):
        if size < 0 or size > MAX_FILE_BYTES:
            raise NodeSourceError('npm archive metadata exceeds its byte budget')
        value = self.stream.read(min(size, MAX_EXPANDED_BYTES - self.total + 1))
        self.total += len(value)
        if self.total > MAX_EXPANDED_BYTES:
            raise NodeSourceError('npm archive exceeds its expanded byte budget')
        return value


def observe(raw, row):
    """Verify the compressed bytes before inspecting a bounded, unextracted tar."""
    _url, digest = _source(row)
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARCHIVE_BYTES
            or hashlib.sha512(raw).digest() != digest):
        raise NodeSourceError('npm archive integrity verification failed')
    files, manifest, manifest_digest, seen, selected, wrapper = [], None, None, set(), 0, None
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
            stream = _Expanded(compressed)
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for index, member in enumerate(archive):
                    name = member.name
                    parts = [part for part in name.split('/') if part != '.']
                    if (index >= MAX_MEMBERS or len(name) > 1024
                            or not parts or any(p in {'', '..'} for p in parts)
                            or any(ord(c) < 32 or ord(c) == 127 for c in name)
                            or '\\' in name or member.issparse()
                            or not 0 <= member.size <= MAX_EXPANDED_BYTES):
                        raise NodeSourceError('invalid or excessive npm archive entries')
                    if wrapper is None:
                        wrapper = parts[0]
                    if parts[0] != wrapper or len(parts) == 1 and not member.isdir():
                        raise NodeSourceError('npm archive must use one package wrapper')
                    leaf = parts[-1]
                    wanted = len(parts) == 2 and (leaf == 'package.json' or LICENSE_NAME.fullmatch(leaf)
                                                  or NOTICE_NAME.fullmatch(leaf))
                    if not wanted:
                        continue
                    normalized = '/'.join(parts)
                    if normalized in seen:
                        raise NodeSourceError('duplicate npm manifest or license file')
                    seen.add(normalized)
                    selected += 1
                    if not member.isreg() or member.size > MAX_FILE_BYTES or selected > MAX_SELECTED_FILES:
                        raise NodeSourceError('invalid or excessive npm manifest or license file')
                    source = archive.extractfile(member)
                    if source is None:
                        raise NodeSourceError('missing npm archive member bytes')
                    with source:
                        content = source.read(MAX_FILE_BYTES + 1)
                    if len(content) != member.size:
                        raise NodeSourceError('incomplete npm archive member bytes')
                    sha = hashlib.sha256(content).hexdigest()
                    if leaf == 'package.json':
                        manifest = policy.parse_document(content)
                        manifest_digest = sha
                    else:
                        files.append({'file': leaf, 'kind': 'notice' if NOTICE_NAME.fullmatch(leaf) else 'license',
                                      'sha256': sha, 'content': content})
            # Drain through the gzip trailer: tar's end marker alone does not check CRC/truncation.
            while stream.read(65536):
                pass
        if (not isinstance(manifest, dict) or manifest.get('name') != row['name']
                or manifest.get('version') != row['version']):
            raise NodeSourceError('npm archive manifest identity differs from its lock')
        expression = manifest.get('license')
        status = 'missing' if expression is None else 'matched' if expression == row.get('license') else 'different'
        try:
            policy.license_allowed(expression, {'allowed_licenses': ['MIT'], 'allowed_with': []})
        except policy.PolicyError:
            expression, status = None, 'unsupported'
        return ({'verification': 'sha512-verified', 'package_json_sha256': manifest_digest,
                 'license': expression, 'declaration_status': status}, sorted(files, key=lambda item: item['file']))
    except (OSError, ValueError, TypeError, KeyError, EOFError, tarfile.TarError, RecursionError, zlib.error):
        raise NodeSourceError('cannot observe a valid bounded npm archive') from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _file, _code, _message, _headers, _url):
        raise NodeSourceError('npm archive redirects are not allowed')


def _open(url):
    # No environment proxy/netrc credentials, cookies or redirect destination.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={'Accept-Encoding': 'identity',
                                                  'User-Agent': 'evydence-dependency-inventory/1'})
    return opener.open(request, timeout=20)


def fetch(row, work):
    """Fetch one exact registry object; retain verified bytes in owned private work."""
    url, digest = _source(row)
    try:
        deadline, content = time.monotonic() + 180, bytearray()
        with _open(url) as response:
            if (response.status != 200 or response.geturl() != url
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                raise NodeSourceError('unexpected npm archive HTTP response')
            declared = response.headers.get('Content-Length')
            if declared is not None and (not re.fullmatch(r'[0-9]{1,10}', declared)
                                         or not 0 < int(declared) <= MAX_ARCHIVE_BYTES):
                raise NodeSourceError('invalid npm archive response length')
            while True:
                if time.monotonic() > deadline:
                    raise NodeSourceError('npm archive transfer exceeded its time budget')
                chunk = response.read(min(65536, MAX_ARCHIVE_BYTES - len(content) + 1))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > MAX_ARCHIVE_BYTES:
                    raise NodeSourceError('npm archive transfer exceeds its byte budget')
            if declared is not None and len(content) != int(declared):
                raise NodeSourceError('incomplete npm archive transfer')
        raw = bytes(content)
        observation, files = observe(raw, row)
        # work is a newly created mode-0700 collector directory, never a supplied cache.
        with (work / (digest.hex() + '.tgz')).open('xb') as output:
            output.write(raw)
        return observation, files
    except (OSError, ValueError, TypeError, urllib.error.URLError):
        raise NodeSourceError('cannot fetch verified npm archive bytes') from None
