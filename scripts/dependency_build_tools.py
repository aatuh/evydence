#!/usr/bin/env python3
"""Observe pinned build-tool archives without extracting or executing binaries."""
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import zlib

import support_matrix

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_MEMBERS = 2048
MAX_SELECTED_FILES = 32
LICENSE_NAME = re.compile(r'(?:licen[sc]e|copying|copyright|unlicense)(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
NOTICE_NAME = re.compile(r'notice(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
RELEASE_URL = re.compile(r'https://github\.com/oasdiff/oasdiff/releases/download/v([0-9]+\.[0-9]+\.[0-9]+)/oasdiff_\1_linux_amd64\.tar\.gz\Z')


class BuildToolError(ValueError):
    def __init__(self):
        super().__init__('invalid or unavailable bounded build-tool archive')


def _url(name, version):
    if name == 'helm' and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        return 'https://get.helm.sh/helm-' + version + '-linux-amd64.tar.gz'
    if name == 'oasdiff' and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        return 'https://github.com/oasdiff/oasdiff/releases/download/v' + version + '/oasdiff_' + version + '_linux_amd64.tar.gz'
    raise BuildToolError()


def archive_tools(raw_policy):
    try:
        policy = support_matrix.parse_policy(raw_policy)
        return [{'ecosystem': 'generic', 'name': name, 'version': policy['tools'][name]['version'],
                 'origins': ['qa-tool'], 'license': None, 'license_status': 'unobserved',
                 'license_evidence': [], 'version_published_at': None,
                 'source': {'url': _url(name, policy['tools'][name]['version']),
                            'sha256': policy['tools'][name]['linux_amd64_sha256'],
                            'platform': 'linux/amd64'}} for name in support_matrix.ARCHIVE_TOOLS]
    except (ValueError, KeyError, TypeError):
        raise BuildToolError() from None


def _source(row):
    try:
        source = row['source']
        if (row['ecosystem'] != 'generic' or source['url'] != _url(row['name'], row['version'])
                or source['platform'] != 'linux/amd64' or not isinstance(source['sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', source['sha256'])):
            raise BuildToolError()
        return source['url'], source['sha256']
    except (ValueError, TypeError, KeyError):
        raise BuildToolError() from None


class _Expanded:
    def __init__(self, stream):
        self.stream, self.total = stream, 0

    def read(self, size):
        if size < 0 or size > 1024 * 1024:
            raise BuildToolError()
        value = self.stream.read(min(size, MAX_EXPANDED_BYTES - self.total + 1))
        self.total += len(value)
        if self.total > MAX_EXPANDED_BYTES:
            raise BuildToolError()
        return value


def observe(raw, row):
    """Check compressed integrity before any bounded tar/gzip interpretation."""
    _source_url, digest = _source(row)
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARCHIVE_BYTES
            or hashlib.sha256(raw).hexdigest() != digest):
        raise BuildToolError()
    wrapper = 'linux-amd64' if row['name'] == 'helm' else None
    binary_path = (wrapper + '/' if wrapper else '') + row['name']
    files, seen, binary = [], set(), None
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
            stream = _Expanded(compressed)
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for index, member in enumerate(archive):
                    name = member.name.rstrip('/') if member.isdir() else member.name
                    parts = [part for part in name.split('/') if part != '.']
                    if (index >= MAX_MEMBERS or len(name) > 1024 or not parts
                            or any(part in {'', '..'} for part in parts) or '\\' in name
                            or any(ord(char) < 32 or ord(char) == 127 for char in name)
                            or member.issparse() or not 0 <= member.size <= MAX_EXPANDED_BYTES
                            or wrapper and (parts[0] != wrapper or len(parts) == 1 and not member.isdir())):
                        raise BuildToolError()
                    normalized = '/'.join(parts)
                    if normalized in seen:
                        raise BuildToolError()
                    seen.add(normalized)
                    leaf = parts[-1]
                    notice = len(parts) == (2 if wrapper else 1) and (
                        LICENSE_NAME.fullmatch(leaf) or NOTICE_NAME.fullmatch(leaf))
                    is_binary = normalized == binary_path
                    if not notice and not is_binary:
                        continue
                    if (not member.isreg() or not member.size or
                            notice and (member.size > MAX_FILE_BYTES or len(files) >= MAX_SELECTED_FILES)):
                        raise BuildToolError()
                    source = archive.extractfile(member)
                    if source is None:
                        raise BuildToolError()
                    sha, count, content = hashlib.sha256(), 0, bytearray()
                    with source:
                        while chunk := source.read(65536):
                            count += len(chunk)
                            if count > member.size:
                                raise BuildToolError()
                            sha.update(chunk)
                            if notice:
                                content.extend(chunk)
                    if count != member.size:
                        raise BuildToolError()
                    if is_binary:
                        binary = sha.hexdigest()
                    else:
                        files.append({'file': leaf, 'kind': 'notice' if NOTICE_NAME.fullmatch(leaf) else 'license',
                                      'sha256': sha.hexdigest(), 'content': bytes(content)})
            # Check the gzip trailer/CRC even when tar has reached its end marker.
            while stream.read(65536):
                pass
        if binary is None:
            raise BuildToolError()
        return {'verification': 'sha256-verified', 'binary_sha256': binary}, sorted(files, key=lambda file: file['file'])
    except (OSError, ValueError, TypeError, KeyError, EOFError, tarfile.TarError, zlib.error):
        raise BuildToolError() from None


def _release_asset(url):
    if not isinstance(url, str) or len(url) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in url):
        return False
    parsed = urlsplit(url)
    return (parsed.scheme == 'https' and parsed.netloc == 'release-assets.githubusercontent.com'
            and not parsed.fragment and parsed.path.startswith('/'))


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    # GitHub's public release endpoint has one signed CDN redirect. Never pass
    # operator credentials or accept arbitrary hosts, schemes, ports or chains.
    max_redirections = 1

    def redirect_request(self, request, file, code, message, headers, url):
        if not RELEASE_URL.fullmatch(request.full_url) or not _release_asset(url):
            raise BuildToolError()
        return super().redirect_request(request, file, code, message, headers, url)


def _open(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _ReleaseRedirect())
    request = urllib.request.Request(url, headers={'Accept-Encoding': 'identity',
                                                  'User-Agent': 'evydence-dependency-inventory/1'})
    return opener.open(request, timeout=20)


def fetch(row, work):
    try:
        url, digest = _source(row)
        deadline, content = time.monotonic() + 180, bytearray()
        with _open(url) as response:
            final = response.geturl()
            if (response.status != 200 or final != url and not (RELEASE_URL.fullmatch(url) and _release_asset(final))
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                raise BuildToolError()
            declared = response.headers.get('Content-Length')
            if declared is not None and (not re.fullmatch(r'[0-9]{1,10}', declared) or not 0 < int(declared) <= MAX_ARCHIVE_BYTES):
                raise BuildToolError()
            while True:
                if time.monotonic() > deadline:
                    raise BuildToolError()
                chunk = response.read(min(65536, MAX_ARCHIVE_BYTES - len(content) + 1))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > MAX_ARCHIVE_BYTES:
                    raise BuildToolError()
            if declared is not None and len(content) != int(declared):
                raise BuildToolError()
        raw = bytes(content)
        observation, files = observe(raw, row)
        # Only the collector's fresh mode-0700 scratch directory is passed here.
        with (Path(work) / (digest + '.tar.gz')).open('xb') as target:
            target.write(raw)
        return observation, files
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        raise BuildToolError() from None
