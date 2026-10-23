#!/usr/bin/env python3
"""Resolve public image manifests anonymously, with bounded metadata and exact digests."""
import hashlib
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit

import dependency_policy as policy

OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
OCI_LAYER = 'application/vnd.oci.image.layer.v1.tar'
DOCKER_INDEX = 'application/vnd.docker.distribution.manifest.list.v2+json'
DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'
INDEXES = {OCI_INDEX, DOCKER_INDEX}
MANIFESTS = {OCI_MANIFEST, DOCKER_MANIFEST}
LAYERS = {OCI_LAYER, OCI_LAYER + '+gzip', OCI_LAYER + '+zstd',
          'application/vnd.docker.image.rootfs.diff.tar', 'application/vnd.docker.image.rootfs.diff.tar.gzip'}
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
MAX_LAYERS = 128
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


class ImageRegistryError(ValueError):
    def __init__(self, status=None):
        self.status = status if type(status) is int and 100 <= status <= 599 else None
        super().__init__('invalid or unavailable bounded image registry metadata')


def require(value):
    if not value:
        raise ImageRegistryError()


def reference(value):
    try:
        require(isinstance(value, str) and 0 < len(value) <= 512
                and all(32 < ord(char) < 127 for char in value))
        value = value.removeprefix('docker://')
        require(value.count('@') <= 1)
        name, separator, digest = value.partition('@')
        require(not separator or DIGEST.fullmatch(digest))
        tag = None
        if ':' in name.rsplit('/', 1)[-1]:
            name, tag = name.rsplit(':', 1)
            require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag))
        require(tag is not None or separator)
        parts = name.split('/')
        if parts[0] in {'docker.io', 'index.docker.io', 'registry-1.docker.io', 'ghcr.io'}:
            registry, parts = ('ghcr.io' if parts[0] == 'ghcr.io' else 'docker.io'), parts[1:]
        else:
            require('.' not in parts[0] and ':' not in parts[0]); registry = 'docker.io'
        require(1 <= len(parts) <= 8 and all(part not in {'.', '..'} and re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', part) for part in parts))
        if registry == 'docker.io' and len(parts) == 1: parts.insert(0, 'library')
        require(len(parts) >= 2)
        repo = '/'.join(parts); require(len(repo) <= 255)
        return {'name': registry + '/' + repo, 'registry': registry, 'repository': repo,
                'tag': tag, 'digest': digest if separator else None}
    except (ValueError, TypeError, AttributeError):
        raise ImageRegistryError() from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        raise ImageRegistryError()


def read(url, *, bearer=None):
    try:
        require(isinstance(url, str) and len(url) <= 2048 and all(32 < ord(char) < 127 for char in url))
        parsed = urlsplit(url)
        require(parsed.scheme == 'https' and parsed.netloc in {'auth.docker.io', 'registry-1.docker.io', 'ghcr.io'} and not parsed.fragment)
        require(parsed.path == '/token' or parsed.path.startswith('/v2/'))
        require(bearer is None or parsed.path.startswith('/v2/'))
        headers = {'Accept': ', '.join(sorted(INDEXES | MANIFESTS)), 'Accept-Encoding': 'identity',
                   'User-Agent': 'evydence-image-inventory/1'}
        if bearer is not None:
            require(isinstance(bearer, str) and 0 < len(bearer) <= 32768 and re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', bearer))
            headers['Authorization'] = 'Bearer ' + bearer
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(url, headers=headers, method='GET')
        deadline, content = time.monotonic() + 120, bytearray()
        with opener.open(request, timeout=20) as response:
            require(response.status == 200 and response.geturl() == url
                    and response.headers.get('Content-Encoding', 'identity') == 'identity')
            declared = response.headers.get('Content-Length')
            require(declared is None or isinstance(declared, str) and re.fullmatch(r'[0-9]{1,10}', declared)
                    and 0 < int(declared) <= MAX_JSON_BYTES)
            while True:
                require(time.monotonic() <= deadline)
                chunk = response.read(min(65536, MAX_JSON_BYTES - len(content) + 1))
                if not chunk: break
                content.extend(chunk); require(len(content) <= MAX_JSON_BYTES)
            require(declared is None or len(content) == int(declared))
            return bytes(content), {name: response.headers.get(name) for name in ('Docker-Content-Digest', 'Content-Type')}
    except urllib.error.HTTPError as error:
        raise ImageRegistryError(error.code) from None
    except (OSError, ValueError, TypeError, urllib.error.URLError):
        raise ImageRegistryError() from None


def token(row):
    try:
        require(reference(row['name'] + (':' + row['tag'] if row['tag'] else '') + ('@' + row['digest'] if row['digest'] else '')) == row)
        host, service = ('auth.docker.io', 'registry.docker.io') if row['registry'] == 'docker.io' else ('ghcr.io', 'ghcr.io')
        query = urlencode({'service': service, 'scope': 'repository:' + row['repository'] + ':pull'})
        raw, _headers = read('https://' + host + '/token?' + query)
        data = document(raw); result = data.get('token', data.get('access_token'))
        require(isinstance(result, str) and 0 < len(result) <= 32768 and re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', result))
        require('token' not in data or 'access_token' not in data or data['token'] == data['access_token'])
        return result
    except ImageRegistryError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ImageRegistryError() from None


def document(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_JSON_BYTES)
    value = policy.parse_document(raw); require(isinstance(value, dict))
    return value


def descriptor(value, media, maximum):
    require(isinstance(value, dict) and value.get('mediaType') in media
            and isinstance(value.get('digest'), str) and DIGEST.fullmatch(value['digest'])
            and type(value.get('size')) is int and 0 < value['size'] <= maximum
            and value.get('urls') in (None, []) and value.get('data') in (None, ''))
    return {name: value[name] for name in ('mediaType', 'digest', 'size')}


def resolve(row):
    try:
        require(reference(row['name'] + (':' + row['tag'] if row['tag'] else '') + ('@' + row['digest'] if row['digest'] else '')) == row)
        bearer = token(row)
        host = 'registry-1.docker.io' if row['registry'] == 'docker.io' else 'ghcr.io'
        prefix = 'https://' + host + '/v2/' + row['repository'] + '/manifests/'
        def get(revision, expected_size=None):
            raw, headers = read(prefix + revision, bearer=bearer)
            actual = 'sha256:' + hashlib.sha256(raw).hexdigest()
            require(not revision.startswith('sha256:') or actual == revision)
            require(expected_size is None or len(raw) == expected_size)
            require(headers.get('Docker-Content-Digest') in (None, actual))
            data = document(raw)
            require(type(data.get('schemaVersion')) is int and data['schemaVersion'] == 2)
            media = data.get('mediaType'); require(media in INDEXES | MANIFESTS)
            content_type = headers.get('Content-Type')
            require(content_type is None or content_type.split(';')[0].strip() == media)
            return data, {'mediaType': media, 'digest': actual, 'size': len(raw)}
        root, root_descriptor = get(row['digest'] or row['tag'])
        selection = 'not-observed'
        if root_descriptor['mediaType'] in INDEXES:
            entries = root.get('manifests'); require(isinstance(entries, list) and 0 < len(entries) <= 256)
            matching = []
            for entry in entries:
                require(isinstance(entry, dict))
                platform = entry.get('platform')
                if isinstance(platform, dict) and platform.get('os') == 'linux' and platform.get('architecture') == 'amd64' and platform.get('variant') in (None, ''):
                    matching.append(descriptor(entry, MANIFESTS, MAX_JSON_BYTES))
            require(len(matching) == 1)
            expected = matching[0]; manifest, selected = get(expected['digest'], expected['size'])
            require(selected == expected); selection = 'index-assertion'
        else:
            manifest, selected = root, root_descriptor
        config = descriptor(manifest.get('config'), {OCI_CONFIG, DOCKER_CONFIG}, MAX_JSON_BYTES)
        raw_layers = manifest.get('layers'); require(isinstance(raw_layers, list) and 0 < len(raw_layers) <= MAX_LAYERS)
        layers = [descriptor(layer, LAYERS, MAX_IMAGE_BYTES) for layer in raw_layers]
        require(sum(layer['size'] for layer in layers) <= MAX_IMAGE_BYTES)
        return {'verification': 'manifest-digests', 'root_digest': root_descriptor['digest'],
                'root': root_descriptor, 'manifest_digest': selected['digest'], 'manifest': selected,
                'config': config, 'layers': layers, 'requested_platform': 'linux/amd64',
                'platform_evidence': selection, 'mutable_reference': row['digest'] is None}
    except ImageRegistryError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ImageRegistryError() from None
