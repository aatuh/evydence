#!/usr/bin/env python3
"""Validate one supported OCI image's content-addressed envelope and layer digests."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import re
import tarfile
import zlib

import release_artifacts
import release_evidence_profile as profile


MANIFEST_MEDIA = 'application/vnd.oci.image.manifest.v1+json'
CONFIG_MEDIA = 'application/vnd.oci.image.config.v1+json'
LAYER_MEDIA = 'application/vnd.oci.image.layer.v1.tar'
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_LAYER_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_TOTAL_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 256


def invalid():
    return ValueError('invalid release OCI payload')


def content_digest(stream, maximum):
    result, count = hashlib.sha256(), 0
    while chunk := stream.read(1024 * 1024):
        count += len(chunk)
        if count > maximum:
            raise invalid()
        result.update(chunk)
    return result.hexdigest(), count


def inspect(path, image, expected_digest, commit):
    try:
        if (type(image) is not str or len(image) > 300
                or re.fullmatch(r'ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', image) is None
                or type(expected_digest) is not str or not re.fullmatch(r'sha256:[a-f0-9]{64}', expected_digest)
                or type(commit) is not str or not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', commit)):
            raise invalid()
        source_repository, tag = image.removeprefix('ghcr.io/').rsplit(':', 1)
        stream, size = release_artifacts.regular_file(Path(path))
        with stream:
            if size > MAX_ARCHIVE_BYTES:
                raise invalid()
            with tarfile.open(fileobj=stream, mode='r:') as archive:
                members, seen, total = {}, set(), 0
                for member in archive:
                    name = member.name
                    if name in seen or len(seen) >= MAX_MEMBERS:
                        raise invalid()
                    seen.add(name)
                    if member.isdir() and name.rstrip('/') in ('blobs', 'blobs/sha256'):
                        continue
                    if (not member.isfile() or member.issparse() or not 0 <= member.size <= MAX_ARCHIVE_BYTES
                            or name not in ('oci-layout', 'index.json', 'manifest.json')
                            and re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', name) is None):
                        raise invalid()
                    total += member.size
                    if total > MAX_ARCHIVE_BYTES:
                        raise invalid()
                    with archive.extractfile(member) as payload:
                        sha, actual_size = content_digest(payload, member.size)
                    if actual_size != member.size or name.startswith('blobs/') and sha != name.rsplit('/', 1)[1]:
                        raise invalid()
                    members[name] = member

                def raw(name):
                    member = members[name]
                    if member.size > profile.MAX_JSON_BYTES:
                        raise invalid()
                    with archive.extractfile(member) as payload:
                        value = payload.read(profile.MAX_JSON_BYTES + 1)
                    if len(value) != member.size:
                        raise invalid()
                    return value

                def record(name):
                    return profile.parse_json(raw(name))

                referenced = {'oci-layout', 'index.json'}
                def descriptor(value, media):
                    if (type(value) is not dict or value.get('mediaType') != media
                            or type(value.get('digest')) is not str
                            or re.fullmatch(r'sha256:[a-f0-9]{64}', value['digest']) is None
                            or type(value.get('size')) is not int or value['size'] <= 0):
                        raise invalid()
                    name = 'blobs/sha256/' + value['digest'][7:]
                    if name not in members or members[name].size != value['size']:
                        raise invalid()
                    referenced.add(name)
                    return name

                if record('oci-layout') != {'imageLayoutVersion': '1.0.0'}:
                    raise invalid()
                index = record('index.json')
                if (index.get('schemaVersion') != 2 or type(index.get('manifests')) is not list
                        or len(index['manifests']) != 1):
                    raise invalid()
                root_descriptor = index['manifests'][0]
                manifest_name = descriptor(root_descriptor, MANIFEST_MEDIA)
                if root_descriptor['digest'] != expected_digest:
                    raise invalid()
                manifest = record(manifest_name)
                if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != MANIFEST_MEDIA:
                    raise invalid()
                config_name = descriptor(manifest.get('config'), CONFIG_MEDIA)
                config = record(config_name)
                if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
                    raise invalid()
                labels = config.get('config', {}).get('Labels', {})
                if (type(labels) is not dict or labels.get('org.opencontainers.image.revision') != commit
                        or labels.get('org.opencontainers.image.version') != tag
                        or labels.get('org.opencontainers.image.source') != 'https://github.com/' + source_repository):
                    raise invalid()
                layers = manifest.get('layers')
                rootfs = config.get('rootfs')
                if (type(layers) is not list or not 0 < len(layers) <= 128
                        or type(rootfs) is not dict or rootfs.get('type') != 'layers'
                        or type(rootfs.get('diff_ids')) is not list or len(rootfs['diff_ids']) != len(layers)):
                    raise invalid()
                layer_names, expanded_total = [], 0
                for layer, diff_id in zip(layers, rootfs['diff_ids']):
                    media = layer.get('mediaType') if type(layer) is dict else None
                    if media not in (LAYER_MEDIA, LAYER_MEDIA + '+gzip'):
                        raise invalid()
                    name = descriptor(layer, media)
                    layer_names.append(name)
                    with archive.extractfile(members[name]) as payload:
                        if media.endswith('+gzip'):
                            with gzip.GzipFile(fileobj=payload) as expanded:
                                sha, length = content_digest(expanded, MAX_LAYER_EXPANDED_BYTES)
                        else:
                            sha, length = content_digest(payload, MAX_LAYER_EXPANDED_BYTES)
                    expanded_total += length
                    if diff_id != 'sha256:' + sha or expanded_total > MAX_TOTAL_EXPANDED_BYTES:
                        raise invalid()
                if 'manifest.json' in members:
                    # Some OCI exporters also emit Docker's compatibility index.
                    # It must identify the very same config/layers, never a second image.
                    def no_constant(_value):
                        raise invalid()
                    compatibility = json.loads(raw('manifest.json'), object_pairs_hook=profile.unique_object,
                                               parse_constant=no_constant)
                    if (type(compatibility) is not list or len(compatibility) != 1
                            or type(compatibility[0]) is not dict or compatibility[0].get('Config') != config_name
                            or compatibility[0].get('Layers') != layer_names
                            or compatibility[0].get('RepoTags', []) not in ([], [image])):
                        raise invalid()
                    referenced.add('manifest.json')
                if set(members) != referenced:
                    raise invalid()
                return {'name': image, 'kind': 'container', 'sha256': expected_digest[7:],
                        'bytes': members[manifest_name].size, 'platform': 'linux/amd64',
                        'source_commit': commit}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, RecursionError, tarfile.TarError, zlib.error):
        raise invalid() from None
