#!/usr/bin/env python3
"""Validate bounded OCI image or platform-index envelopes and layer digests."""
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
INDEX_MEDIA = 'application/vnd.oci.image.index.v1+json'
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
    """Preserve the v1 evidence profile: exactly one Linux amd64 manifest."""
    return _inspect(path, image, expected_digest, commit, None)


def inspect_index(path, image, expected_digest, commit, *, platforms):
    """Bind a wrapped OCI index to an explicit matrix, without claiming runtime support."""
    if (type(platforms) not in (tuple, list) or not 1 <= len(platforms) <= 2
            or any(type(value) is not str or value not in ('linux/amd64', 'linux/arm64') for value in platforms)
            or len(set(platforms)) != len(platforms)):
        raise invalid()
    return _inspect(path, image, expected_digest, commit, tuple(sorted(platforms)))


def index_platform(value):
    if (type(value) is not dict or not {'os', 'architecture'} <= set(value)
            or set(value) - {'os', 'architecture', 'variant'} or value['os'] != 'linux'
            or value['architecture'] not in ('amd64', 'arm64')
            or 'variant' in value and value['variant'] != {'amd64': 'v1', 'arm64': 'v8'}[value['architecture']]):
        raise invalid()
    return 'linux/' + value['architecture']


def _inspect(path, image, expected_digest, commit, platforms):
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
                root_name = descriptor(root_descriptor, MANIFEST_MEDIA if platforms is None else INDEX_MEDIA)
                if root_descriptor['digest'] != expected_digest:
                    raise invalid()
                if platforms is None:
                    descriptors = [root_descriptor]
                else:
                    image_index = record(root_name)
                    descriptors = image_index.get('manifests')
                    if (type(image_index.get('schemaVersion')) is not int or image_index['schemaVersion'] != 2
                            or image_index.get('mediaType') != INDEX_MEDIA
                            or type(descriptors) is not list or len(descriptors) != len(platforms)):
                        raise invalid()
                images, docker_images, observed_platforms, expanded_total = [], {}, set(), 0
                for image_descriptor in descriptors:
                    manifest_name = descriptor(image_descriptor, MANIFEST_MEDIA)
                    selected_platform = 'linux/amd64' if platforms is None else index_platform(image_descriptor.get('platform'))
                    if selected_platform in observed_platforms or platforms is not None and selected_platform not in platforms:
                        raise invalid()
                    observed_platforms.add(selected_platform)
                    manifest = record(manifest_name)
                    if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != MANIFEST_MEDIA:
                        raise invalid()
                    config_name = descriptor(manifest.get('config'), CONFIG_MEDIA)
                    config = record(config_name)
                    if platforms is None:
                        if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
                            raise invalid()
                    elif (index_platform({key: config[key] for key in ('os', 'architecture', 'variant') if key in config}) != selected_platform
                          or any(key in config for key in ('os.version', 'os.features', 'features'))):
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
                    layer_names = []
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
                    docker_images[config_name] = layer_names
                    images.append({'name': image, 'kind': 'container', 'sha256': image_descriptor['digest'][7:],
                                   'bytes': members[manifest_name].size, 'platform': selected_platform,
                                   'source_commit': commit})
                if 'manifest.json' in members:
                    # Docker's compatibility index must identify exactly the verified configs/layers.
                    def no_constant(_value):
                        raise invalid()
                    compatibility = json.loads(raw('manifest.json'), object_pairs_hook=profile.unique_object,
                                               parse_constant=no_constant)
                    if type(compatibility) is not list or len(compatibility) != len(docker_images):
                        raise invalid()
                    seen_configs = set()
                    for entry in compatibility:
                        if (type(entry) is not dict or type(entry.get('Config')) is not str
                                or entry['Config'] not in docker_images or entry['Config'] in seen_configs
                                or entry.get('Layers') != docker_images[entry['Config']]
                                or entry.get('RepoTags', []) not in ([], [image])):
                            raise invalid()
                        seen_configs.add(entry['Config'])
                    referenced.add('manifest.json')
                if set(members) != referenced:
                    raise invalid()
                if platforms is None:
                    return images[0]
                if observed_platforms != set(platforms):
                    raise invalid()
                return {'name': image, 'kind': 'container-index', 'sha256': expected_digest[7:],
                        'bytes': members[root_name].size, 'source_commit': commit,
                        'images': sorted(images, key=lambda item: item['platform'])}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, RecursionError, tarfile.TarError, zlib.error):
        raise invalid() from None
