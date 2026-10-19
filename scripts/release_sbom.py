#!/usr/bin/env python3
"""A narrow CycloneDX profile for public release subjects and package coordinates."""
from __future__ import annotations

import re
from urllib.parse import unquote
import uuid


SYFT_VERSION = '1.54.1'
MAX_COMPONENTS = 4096
COORDINATE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._~+/-]*')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~-]*|\(devel\)')
PURL = re.compile(r'pkg:golang/[A-Za-z0-9][A-Za-z0-9._~+/%-]*(?:@[A-Za-z0-9()][A-Za-z0-9._~+%()-]*)?')
LIMITATIONS = (
    'Package inventory comes from pinned Syft catalogers; omitted symbols, dynamic downloads, '
    'vendored or unrecognized code, licenses, and package relationships may be incomplete. '
    'Exported package coordinates exclude scanner paths and ambient configuration. '
    'This is not a complete SBOM proof, authoritative vulnerability result, or secure-release guarantee.'
)


def invalid():
    return ValueError('invalid release SBOM data')


def public_components(scanner_bom):
    """Export a deliberately flat inventory, never arbitrary scanner metadata."""
    if (type(scanner_bom) is not dict or scanner_bom.get('bomFormat') != 'CycloneDX'
            or scanner_bom.get('specVersion') != '1.6'):
        raise invalid()
    components = scanner_bom.get('components')
    if type(components) is not list or not 0 < len(components) <= MAX_COMPONENTS:
        raise invalid()
    result, seen = [], {}
    for component in components:
        # Syft includes source file records containing local paths. This public
        # package inventory intentionally omits those records and their metadata.
        if type(component) is dict and component.get('type') == 'file':
            continue
        if type(component) is not dict or component.get('type') not in ('library', 'application'):
            raise invalid()
        clean = {'type': component['type']}
        for field, pattern in [('name', COORDINATE), ('version', VERSION), ('purl', PURL)]:
            value = component.get(field)
            if (type(value) is not str or not 1 <= len(value) <= 2048
                    or pattern.fullmatch(value) is None or any(part in ('.', '..') for part in value.split('/'))):
                raise invalid()
            clean[field] = value
        identity = clean['purl']
        expected = 'pkg:golang/' + clean['name']
        if clean['version'] != 'UNKNOWN':
            version = clean['version']
            if clean['name'] == 'stdlib' and re.fullmatch(r'go1\.[0-9]+\.[0-9]+', version):
                version = version.removeprefix('go')
            expected += '@' + version
        if unquote(identity, errors='strict') != expected:
            raise invalid()
        if identity in seen:
            if clean != seen[identity]:
                raise invalid()
            continue
        seen[identity] = clean
        result.append(clean)
    if not result:
        raise invalid()
    return sorted(result, key=lambda item: item['purl'])


def bound_bom(subject, components):
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                  subject['name'] + ':sha256:' + subject['sha256'])),
        'metadata': {
            'component': {'type': 'file', 'name': subject['name'],
                          'hashes': [{'alg': 'SHA-256', 'content': subject['sha256']}]},
            'tools': {'components': [{'type': 'application', 'name': 'syft', 'version': SYFT_VERSION,
                                     'purl': 'pkg:golang/github.com/anchore/syft@v' + SYFT_VERSION}]},
            'properties': [{'name': 'evydence:coverage-limitations', 'value': LIMITATIONS}],
        },
        'components': components,
    }


def verify_bom(bom, subject):
    try:
        components = public_components(bom)
        expected = bound_bom(subject, components)
        if bom != expected:
            raise invalid()
    except (KeyError, TypeError, ValueError, RecursionError):
        raise invalid() from None
