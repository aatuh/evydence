#!/usr/bin/env python3
"""Bind closed standalone Go source pins to the existing installation recipes."""
import base64
import binascii
import re

import yaml

import dependency_policy as policy
from support_matrix_artifacts import UniqueLoader

CATALOG = 'release/tools/standalone-go.json'
WORKFLOW = '.github/workflows/container-image.yml'
DOCKERFILE = 'deploy/local-dependencies/Dockerfile'
INPUTS = (CATALOG, WORKFLOW, DOCKERFILE)
SCOPES = frozenset({'tool-cosign', 'fixture-minio', 'fixture-mc'})


class ToolSourceError(ValueError):
    def __init__(self):
        super().__init__('invalid standalone Go source pins or installation bindings')


def require(condition):
    if not condition:
        raise ToolSourceError()


def checksum(value):
    require(isinstance(value, str) and value.startswith('h1:') and len(value) == 47)
    raw = base64.b64decode(value[3:], validate=True)
    require(len(raw) == 32 and 'h1:' + base64.b64encode(raw).decode() == value)


def profiles(inputs):
    try:
        raw = inputs[CATALOG]
        require(isinstance(raw, bytes) and 0 < len(raw) <= 65536)
        document = policy.parse_document(raw)
        require(isinstance(document, dict) and set(document) == {'schema', 'tools'}
                and document['schema'] == 'evydence-standalone-go-tools.v1')
        tools = document['tools']; require(isinstance(tools, list) and len(tools) == 3)
        result, seen = [], set()
        for row in tools:
            require(isinstance(row, dict) and set(row) == {'id', 'module', 'package', 'version', 'sum', 'go_mod_sum', 'commit'})
            identity = row['id']; require(identity in {'cosign', 'minio', 'mc'} and identity not in seen)
            seen.add(identity)
            policy._coordinates({'ecosystem': 'gomod', 'name': row['module'], 'version': row['version']})
            require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9]{14}-[0-9a-f]{12})?', row['version']))
            require(isinstance(row['package'], str) and (row['package'] == row['module'] or row['package'].startswith(row['module'] + '/'))
                    and re.fullmatch(r'[A-Za-z0-9._/-]{1,512}', row['package'])
                    and all(part not in {'', '.', '..'} for part in row['package'].split('/')))
            require(isinstance(row['commit'], str) and re.fullmatch(r'[0-9a-f]{40}', row['commit']))
            checksum(row['sum']); checksum(row['go_mod_sum'])
            result.append(dict(row, scope='tool-cosign' if identity == 'cosign' else 'fixture-' + identity,
                               installation_file=WORKFLOW if identity == 'cosign' else DOCKERFILE))
        require(seen == {'cosign', 'minio', 'mc'})
        workflow = yaml.load(inputs[WORKFLOW].decode('utf-8'), Loader=UniqueLoader)
        matches = [step['run'] for step in workflow['jobs']['sign-image']['steps'] if step.get('name') == 'Install cosign']
        require(len(matches) == 1 and isinstance(matches[0], str))
        row = next(row for row in result if row['id'] == 'cosign')
        installs = [line.strip() for line in matches[0].splitlines() if 'go install' in line]
        require(installs == ['go install ' + row['package'] + '@' + row['version']])
        docker = inputs[DOCKERFILE].decode('utf-8')
        installs = [line.strip() for line in docker.splitlines() if 'go install' in line]
        expected = ['GOBIN=/out go install -p=1 -trimpath ' + row['package'] + '@' + row['version'] + ' && \\'
                    for row in result if row['id'] != 'cosign']
        require(sorted(installs) == sorted(expected))
        return sorted(result, key=lambda row: row['id'])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError, yaml.YAMLError, binascii.Error):
        raise ToolSourceError() from None
