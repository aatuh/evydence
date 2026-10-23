#!/usr/bin/env python3
"""Bind public package inventories and SLSA-style provenance to actual payloads."""
from __future__ import annotations

import hashlib
import json
import re

import release_artifacts
import release_sbom
import support_matrix


INDEX_NAME = 'evydence-release-evidence-index.json'
PROVENANCE_NAME = 'evydence-release-provenance.intoto.jsonl'
SUMMARY_NAME = 'evydence-release-provenance.json'
MAX_JSON_BYTES = 4 * 1024 * 1024
SOURCE = 'https://github.com/aatuh/evydence'
BUILD_TYPE = SOURCE + '/blob/master/docs/reference/release-supply-chain.md#build-v1'
LIMITATIONS = [
    'This is not a SLSA level claim, legal compliance proof, certification, complete SBOM proof, '
    'authoritative vulnerability result, or secure-release guarantee.',
    'Subject hashes bind these bytes; builder and invocation fields are producer assertions. '
    'The signed release manifest and separately verified signing identity establish their trust boundary.',
    'Release binary/archive inventories cover Go packages recognized by the pinned binary cataloger. '
    'They omit file paths, licenses, package relationships, dynamic downloads and unrecognized code.',
]


def invalid():
    return ValueError('invalid release evidence profile')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise invalid()
        result[key] = value
    return result


def parse_json(raw):
    try:
        if type(raw) is not bytes or len(raw) > MAX_JSON_BYTES:
            raise invalid()
        def invalid_constant(_value):
            raise invalid()
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
        if type(value) is not dict:
            raise invalid()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise invalid() from None


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sbom_name(subject_name):
    return 'evydence-sbom-' + digest(subject_name.encode()) + '.cdx.json'


def safe_path(value):
    return (type(value) is str and 0 < len(value) <= 1024
            and re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value) is not None
            and all(part not in ('.', '..') for part in value.split('/')))


def valid_sha(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def source_dependencies(materials, source, commit):
    if (type(source) is not str or re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', source) is None
            or type(commit) is not str or re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', commit) is None):
        raise invalid()
    dependencies, seen = [{'uri': 'git+' + source, 'digest': {'gitCommit': commit}}], set()
    if type(materials) is not list or not 0 < len(materials) <= 256:
        raise invalid()
    for material in materials:
        if type(material) is not dict or set(material) != {'path', 'digest'}:
            raise invalid()
        path, value = material['path'], material['digest']
        if (not safe_path(path) or path in seen or type(value) is not str
                or not value.startswith('sha256:') or not valid_sha(value[7:])):
            raise invalid()
        seen.add(path)
        dependencies.append({'uri': 'git+' + source + '@' + commit + '#' + path,
                             'digest': {'sha256': value[7:]}})
    return dependencies


def statement(records, manifest, manifest_sha, tag, commit, invocation, workflow_commit):
    release_artifacts.validate_coordinates(tag, commit)
    policy = support_matrix.load_policy()
    if (type(manifest) is not dict or manifest.get('schema_version') != 'evydence-release-build-manifest.v1'
            or manifest.get('tag') != tag or manifest.get('commit') != commit
            or manifest.get('build_recipe_version') != release_artifacts.RECIPE_VERSION
            or manifest.get('go_version') != 'go' + policy['go']['current'] or not valid_sha(manifest_sha)):
        raise invalid()
    dependencies = source_dependencies(manifest.get('materials'), SOURCE, commit)
    dependencies.insert(1, {'name': 'release-build-manifest.json', 'digest': {'sha256': manifest_sha}})
    if invocation == 'local':
        if workflow_commit is not None:
            raise invalid()
        builder = SOURCE + '/blob/' + commit + '/scripts/release_candidate_package.sh'
        invocation_id = 'local:' + commit + ':' + tag
    elif (type(invocation) is str
          and re.fullmatch(re.escape(SOURCE) + r'/actions/runs/[1-9][0-9]{0,19}', invocation)):
        if type(workflow_commit) is not str or re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', workflow_commit) is None:
            raise invalid()
        builder = SOURCE + '/.github/workflows/release-artifacts.yml@' + workflow_commit
        invocation_id = invocation
    else:
        raise invalid()
    return {
        '_type': 'https://in-toto.io/Statement/v1',
        'subject': [{'name': item['name'], 'digest': {'sha256': item['sha256']}} for item in records],
        'predicateType': 'https://slsa.dev/provenance/v1',
        'predicate': {
            'buildDefinition': {
                'buildType': BUILD_TYPE,
                'externalParameters': {'tag': tag, 'source_commit': commit,
                                       'platforms': [target['target'] for target in support_matrix.release_plan(policy)],
                                       'build_recipe_version': release_artifacts.RECIPE_VERSION},
                'resolvedDependencies': dependencies,
            },
            'runDetails': {'builder': {'id': builder,
                                      'version': {'go': manifest['go_version'], 'syft': release_sbom.SYFT_VERSION,
                                                  'evidence_profile': 'evydence-release-evidence.v1'}},
                           'metadata': {'invocationId': invocation_id}},
            'evydence': {'limitations': LIMITATIONS},
        },
    }


def documents(records, boms, manifest, manifest_sha, tag, commit, *, invocation, workflow_commit=None):
    try:
        if type(records) is not list or not 0 < len(records) <= 32 or type(boms) is not dict:
            raise invalid()
        records = sorted(records, key=lambda item: item['name'])
        seen = set()
        for item in records:
            if (type(item) is not dict or not safe_path(item.get('name')) or item['name'] in seen
                    or item.get('kind') not in ('binary', 'archive') or not valid_sha(item.get('sha256'))
                    or type(item.get('bytes')) is not int or not 0 < item['bytes'] <= release_artifacts.MAX_FILE_BYTES):
                raise invalid()
            seen.add(item['name'])
        if set(boms) != seen:
            raise invalid()
        provenance = statement(records, manifest, manifest_sha, tag, commit, invocation, workflow_commit)
        result = {PROVENANCE_NAME: json_bytes(provenance),
                  SUMMARY_NAME: json_bytes({'schema': 'evydence-release-provenance.v2',
                                            'subject': {'name': 'evydence', 'version': tag, 'commit': commit},
                                            'statement': provenance, 'limitations': LIMITATIONS})}
        index = {'schema': 'evydence-release-evidence.v1', 'tag': tag, 'source_commit': commit,
                 'workflow_commit': workflow_commit,
                 'tools': {'syft': release_sbom.SYFT_VERSION, 'cyclonedx': '1.6', 'slsa_predicate': 'v1'},
                 'artifacts': [], 'limitations': LIMITATIONS}
        for item in records:
            release_sbom.verify_bom(boms[item['name']], item)
            filename = sbom_name(item['name'])
            raw = json_bytes(boms[item['name']])
            if filename in result:
                raise invalid()
            result[filename] = raw
            index['artifacts'].append({key: item[key] for key in ('name', 'kind', 'sha256', 'bytes')} | {
                'sbom': {'path': filename, 'sha256': digest(raw)},
                'provenance': {'path': PROVENANCE_NAME, 'sha256': digest(result[PROVENANCE_NAME])},
            })
        result[INDEX_NAME] = json_bytes(index)
        return result
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise invalid() from None


def verify_documents(actual, records, manifest, manifest_sha, tag, commit):
    try:
        provenance = parse_json(actual[PROVENANCE_NAME])
        invocation = provenance['predicate']['runDetails']['metadata']['invocationId']
        if invocation == 'local:' + commit + ':' + tag:
            invocation = 'local'
        boms = {item['name']: parse_json(actual[sbom_name(item['name'])]) for item in records}
        workflow_commit = parse_json(actual[INDEX_NAME])['workflow_commit']
        expected = documents(records, boms, manifest, manifest_sha, tag, commit, invocation=invocation,
                             workflow_commit=workflow_commit)
        if type(actual) is not dict or actual != expected:
            raise invalid()
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise invalid() from None


def verify_legacy_identity(raw_policy, repository, tag, commit):
    release_artifacts.validate_coordinates(tag, commit)
    policy = parse_json(raw_policy)
    if set(policy) != {'schema', 'releases'} or policy['schema'] != 'evydence-legacy-release-evidence.v1':
        raise invalid()
    releases = policy['releases']
    if type(releases) is not list or not 0 < len(releases) <= 16:
        raise invalid()
    seen = set()
    for release in releases:
        if (type(release) is not dict or set(release) != {'repository', 'tag', 'source_commit', 'provenance_profile'}
                or release['provenance_profile'] != 'evydence-release-provenance.v1'
                or type(release['repository']) is not str
                or re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', release['repository']) is None):
            raise invalid()
        release_artifacts.validate_coordinates(release['tag'], release['source_commit'])
        identity = (release['repository'], release['tag'], release['source_commit'])
        if identity in seen:
            raise invalid()
        seen.add(identity)
    if (repository, tag, commit) not in seen:
        raise invalid()
