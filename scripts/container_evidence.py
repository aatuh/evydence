#!/usr/bin/env python3
"""Generate or verify image SBOM/provenance bound to a validated OCI manifest."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import release_artifacts
import release_build
import release_evidence_profile as profile
import release_evidence_tools
import release_evidence_verify
import release_oci
import release_scanner
import release_sbom
import support_matrix


SBOM_NAME = 'evydence-container-sbom.cdx.json'
PROVENANCE_NAME = 'evydence-container-provenance.intoto.jsonl'
INDEX_NAME = 'evydence-container-evidence-index.json'
ROOT = Path(__file__).resolve().parents[1]
MATERIALS = (
    'Dockerfile', 'go.mod', 'go.sum', 'release/support-matrix.json',
    'release/tools/syft.go.mod', 'release/tools/syft.go.sum',
    '.github/workflows/container-image.yml', 'scripts/build_ldflags.sh',
    'scripts/container_evidence.py', 'scripts/release_oci.py', 'scripts/release_scanner.py',
    'scripts/release_sbom.py', 'scripts/release_evidence_tools.py', 'scripts/release_evidence_profile.py',
    'scripts/release_signing.py', 'release/signing-policy.json',
)
LIMITATIONS = [
    'This is not a SLSA level claim, legal compliance proof, certification, complete SBOM proof, '
    'authoritative vulnerability result, or secure-release guarantee.',
    'The supported image platform is linux/amd64. Inventory uses pinned Go-binary and Alpine APK catalogers. '
    'Unrecognized code, runtime downloads, licenses and package relationships may be incomplete.',
    'Image labels, builder and source input fields are producer assertions. Signature identity, registry '
    'policy, publication state and deployment admission require separate verification.',
]


def invalid():
    return ValueError('invalid container release evidence')


def documents(subject, bom, materials, *, invocation, buildx_version, workflow_commit=None):
    try:
        if (type(subject) is not dict or set(subject) != {'name', 'kind', 'sha256', 'bytes', 'platform', 'source_commit'}
                or subject['kind'] != 'container' or subject['platform'] != 'linux/amd64'
                or not profile.valid_sha(subject['sha256']) or type(subject['bytes']) is not int
                or not 0 < subject['bytes'] <= profile.MAX_JSON_BYTES or type(subject['name']) is not str
                or re.fullmatch(r'ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', subject['name']) is None):
            raise invalid()
        if type(buildx_version) is not str or re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', buildx_version) is None:
            raise invalid()
        if tuple(map(int, buildx_version[1:].split('.'))) < (0, 13, 0):
            raise invalid()
        release_sbom.verify_bom(bom, subject)
        if not all(any(c.get('purl', '').startswith('pkg:' + ecosystem + '/') for c in bom['components'])
                   for ecosystem in ('apk', 'golang')):
            raise invalid()
        source = 'https://github.com/' + subject['name'].removeprefix('ghcr.io/').rsplit(':', 1)[0]
        commit = subject['source_commit']
        dependencies = profile.source_dependencies(materials, source, commit)
        if invocation == 'local':
            if workflow_commit is not None:
                raise invalid()
            builder = source + '/blob/' + commit + '/scripts/container_evidence.py'
            invocation_id = 'local:' + commit + ':' + subject['name']
        elif (type(invocation) is str
              and re.fullmatch(re.escape(source) + r'/actions/runs/[1-9][0-9]{0,19}', invocation)):
            if type(workflow_commit) is not str or re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', workflow_commit) is None:
                raise invalid()
            builder = source + '/.github/workflows/container-image.yml@' + workflow_commit
            invocation_id = invocation
        else:
            raise invalid()
        tools = {'syft': release_sbom.SYFT_VERSION, 'scanner_go': release_scanner.SCANNER_GO_VERSION,
                 'buildx': buildx_version, 'evidence_profile': 'evydence-container-evidence.v1'}
        statement = {
            '_type': 'https://in-toto.io/Statement/v1',
            'subject': [{'name': subject['name'], 'digest': {'sha256': subject['sha256']}}],
            'predicateType': 'https://slsa.dev/provenance/v1',
            'predicate': {
                'buildDefinition': {
                    'buildType': profile.SOURCE + '/blob/master/docs/reference/release-supply-chain.md#container-build-v1',
                    'externalParameters': {'image': subject['name'], 'source_commit': commit, 'platform': 'linux/amd64',
                                           'dockerfile': 'Dockerfile', 'provenance': False, 'sbom': False,
                                           'oci_media_types': True},
                    'resolvedDependencies': dependencies,
                },
                'runDetails': {'builder': {'id': builder, 'version': tools},
                               'metadata': {'invocationId': invocation_id}},
                'evydence': {'limitations': LIMITATIONS},
            },
        }
        result = {SBOM_NAME: profile.json_bytes(bom), PROVENANCE_NAME: profile.json_bytes(statement)}
        index = {'schema': 'evydence-container-evidence.v1', 'subject': subject, 'tools': tools,
                 'workflow_commit': workflow_commit,
                 'materials': materials, 'limitations': LIMITATIONS,
                 'sbom': {'path': SBOM_NAME, 'sha256': profile.digest(result[SBOM_NAME])},
                 'provenance': {'path': PROVENANCE_NAME, 'sha256': profile.digest(result[PROVENANCE_NAME])}}
        result[INDEX_NAME] = profile.json_bytes(index)
        return result
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise invalid() from None


def verify_documents(actual, subject):
    try:
        if type(actual) is not dict or set(actual) != {SBOM_NAME, PROVENANCE_NAME, INDEX_NAME}:
            raise invalid()
        index = profile.parse_json(actual[INDEX_NAME])
        statement = profile.parse_json(actual[PROVENANCE_NAME])
        bom = profile.parse_json(actual[SBOM_NAME])
        invocation = statement['predicate']['runDetails']['metadata']['invocationId']
        if invocation == 'local:' + subject['source_commit'] + ':' + subject['name']:
            invocation = 'local'
        expected = documents(subject, bom, index['materials'], invocation=invocation,
                             buildx_version=index['tools']['buildx'], workflow_commit=index['workflow_commit'])
        if actual != expected:
            raise invalid()
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise invalid() from None


def source_materials():
    return [{'path': name, 'digest': release_artifacts.material_digest(ROOT, Path(name))}
            for name in sorted(MATERIALS)]


def generate(args):
    environment = release_build.build_environment(os.environ, support_matrix.load_policy()['go']['current'])
    release_build.source_identity(ROOT, args.expected_commit, environment)
    output = Path(args.out)
    if output.is_symlink() or output.exists() and not output.is_dir():
        raise invalid()
    for name in (SBOM_NAME, PROVENANCE_NAME, INDEX_NAME):
        if (output / name).exists() or (output / name).is_symlink():
            raise invalid()
    subject = release_oci.inspect(args.oci, args.image, args.digest, args.expected_commit)
    executable = Path(args.syft).resolve()
    if release_evidence_tools.verify_installation(executable.parent, release_evidence_tools.recipe_digest()) != executable:
        raise invalid()
    with tempfile.TemporaryDirectory(prefix='evydence-container-evidence-') as temporary:
        scratch = Path(temporary)
        release_scanner.verify_tool(executable, scratch)
        bom = release_scanner.scan_container(executable, args.oci, subject, scratch / 'scan')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    invocation = 'local'
    workflow_commit = None
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        repository = args.image.removeprefix('ghcr.io/').rsplit(':', 1)[0]
        if os.environ.get('GITHUB_REPOSITORY') != repository or re.fullmatch(r'[1-9][0-9]{0,19}', run_id) is None:
            raise invalid()
        invocation = 'https://github.com/' + repository + '/actions/runs/' + run_id
        workflow_commit = os.environ.get('GITHUB_WORKFLOW_SHA', '')
    result = documents(subject, bom, source_materials(), invocation=invocation, buildx_version=args.buildx_version,
                       workflow_commit=workflow_commit)
    verify_documents(result, subject)
    release_build.source_identity(ROOT, args.expected_commit, environment)
    output.mkdir(parents=True, exist_ok=True)
    for name, raw in result.items():
        with (output / name).open('xb') as stream:
            stream.write(raw)


def verify(args):
    output = Path(args.out)
    if output.is_symlink() or not output.is_dir():
        raise invalid()
    subject = release_oci.inspect(args.oci, args.image, args.digest, args.expected_commit)
    actual = {name: release_evidence_verify.read_file(output / name)
              for name in (SBOM_NAME, PROVENANCE_NAME, INDEX_NAME)}
    verify_documents(actual, subject)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    for name in ('generate', 'verify'):
        command = modes.add_parser(name)
        command.add_argument('--oci', required=True)
        command.add_argument('--image', required=True)
        command.add_argument('--digest', required=True)
        command.add_argument('--expected-commit', required=True)
        command.add_argument('--out', required=True)
        if name == 'generate':
            command.add_argument('--syft', required=True)
            command.add_argument('--buildx-version', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == 'generate':
            generate(args)
        else:
            verify(args)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, subprocess.SubprocessError):
        print('container release evidence verification failed', file=sys.stderr)
        return 2
    print('container release evidence ' + ('generated and verified' if args.mode == 'generate' else 'verified') + ': linux/amd64')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
