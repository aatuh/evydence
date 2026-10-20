#!/usr/bin/env python3
"""Enforce publisher identity before trusting or executing release payloads."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

import release_artifacts
import release_build
import release_evidence_profile as profile
import release_evidence_verify
import release_scanner
import support_matrix


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_NAME = 'evydence-release-attestations.sigstore.json'
MANIFEST_NAME = 'evydence-release-manifest.json'
SIGNATURE_NAME = 'evydence-release-manifest.sig.json'
WORKFLOWS = {'release': '.github/workflows/release-artifacts.yml',
             'container': '.github/workflows/container-image.yml'}


def invalid():
    return ValueError('release signing identity verification failed')


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise invalid()


def valid_commit(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{40}', value) is not None


def validate_policy(value):
    try:
        if (type(value) is not dict or set(value) != {'schema', 'repository', 'issuer', 'ref',
                'environment', 'reviewer', 'workflows', 'legacy', 'revoked_sources'}
                or value['schema'] != 'evydence-release-signing-policy.v1'
                or value['repository'] != 'aatuh/evydence'
                or value['issuer'] != 'https://token.actions.githubusercontent.com'
                or value['ref'] != 'refs/heads/master' or value['environment'] != 'release-production'
                or value['reviewer'] != 'aatuh' or value['workflows'] != WORKFLOWS
                or type(value['legacy']) is not list or not 0 < len(value['legacy']) <= 16
                or type(value['revoked_sources']) is not list or len(value['revoked_sources']) > 256
                or not all(valid_commit(commit) for commit in value['revoked_sources'])
                or len(value['revoked_sources']) != len(set(value['revoked_sources']))):
            raise invalid()
        seen = set()
        for entry in value['legacy']:
            if (type(entry) is not dict or set(entry) != {'tag', 'source_commit', 'manifest_sha256', 'public_key_sha256'}
                    or not valid_commit(entry['source_commit']) or entry['tag'] in seen
                    or not profile.valid_sha(entry['manifest_sha256']) or not profile.valid_sha(entry['public_key_sha256'])):
                raise invalid()
            release_artifacts.validate_coordinates(entry['tag'], entry['source_commit'])
            seen.add(entry['tag'])
        return value
    except (KeyError, TypeError, ValueError, RecursionError):
        raise invalid() from None


def load_policy():
    raw = release_evidence_verify.read_file(ROOT/'release/signing-policy.json')
    if len(raw) > 64 * 1024:
        raise invalid()
    policy = validate_policy(profile.parse_json(raw))
    legacy = profile.parse_json(release_evidence_verify.read_file(ROOT/'release/legacy-evidence.json'))
    expected = {(entry['tag'], entry['source_commit']) for entry in legacy['releases']
                if entry['repository'] == policy['repository']}
    if expected != {(entry['tag'], entry['source_commit']) for entry in policy['legacy']}:
        raise invalid()
    return policy


def identity(policy, kind):
    validate_policy(policy)
    if kind not in WORKFLOWS:
        raise invalid()
    return 'https://github.com/' + policy['repository'] + '/' + policy['workflows'][kind] + '@' + policy['ref']


def validate_context(policy, kind, environment, commit):
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REPOSITORY': policy['repository'], 'GITHUB_REF': policy['ref'],
                'GITHUB_REF_TYPE': 'branch', 'GITHUB_REF_PROTECTED': 'true',
                'GITHUB_SHA': commit, 'GITHUB_WORKFLOW_SHA': commit,
                'GITHUB_WORKFLOW_REF': identity(policy, kind).removeprefix('https://github.com/')}
    if (not valid_commit(commit) or commit in policy['revoked_sources']
            or any(environment.get(name) != value for name, value in expected.items())):
        raise invalid()


def attestation_arguments(policy, kind, artifact, bundle, commit):
    certificate = identity(policy, kind)
    if not valid_commit(commit) or commit in policy['revoked_sources']:
        raise invalid()
    return ['gh', 'attestation', 'verify', str(Path(artifact).resolve()), '--bundle', str(Path(bundle).resolve()),
            '--hostname', 'github.com', '--repo', policy['repository'],
            '--cert-identity', certificate, '--cert-oidc-issuer', policy['issuer'],
            '--source-ref', policy['ref'], '--source-digest', commit, '--signer-digest', commit,
            '--predicate-type', 'https://slsa.dev/provenance/v1', '--deny-self-hosted-runners']


def verify_legacy(policy, dist, tag, commit):
    if commit in policy['revoked_sources']:
        raise invalid()
    profile.verify_legacy_identity(release_evidence_verify.read_file(ROOT/'release/legacy-evidence.json'),
                                   policy['repository'], tag, commit)
    entries = [entry for entry in policy['legacy'] if entry['tag'] == tag and entry['source_commit'] == commit]
    if len(entries) != 1:
        raise invalid()
    pin = entries[0]
    manifest = release_evidence_verify.read_file(Path(dist)/MANIFEST_NAME)
    signature = profile.parse_json(release_evidence_verify.read_file(Path(dist)/SIGNATURE_NAME))
    try:
        key = base64.b64decode(signature['public_key'], validate=True)
        value = base64.b64decode(signature['signature'], validate=True)
        if (len(key) != 32 or len(value) != 64 or signature['algorithm'] != 'Ed25519'
                or profile.digest(manifest) != pin['manifest_sha256']
                or profile.digest(key) != pin['public_key_sha256']):
            raise invalid()
    except (ValueError, KeyError, TypeError):
        raise invalid() from None


def verify_manifest_files(dist):
    dist = Path(dist)
    if dist.is_symlink() or not dist.is_dir():
        raise invalid()
    manifest = profile.parse_json(release_evidence_verify.read_file(dist/MANIFEST_NAME))
    if (set(manifest) != {'schema_version', 'generated_at', 'artifacts'}
            or manifest['schema_version'] != 'evydence-release-artifacts.v1.0.0'
            or type(manifest['generated_at']) is not str or type(manifest['artifacts']) is not list
            or not 0 < len(manifest['artifacts']) <= 256):
        raise invalid()
    names = set()
    for entry in manifest['artifacts']:
        if (type(entry) is not dict or set(entry) != {'path', 'digest', 'size'}
                or type(entry['path']) is not str
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', entry['path']) is None
                or entry['path'] in names or type(entry['size']) is not int
                or not 0 <= entry['size'] <= release_artifacts.MAX_FILE_BYTES
                or type(entry['digest']) is not str
                or re.fullmatch(r'sha256:[a-f0-9]{64}', entry['digest']) is None):
            raise invalid()
        names.add(entry['path'])
        stream, size = release_artifacts.regular_file(dist/entry['path'])
        with stream:
            if size != entry['size'] or 'sha256:'+hashlib.file_digest(stream, 'sha256').hexdigest() != entry['digest']:
                raise invalid()
    return names


def verifier_environment(parent):
    return {name: parent[name] for name in ['PATH', 'HOME', 'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
            'GH_TOKEN', 'GITHUB_TOKEN', 'GH_CONFIG_DIR'] if parent.get(name)}


def github_get(endpoint):
    raw = release_scanner.capture(['gh', 'api', '--hostname', 'github.com',
        '-H', 'X-GitHub-Api-Version: 2026-03-10', endpoint], ROOT,
        verifier_environment(os.environ), 64 * 1024, 30)
    return profile.parse_json(raw)


def validate_provider_rules(policy, environment, branches):
    try:
        rules = environment['protection_rules']
        reviewers = [rule for rule in rules if rule['type'] == 'required_reviewers']
        if (environment['name'] != policy['environment']
                or environment['deployment_branch_policy'] != {'protected_branches': False, 'custom_branch_policies': True}
                or type(rules) is not list or len(reviewers) != 1
                or reviewers[0]['prevent_self_review'] is not False
                or type(reviewers[0]['reviewers']) is not list or len(reviewers[0]['reviewers']) != 1
                or reviewers[0]['reviewers'][0]['type'] != 'User'
                or reviewers[0]['reviewers'][0]['reviewer']['login'] != policy['reviewer']
                or reviewers[0]['reviewers'][0]['reviewer']['id'] != 1116211
                or type(branches['total_count']) is not int or branches['total_count'] != 1
                or type(branches['branch_policies']) is not list or len(branches['branch_policies']) != 1
                or branches['branch_policies'][0]['name'] != 'master'
                or branches['branch_policies'][0]['type'] != 'branch'):
            raise invalid()
    except (KeyError, TypeError, ValueError, IndexError):
        raise invalid() from None


def verify_provider_rules(policy):
    endpoint = 'repos/'+policy['repository']+'/environments/'+policy['environment']
    validate_provider_rules(policy, github_get(endpoint), github_get(endpoint+'/deployment-branch-policies?per_page=100'))


def secret_names(endpoint):
    names = set()
    for page in range(1, 11):
        result = github_get(endpoint+'?per_page=100&page='+str(page))
        records = result['secrets']
        if type(records) is not list or type(result['total_count']) is not int:
            raise invalid()
        for item in records:
            name = item['name']
            if type(name) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) is None or name in names:
                raise invalid()
            names.add(name)
        if len(names) == result['total_count']:
            return names
        if len(records) != 100:
            raise invalid()
    raise invalid()


def verify_provider_custody(policy):
    verify_provider_rules(policy)
    root = 'repos/'+policy['repository']
    repository = secret_names(root+'/actions/secrets')
    environment = secret_names(root+'/environments/'+policy['environment']+'/secrets')
    publishers = {'EVYDENCE_RELEASE_PUBLISH_TOKEN', 'EVYDENCE_GHCR_PUBLISH_TOKEN'}
    private_key = {'EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64'}
    if repository & (publishers | private_key) or not publishers <= environment or environment & private_key:
        raise invalid()


def verify_public(policy, dist, repository, tag, commit, *, legacy=False):
    release_artifacts.validate_coordinates(tag, commit)
    if repository != policy['repository'] or commit in policy['revoked_sources']:
        raise invalid()
    dist = Path(dist)
    if dist.is_symlink() or not dist.is_dir():
        raise invalid()
    if legacy:
        verify_legacy(policy, dist, tag, commit)
    else:
        release_evidence_verify.read_file(dist/BUNDLE_NAME)
        for filename in [MANIFEST_NAME, SIGNATURE_NAME]:
            release_evidence_verify.read_file(dist/filename)
            subprocess.run(attestation_arguments(policy, 'release', dist/filename, dist/BUNDLE_NAME, commit),
                           check=True, timeout=120, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=verifier_environment(os.environ))
    names = verify_manifest_files(dist)
    required = {'SHA256SUMS', 'evydence_'+tag+'_linux_amd64.tar.gz'}
    if not required <= names:
        raise invalid()


def main():
    parser = Parser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    public = modes.add_parser('verify-public')
    public.add_argument('--dist', required=True)
    public.add_argument('--repository', required=True)
    public.add_argument('--tag', required=True)
    public.add_argument('--expected-commit', required=True)
    public.add_argument('--legacy', action='store_true')
    files = modes.add_parser('verify-files')
    files.add_argument('--dist', required=True)
    modes.add_parser('check-provider')
    preflight = modes.add_parser('preflight')
    preflight.add_argument('--kind', choices=WORKFLOWS, required=True)
    preflight.add_argument('--expected-commit', required=True)
    preflight.add_argument('--tag')
    certificate = modes.add_parser('identity')
    certificate.add_argument('--kind', choices=WORKFLOWS, required=True)
    try:
        arguments = parser.parse_args()
        policy = load_policy()
        if arguments.mode == 'identity':
            print(identity(policy, arguments.kind))
            return 0
        if arguments.mode == 'check-provider':
            verify_provider_custody(policy)
        elif arguments.mode == 'verify-files':
            verify_manifest_files(arguments.dist)
        elif arguments.mode == 'verify-public':
            verify_public(policy, arguments.dist, arguments.repository, arguments.tag,
                          arguments.expected_commit, legacy=arguments.legacy)
        else:
            validate_context(policy, arguments.kind, os.environ, arguments.expected_commit)
            verify_provider_rules(policy)
            environment = release_build.build_environment(os.environ, support_matrix.load_policy()['go']['current'])
            release_build.source_identity(ROOT, arguments.expected_commit, environment)
            if arguments.kind == 'release':
                release_artifacts.validate_coordinates(arguments.tag, arguments.expected_commit)
                tagged = release_build.capture(['git', 'rev-parse', '--verify',
                    'refs/tags/'+arguments.tag+'^{commit}'], ROOT, environment)
                if tagged != arguments.expected_commit:
                    raise invalid()
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        print('release signing identity verification failed', file=sys.stderr)
        return 2
    print('release signing policy verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
