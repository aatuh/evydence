#!/usr/bin/env python3
"""Publisher identity, protected workflow context and authenticated-file checks."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import release_signing as signing


class ReleaseSigningTests(unittest.TestCase):
    def test_bad_flags_do_not_echo_possible_secrets(self):
        result = subprocess.run([sys.executable, str(Path(signing.__file__)), 'identity',
                                 '--kind', 'SECRET_CANARY'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('SECRET_CANARY', result.stderr + result.stdout)

    def context(self):
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REPOSITORY': 'aatuh/evydence', 'GITHUB_REF': 'refs/heads/master',
                'GITHUB_REF_TYPE': 'branch', 'GITHUB_REF_PROTECTED': 'true',
                'GITHUB_SHA': 'a' * 40, 'GITHUB_WORKFLOW_SHA': 'a' * 40,
                'GITHUB_WORKFLOW_REF': 'aatuh/evydence/.github/workflows/release-artifacts.yml@refs/heads/master'}

    def test_only_protected_master_exact_workflow_and_source_can_sign(self):
        policy = signing.load_policy()
        signing.validate_context(policy, 'release', self.context(), 'a' * 40)
        for field, value in [('GITHUB_REF', 'refs/heads/feature'), ('GITHUB_REF_TYPE', 'tag'),
                             ('GITHUB_REF_PROTECTED', 'false'), ('GITHUB_EVENT_NAME', 'pull_request'),
                             ('GITHUB_REPOSITORY', 'attacker/evydence'), ('GITHUB_SHA', 'b' * 40),
                             ('GITHUB_WORKFLOW_SHA', 'b' * 40), ('GITHUB_ACTIONS', 'false'),
                             ('GITHUB_WORKFLOW_REF', 'aatuh/evydence/.github/workflows/other.yml@refs/heads/master')]:
            with self.subTest(field=field):
                env = dict(self.context(), **{field: value})
                with self.assertRaises(ValueError):
                    signing.validate_context(policy, 'release', env, 'a' * 40)

    def test_attestation_verifier_pins_identity_issuer_ref_source_and_signer(self):
        policy = signing.load_policy()
        args = signing.attestation_arguments(policy, 'release', Path('/artifact'), Path('/bundle'), 'a' * 40)
        for flag, expected in [('--repo', 'aatuh/evydence'),
                ('--cert-identity', 'https://github.com/aatuh/evydence/.github/workflows/release-artifacts.yml@refs/heads/master'),
                ('--cert-oidc-issuer', 'https://token.actions.githubusercontent.com'),
                ('--source-ref', 'refs/heads/master'), ('--source-digest', 'a' * 40),
                ('--signer-digest', 'a' * 40)]:
            self.assertEqual(args[args.index(flag)+1], expected)
        self.assertIn('--deny-self-hosted-runners', args)
        self.assertNotIn('--cert-identity-regex', args)
        with self.assertRaises(ValueError):
            signing.attestation_arguments(policy, 'release', Path('/artifact'), Path('/bundle'), '$(SECRET)')

    def test_policy_cannot_add_fork_issuer_wildcard_or_extra_fields(self):
        policy = signing.load_policy()
        for field, value in [('repository', 'attacker/evydence'), ('issuer', 'https://attacker.example'),
                             ('ref', 'refs/heads/*'), ('environment', '../private'), ('unknown', True)]:
            with self.subTest(field=field):
                wrong = dict(policy, **{field: value})
                with self.assertRaises(ValueError):
                    signing.validate_policy(wrong)

    def test_authenticated_manifest_files_are_checked_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root/'artifact.tar.gz';data.write_bytes(b'original')
            manifest = {'schema_version': 'evydence-release-artifacts.v1.0.0', 'generated_at': 'fixture',
                        'artifacts': [{'path': data.name, 'digest': 'sha256:'+hashlib.sha256(b'original').hexdigest(), 'size': 8}]}
            (root/'evydence-release-manifest.json').write_text(json.dumps(manifest))
            signing.verify_manifest_files(root)
            data.write_bytes(b'replaced')
            with self.assertRaises(ValueError):signing.verify_manifest_files(root)
            for path in ['../outside', '/private', 'dir/artifact']:
                manifest['artifacts'][0]['path'] = path
                (root/'evydence-release-manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):signing.verify_manifest_files(root)

    def test_legacy_identity_requires_exact_manifest_and_public_key_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'evydence-release-manifest.json').write_bytes(b'forged')
            (root/'evydence-release-manifest.sig.json').write_text('{}')
            with self.assertRaises(ValueError):
                signing.verify_legacy(signing.load_policy(), root, 'v0.1.0-rc.7', '2f759100e723554e4e68e3ada712c923e391a17a')

    def test_committed_historical_metadata_pins_and_rejects_changed_key_or_bytes(self):
        policy = signing.load_policy();entry = policy['legacy'][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = Path(__file__).parent/'testdata/release-legacy-v0.1.0-rc.7'
            for name in [signing.MANIFEST_NAME, signing.SIGNATURE_NAME]:shutil.copyfile(fixture/name,root/name)
            signing.verify_legacy(policy,root,entry['tag'],entry['source_commit'])
            wrong = copy.deepcopy(policy);wrong['legacy'][0]['public_key_sha256']='0'*64
            with self.assertRaises(ValueError):signing.verify_legacy(wrong,root,entry['tag'],entry['source_commit'])
            with (root/signing.MANIFEST_NAME).open('ab') as output:output.write(b'\n')
            with self.assertRaises(ValueError):signing.verify_legacy(policy,root,entry['tag'],entry['source_commit'])

    def test_provider_requires_review_gate_and_only_master_branch(self):
        policy = signing.load_policy()
        environment = {'name': 'release-production', 'deployment_branch_policy': {
            'protected_branches': False, 'custom_branch_policies': True},
            'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': False,
                'reviewers': [{'type': 'User', 'reviewer': {'login': 'aatuh', 'id': 1116211}}]},
                {'type': 'branch_policy'}]}
        branches = {'total_count': 1, 'branch_policies': [{'name': 'master', 'type': 'branch'}]}
        signing.validate_provider_rules(policy, environment, branches)
        for mode in ['no-reviewer', 'wrong-reviewer', 'all-branches', 'tag', 'wildcard']:
            with self.subTest(mode=mode):
                env, refs = copy.deepcopy(environment), copy.deepcopy(branches)
                if mode == 'no-reviewer': env['protection_rules'][0]['reviewers'] = []
                if mode == 'wrong-reviewer': env['protection_rules'][0]['reviewers'][0]['reviewer']['login'] = 'attacker'
                if mode == 'all-branches': env['deployment_branch_policy'] = None
                if mode == 'tag': refs['branch_policies'][0]['type'] = 'tag'
                if mode == 'wildcard': refs['branch_policies'][0]['name'] = '*'
                with self.assertRaises(ValueError): signing.validate_provider_rules(policy, env, refs)

    def test_provider_custody_rejects_repository_signer_and_publisher_secrets(self):
        policy = signing.load_policy()
        publishers = {'EVYDENCE_RELEASE_PUBLISH_TOKEN', 'EVYDENCE_GHCR_PUBLISH_TOKEN'}
        with mock.patch.object(signing, 'verify_provider_rules'), mock.patch.object(signing, 'secret_names') as names:
            names.side_effect = [set(), publishers]
            signing.verify_provider_custody(policy)
            for repository, environment in [({'EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64'}, publishers),
                    ({'EVYDENCE_RELEASE_PUBLISH_TOKEN'}, publishers), (set(), set()),
                    (set(), publishers | {'EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64'})]:
                with self.subTest(repository=repository, environment=environment):
                    names.side_effect = [repository, environment]
                    with self.assertRaises(ValueError): signing.verify_provider_custody(policy)

    def test_secret_inventory_does_not_accept_truncated_or_duplicate_pages(self):
        with mock.patch.object(signing, 'github_get') as get:
            get.return_value = {'total_count': 2, 'secrets': [{'name': 'ONLY_ONE'}]}
            with self.assertRaises(ValueError): signing.secret_names('fixture')
            get.return_value = {'total_count': 2, 'secrets': [{'name': 'DUP'}, {'name': 'DUP'}]}
            with self.assertRaises(ValueError): signing.secret_names('fixture')

    def test_revoked_source_is_denied_before_provider_verification_or_signing(self):
        policy = signing.load_policy()
        policy['revoked_sources'] = ['a' * 40]
        self.assertEqual(signing.validate_policy(policy), policy)
        with self.assertRaises(ValueError): signing.validate_context(policy, 'release', self.context(), 'a' * 40)
        with self.assertRaises(ValueError): signing.attestation_arguments(policy, 'release', Path('/a'), Path('/b'), 'a' * 40)
        with mock.patch.object(signing.subprocess, 'run') as provider:
            with self.assertRaises(ValueError): signing.verify_public(policy, Path('/a'), 'aatuh/evydence', 'v0.0.0-rc.1', 'a' * 40)
            provider.assert_not_called()


if __name__ == '__main__':
    unittest.main()
