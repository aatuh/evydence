#!/usr/bin/env python3
"""Exercise downloaded release subject verification through the real shell command.

The tiny downloaded CLI only records invocation. Cryptographic verification is
covered by the project's real Go release-asset smoke gate, not this fixture.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import release_artifacts
import release_evidence_profile as profile
import release_sbom
import support_matrix
import release_signing
import release_subjects


ROOT = Path(__file__).resolve().parents[1]


class PublicReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        from test_release_subjects import ReleaseSubjectsTests, TAG
        fixture = ReleaseSubjectsTests('test_all_eight_binaries_and_five_archives_bind_to_actual_bytes')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.dist, self.tag = fixture.root, fixture.dist, TAG
        self.marker = self.root / 'cli-executed'
        name = 'evydence_' + TAG + '_linux_amd64'
        directory = self.root / name
        (directory / 'evydence').write_text(
            '#!/usr/bin/python3\nimport os,pathlib\npathlib.Path(' + repr(str(self.marker)) + ').write_text('
            '"credentials-present" if any(k in os.environ for k in ["GH_TOKEN", "AWS_SECRET_ACCESS_KEY", '
            '"EVYDENCE_DATABASE_URL"]) else "clean")\n')
        archive = self.dist / (name + '.tar.gz')
        archive.unlink()
        release_artifacts.write_archive(directory, archive, 1700000000,
                                        ['evydence', 'evydence-api', 'evydence-worker', 'evydence-migrate'])
        self.records = release_subjects.collect(self.dist, TAG, self.root / 'subjects')
        manifest = {'schema_version': 'evydence-release-build-manifest.v1',
                    'build_recipe_version': release_artifacts.RECIPE_VERSION, 'tag': TAG,
                    'commit': 'a' * 40, 'go_version': 'go' + support_matrix.load_policy()['go']['current'],
                    'materials': [{'path': 'go.mod', 'digest': 'sha256:' + 'b' * 64}]}
        manifest_bytes = profile.json_bytes(manifest)
        (self.dist / 'release-build-manifest.json').write_bytes(manifest_bytes)
        boms = {item['name']: release_sbom.bound_bom(item, [{'type': 'library', 'name': 'stdlib',
                 'version': 'go' + support_matrix.load_policy()['go']['current'], 'purl': 'pkg:golang/stdlib@' + support_matrix.load_policy()['go']['current']}]) for item in self.records}
        for filename, raw in profile.documents(self.records, boms, manifest, profile.digest(manifest_bytes),
                                               TAG, 'a' * 40, invocation='local').items():
            (self.dist / filename).write_bytes(raw)
        self.manifest, self.boms = manifest, boms
        for filename in ['openapi.yaml', 'evydence-release-sbom.cdx.json', 'coverage.out',
                         'release-check-summary.txt', 'release-notes.md']:
            (self.dist / filename).write_text('public fixture\n')
        (self.dist / 'openapi.sha256').write_text(self.sha(self.dist / 'openapi.yaml') + '  openapi.yaml\n')
        migration = sorted((ROOT / 'migrations').glob('*.sql'))[0]
        (self.dist / 'migrations.sha256').write_text(self.sha(migration) + '  ' + migration.relative_to(ROOT).as_posix() + '\n')
        for filename in ['evydence-release-manifest.sig.json', 'evydence-release-manifest.sig']:
            (self.dist / filename).write_text('signature fixture\n')
        (self.dist / release_signing.BUNDLE_NAME).write_text('attestation fixture\n')
        self.bind_files()
        binary_directory = self.root / 'bin'
        binary_directory.mkdir()
        gh = binary_directory / 'gh'
        gh.write_text(('#!' + sys.executable + '''
import json,os,pathlib,shutil,sys
args=sys.argv[1:]
if args[:2]==['release','download']:
 shutil.copytree(os.environ['FIXTURE_RELEASE_SOURCE'],args[args.index('--dir')+1],dirs_exist_ok=True)
elif args[0]=='api':print('a'*40)
elif args[:2]==['attestation','verify']:
 expected={'--repo':'aatuh/evydence','--cert-identity':'https://github.com/aatuh/evydence/.github/workflows/release-artifacts.yml@refs/heads/master','--cert-oidc-issuer':'https://token.actions.githubusercontent.com','--source-ref':'refs/heads/master','--source-digest':'a'*40,'--signer-digest':'a'*40}
 if any(flag not in args or args[args.index(flag)+1]!=value for flag,value in expected.items()) or '--deny-self-hosted-runners' not in args:raise SystemExit(92)
 if pathlib.Path(DENY_FILE).exists():
  print('SECRET_CANARY',file=sys.stderr);raise SystemExit(93)
else:raise SystemExit(92)
''').replace('DENY_FILE', repr(str(self.root / 'deny-attestation'))))
        gh.chmod(0o700)
        self.environment = dict(os.environ, PATH=str(binary_directory) + os.pathsep + os.environ['PATH'],
                                FIXTURE_RELEASE_SOURCE=str(self.dist), FIXTURE_CLI_MARKER=str(self.marker),
                                EVYDENCE_RELEASE_ALLOW_LEGACY_EVIDENCE='0')

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def bind_files(self):
        excluded = {'SHA256SUMS', 'evydence-release-manifest.json',
                    'evydence-release-manifest.sig.json', 'evydence-release-manifest.sig', release_signing.BUNDLE_NAME}
        files = sorted(path for path in self.dist.iterdir() if path.name not in excluded)
        (self.dist / 'SHA256SUMS').write_text(''.join(self.sha(path) + '  ' + path.name + '\n' for path in files))
        files.append(self.dist / 'SHA256SUMS')
        (self.dist / 'evydence-release-manifest.json').write_text(json.dumps({
            'schema_version': 'evydence-release-artifacts.v1.0.0',
            'generated_at': '2026-10-20T00:00:00Z',
            'artifacts': [{'path': path.name, 'digest': 'sha256:' + self.sha(path), 'size': path.stat().st_size} for path in files]}))

    def invoke(self):
        return subprocess.run(['bash', str(ROOT / 'scripts/public_release_verify.sh'), self.tag],
                              cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=20)

    def test_valid_artifact_profile_is_checked_before_downloaded_cli_runs(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('release evidence subjects verified: 13', result.stdout)
        self.assertTrue(self.marker.exists())

    def test_unattested_release_is_rejected_before_downloaded_cli_execution(self):
        # Artifact checksums and self-selected signature keys do not establish
        # publisher identity, even when every subject is internally consistent.
        (self.dist / release_signing.BUNDLE_NAME).unlink()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_rejected_attestation_never_executes_cli_or_echoes_provider_output(self):
        (self.root / 'deny-attestation').touch()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertNotIn('SECRET_CANARY', result.stdout + result.stderr)

    def test_downloaded_cli_receives_no_parent_credentials(self):
        self.environment.update(GH_TOKEN='SECRET_CANARY', AWS_SECRET_ACCESS_KEY='SECRET_CANARY',
                                EVYDENCE_DATABASE_URL='SECRET_CANARY')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), 'clean')

    def test_rehashed_checksums_do_not_override_authenticated_manifest(self):
        original = (self.dist / release_signing.MANIFEST_NAME).read_bytes()
        (self.dist / 'release-notes.md').write_text('coherently rehashed substitute\n')
        self.bind_files()
        (self.dist / release_signing.MANIFEST_NAME).write_bytes(original)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_missing_index_fails_before_executing_downloaded_payload(self):
        (self.dist / profile.INDEX_NAME).unlink()
        self.bind_files()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_consistently_rehashed_wrong_subjects_fail_before_execution(self):
        forged = copy.deepcopy(self.records)
        forged[0]['sha256'] = '0' * 64
        boms = {item['name']: release_sbom.bound_bom(item, self.boms[item['name']]['components']) for item in forged}
        raw_manifest = (self.dist / 'release-build-manifest.json').read_bytes()
        for name, raw in profile.documents(forged, boms, self.manifest, profile.digest(raw_manifest),
                                           self.tag, 'a' * 40, invocation='local').items():
            (self.dist / name).write_bytes(raw)
        self.bind_files()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_legacy_opt_in_cannot_downgrade_a_new_release(self):
        self.environment['EVYDENCE_RELEASE_ALLOW_LEGACY_EVIDENCE'] = '1'
        (self.dist / profile.INDEX_NAME).unlink()
        self.bind_files()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_checksum_lists_cannot_read_paths_outside_release_or_migration_roots(self):
        victim = self.root / 'PRIVATE_CANARY'
        victim.write_text('SECRET_CANARY')
        migrations = (self.dist / 'migrations.sha256').read_bytes()
        for kind in ['release', 'migration']:
            with self.subTest(kind=kind):
                self.marker.unlink(missing_ok=True)
                (self.dist / 'migrations.sha256').write_bytes(migrations)
                if kind == 'migration':
                    (self.dist / 'migrations.sha256').write_text(self.sha(victim) + '  ' + str(victim) + '\n')
                self.bind_files()
                if kind == 'release':
                    (self.dist / 'SHA256SUMS').write_text(self.sha(victim) + '  ' + str(victim) + '\n')
                result = self.invoke()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())
                self.assertNotIn('PRIVATE_CANARY', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
