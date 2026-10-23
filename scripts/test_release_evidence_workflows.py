#!/usr/bin/env python3
"""Execute real workflow validation scripts with hostile dispatch inputs offline."""
import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class EvidenceWorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)

    def test_note_review_precedes_expensive_build_and_rechecks_before_provider_writes(self):
        jobs = self.workflow('release-artifacts.yml')['jobs']
        preview = jobs['check-release-notes']
        self.assertNotIn('environment', preview)
        self.assertEqual(preview['permissions'], {'contents': 'read', 'pull-requests': 'read'})
        self.assertIn('check-release-notes', jobs['verify-reproducible-builds']['needs'])
        self.assertIn('release_notes.py', str(preview['steps']))
        self.assertTrue(any(s.get('uses', '').startswith('actions/upload-artifact@') for s in preview['steps']))
        for name in ['attest-release', 'publish-draft-release']:
            steps = jobs[name]['steps']
            checker = next(i for i, step in enumerate(steps) if 'release_notes.py' in step.get('run', ''))
            authority = next(i for i, step in enumerate(steps) if step.get('uses', '').startswith('actions/attest@')
                             or step['name'] == 'Create or update draft GitHub release')
            self.assertLess(checker, authority)

    def test_release_authority_is_protected_and_uses_ephemeral_manifest_keys(self):
        workflow = self.workflow('release-artifacts.yml')
        self.assertNotIn('push', workflow['on'])
        self.assertNotIn('secrets.EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64', str(workflow))
        package = workflow['jobs']['package']
        self.assertEqual(package['environment'], 'release-production')
        self.assertIn('refs/heads/master', package['if'])
        self.assertIn('github.ref_protected', package['if'])
        scripts = '\n'.join(step.get('run', '') for step in package['steps'])
        self.assertIn('release_signing.py preflight', scripts)
        self.assertIn('release keygen', scripts)
        self.assertIn('trap ', scripts)

    def test_release_attestation_precedes_publication_and_pins_official_action(self):
        jobs = self.workflow('release-artifacts.yml')['jobs']
        attest = jobs['attest-release']
        self.assertEqual(attest['environment'], 'release-production')
        self.assertEqual(attest['permissions']['id-token'], 'write')
        step = next(step for step in attest['steps'] if step.get('uses', '').startswith('actions/attest@'))
        self.assertEqual(step['uses'], 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6')
        self.assertIn('evydence-release-manifest.json', step['with']['subject-path'])
        self.assertIn('evydence-release-manifest.sig.json', step['with']['subject-path'])
        publish = jobs['publish-draft-release']
        self.assertIn('attest-release', publish['needs'])
        self.assertEqual(publish['environment'], 'release-production')
        self.assertIn('release_signing.py verify-public', '\n'.join(s.get('run', '') for s in publish['steps']))

    def test_container_checks_out_trusted_workflow_source_before_reading_secrets(self):
        jobs = self.workflow('container-image.yml')['jobs']
        for name in ['publish-image', 'sign-image']:
            self.assertEqual(jobs[name]['environment'], 'release-production')
            self.assertIn('github.ref_protected', jobs[name]['if'])
        steps = jobs['publish-image']['steps']
        checkout = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], '${{ github.sha }}')
        guard = next(i for i,s in enumerate(steps) if 'release_signing.py preflight' in s.get('run', ''))
        secret = next(i for i,s in enumerate(steps) if 'EVYDENCE_GHCR_PUBLISH_TOKEN' in str(s.get('env', {})))
        self.assertLess(guard, secret)
        scripts = '\n'.join(s.get('run', '') for s in jobs['sign-image']['steps'])
        self.assertNotIn('--certificate-identity-regexp', scripts)
        self.assertIn('--certificate-identity ', scripts)
        self.assertIn('--certificate-github-workflow-sha', scripts)

    def test_release_key_generation_does_not_inherit_release_only_settings(self):
        job = self.workflow('release-artifacts.yml')['jobs']['package']
        script = next(s['run'] for s in job['steps'] if s['name'] == 'Package signed release candidate')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);(root/'bin').mkdir();(root/'scripts').mkdir()
            go = root/'bin/go'
            go.write_text('''#!/usr/bin/python3
import os,pathlib,sys
if any(k.startswith('EVYDENCE_RELEASE_') for k in os.environ):raise SystemExit(93)
if 'GH_TOKEN' in os.environ or 'label_reader_token' in os.environ:raise SystemExit(94)
for flag,value in [('--private-out','FIXTURE_KEY'),('--public-out','FIXTURE_PUBLIC')]:
 p=pathlib.Path(sys.argv[sys.argv.index(flag)+1]);p.write_text(value);p.chmod(0o600)
''');go.chmod(0o700)
            package = root/'scripts/release_candidate_package.sh'
            package.write_text('''#!/usr/bin/python3
import os,pathlib,sys
assert os.environ['EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64']=='FIXTURE_KEY'
assert os.environ['EVYDENCE_RELEASE_SYFT']=='/qualified/scanner'
assert os.environ['EVYDENCE_RELEASE_ALLOW_EXISTING_TAG']=='1'
assert os.environ['GH_TOKEN']=='FIXTURE_READ_ONLY_TOKEN'
pathlib.Path('packaged').touch()
''');package.chmod(0o700)
            environment = dict(os.environ, PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],
                               RUNNER_TEMP=str(root), RELEASE_TAG='v0.0.0-rc.1404',
                               GH_TOKEN='FIXTURE_READ_ONLY_TOKEN',
                               EVYDENCE_RELEASE_SYFT='/qualified/scanner')
            for key,value in job.get('env',{}).items():
                if '${{' not in value: environment[key] = value
            result = subprocess.run(['bash','-c',script],cwd=root,env=environment,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue((root/'packaged').exists())
            self.assertEqual(list(root.glob('evydence-manifest-key.*')),[])

    def test_release_packager_provisions_both_required_live_dependencies(self):
        job = self.workflow('release-artifacts.yml')['jobs']['package']
        self.assertIn('EVYDENCE_TEST_S3_ENDPOINT', job['env'])
        setup = next(i for i,s in enumerate(job['steps']) if 'make local-minio-image' in s.get('run',''))
        package = next(i for i,s in enumerate(job['steps']) if s['name']=='Package signed release candidate')
        self.assertLess(setup,package)

    def run_validation(self, name, step_name, ref, tag):
        workflow = self.workflow(name)
        job = workflow['jobs']['publish-image' if name == 'container-image.yml' else 'package']
        script = next(step['run'] for step in job['steps'] if step['name'] == step_name)
        # Emulate runner expression interpolation only for the original exposed
        # inputs. The fixed workflow passes those values through the environment.
        for expression, value in [('github.event.inputs.ref', ref),
                                  ('github.event.inputs.image_tag', tag), ('github.event.inputs.tag', tag)]:
            script = script.replace('${{ ' + expression + ' }}', value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'injected'
            environment = dict(os.environ, INPUT_REF=ref, IMAGE_TAG=tag, INPUT_RELEASE_TAG=tag,
                                GITHUB_REPOSITORY='aatuh/evydence', GITHUB_REF_TYPE='branch',
                                GITHUB_OUTPUT=str(root / 'github-output'), MARKER=str(marker))
            result = subprocess.run(['bash', '-c', script], env=environment, cwd=root,
                                    capture_output=True, text=True, timeout=5)
            return result, marker.exists()

    def test_image_dispatch_inputs_never_execute_shell_substitutions(self):
        for ref, tag in [('$(touch "$MARKER")master', 'v0.0.0-rc.1403'),
                         ('master', 'v0.0.0-rc.1403$(touch "$MARKER")')]:
            with self.subTest(ref=ref, tag=tag):
                result, injected = self.run_validation('container-image.yml', 'Validate image inputs', ref, tag)
                self.assertFalse(injected)
                self.assertNotEqual(result.returncode, 0)

    def test_valid_image_inputs_remain_supported(self):
        result, injected = self.run_validation('container-image.yml', 'Validate image inputs',
                                                'refs/tags/v0.0.0-rc.1403', 'v0.0.0-rc.1403')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(injected)

    def test_release_tag_dispatch_never_executes_shell_substitutions(self):
        result, injected = self.run_validation('release-artifacts.yml', 'Resolve release tag',
                                                'master', 'v0.0.0-rc.1403$(touch "$MARKER")')
        self.assertFalse(injected)
        self.assertNotEqual(result.returncode, 0)

    def test_container_promotion_requires_verified_evidence_and_signing_uses_exact_source(self):
        jobs = self.workflow('container-image.yml')['jobs']
        steps = jobs['publish-image']['steps']
        generation = next(i for i, step in enumerate(steps) if step['name'] == 'Generate and verify image evidence')
        promotion = next(i for i, step in enumerate(steps) if step['name'] == 'Publish verified image tag')
        self.assertLess(generation, promotion)
        self.assertIn('container_evidence.py generate', steps[generation]['run'])
        self.assertIn('container_evidence.py verify', steps[generation]['run'])
        sign = jobs['sign-image']
        checkout = next(step for step in sign['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], '${{ needs.publish-image.outputs.commit }}')
        self.assertNotIn('contents: write', str(jobs))
        self.assertNotIn('packages: write', str(jobs))

    def test_release_publisher_rejects_different_tag_commit_and_never_clobbers_assets(self):
        job = self.workflow('release-artifacts.yml')['jobs']['publish-draft-release']
        script = next(step['run'] for step in job['steps'] if step['name'] == 'Create or update draft GitHub release')
        script = script.replace('${{ needs.package.outputs.tag }}', 'v0.0.0-rc.1403')
        for matching, draft in [(False, True), (True, True), (True, False)]:
            with self.subTest(matching=matching, draft=draft), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                gh = root / 'gh'
                gh.write_text('''#!/usr/bin/python3
import json,os,sys
with open(os.environ['GH_CALLS'],'a') as out:out.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='api':print(os.environ['TAG_COMMIT'])
elif sys.argv[1:3]==['release','view']:print(os.environ['IS_DRAFT'])
''')
                gh.chmod(0o700)
                calls = root / 'calls.jsonl'
                environment = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'], GH_CALLS=str(calls),
                    TAG_COMMIT=('a' if matching else 'b')*40, EXPECTED_COMMIT='a'*40,
                    IS_DRAFT='true' if draft else 'false',
                    RELEASE_TAG='v0.0.0-rc.1403', GITHUB_REPOSITORY='aatuh/evydence')
                result = subprocess.run(['bash','-c',script],cwd=root,env=environment,capture_output=True,text=True,timeout=5)
                commands = [json.loads(line) for line in calls.read_text().splitlines()]
                mutations = [args for args in commands if args[:2] in [['release','upload'],['release','create']]]
                if matching and draft:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(mutations), 1)
                    self.assertNotIn('--clobber', mutations[0])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(mutations, [])


if __name__ == '__main__':
    unittest.main()
