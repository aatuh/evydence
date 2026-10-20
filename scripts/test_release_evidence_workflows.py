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
