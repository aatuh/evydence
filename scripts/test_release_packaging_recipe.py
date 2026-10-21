#!/usr/bin/env python3
"""Exercise real packaging through archive creation with fake build/validation tools."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import release_artifacts
import release_evidence_tools
import change_fragments
import release_notes
import release_scanner
from test_change_fragments import fragment


ROOT = Path(__file__).resolve().parents[1]
TAG = 'v0.0.0-rc.1402'


class PackagingRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def checkout(self, name, with_notes=True, tag=TAG):
        root = self.root / name
        for filename in set(release_artifacts.BUILD_MATERIALS) | {
                'scripts/support_matrix.py', 'scripts/reproducible_build.py',
                'scripts/release_lifecycle.py', 'release/lifecycle-policy.json',
                'scripts/change_fragments.py', 'scripts/release_history.py',
                'scripts/release_change_provider.py', 'scripts/release_notes.py',
                'release/current.json',
                'docs/reference/release-notes-template.md',
                'LICENSE', 'README.md', 'CHANGELOG.md'}:
            output = root / filename
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / filename, output)
        (root / 'migrations').mkdir()
        (root / 'migrations/001_fixture.sql').write_text('SELECT 1;\n')
        # Stop after real archives/manifest are produced, before any signing.
        (root / 'scripts/release_evidence_metadata.py').write_text(
            'from pathlib import Path\nPath("artifact-phase-finished").write_text("yes")\nraise SystemExit(91)\n')
        (root / 'bin').mkdir()
        programs = {
            'syft': '''import json,sys
if sys.argv[1:] != ['version','-o','json']:raise SystemExit(92)
print(json.dumps({'application':'syft','version':'1.54.1','gitCommit':'b254e6d92f28c3868a755f62fb3ca8f26e9fee76','goVersion':'GO_VERSION_FIXTURE','platform':'linux/amd64'}))
''',
            'git': '''import os,sys
from pathlib import Path
a=sys.argv[1:]
changed=Path('source-changed').exists()
mode=Path('source-change-mode').read_text() if Path('source-change-mode').exists() else ''
if a==['rev-parse','--verify','HEAD'] and changed and mode=='head':print('b'*40)
elif a==['status','--porcelain','--untracked-files=all'] and changed:
 if mode=='git-error':raise SystemExit(93)
 if mode=='dirty':print(' M source.go')
 else:os.execv(REAL_GIT,['git',*a])
else:os.execv(REAL_GIT,['git',*a])
'''.replace('REAL_GIT', repr(shutil.which('git'))),
            'go': '''import json,os,sys
from pathlib import Path
a=sys.argv[1:]
if a==['env','GOVERSION']:print('GO_VERSION_FIXTURE')
elif a and a[0]=='build':
 with open('build-requests.jsonl','a') as out:out.write(json.dumps({'args':a,'goos':os.environ.get('GOOS'),'goarch':os.environ.get('GOARCH'),'cgo':os.environ.get('CGO_ENABLED'),'goflags':os.environ.get('GOFLAGS'),'experiment':os.environ.get('GOEXPERIMENT'),'secret_present':any(k in os.environ for k in ['GH_TOKEN','EVYDENCE_TEST_DATABASE_URL','EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64'])})+'\\n')
 target=Path(a[a.index('-o')+1]);target.parent.mkdir(parents=True,exist_ok=True)
 target.write_bytes(('fixture '+a[-1]+' '+a[a.index('-ldflags')+1]).encode())
 if Path('candidate-change').exists() and 'release-candidate' in str(target):
  target.write_bytes(target.read_bytes()+b' DIFFERENT_FINAL_BUILD')
 if Path('source-change-mode').exists():Path('source-changed').write_text('yes')
else:raise SystemExit(92)
''',
            'make': '''import json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/'scripts'))
import release_artifacts,reproducible_build,support_matrix
arguments=[item for item in sys.argv[1:] if not item.startswith('--')]
if arguments[0]=='production-check':
 if any(key in os.environ for key in ['EVYDENCE_RELEASE_SYFT','EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64','EVYDENCE_RELEASE_ALLOW_EXISTING_TAG']):raise SystemExit(94)
 Path('coverage.out').write_text('fixture coverage')
 Path('tmp').mkdir(exist_ok=True)
 Path('tmp/release-check-summary.txt').write_text('fixture validation')
elif arguments[0]=='reproducible-build-check':
 head=subprocess.check_output(['git','rev-parse','--verify','HEAD'],text=True).strip()
 tag=next(item.split('=',1)[1] for item in arguments if item.startswith('TAG='))
 bundle=Path('tmp/repro-reference')
 result=subprocess.run([sys.executable,'scripts/release_build.py','--tag',tag,
   '--output',str(bundle/'archives'),'--work',str(bundle/'work'),'--expected-commit',head])
 if result.returncode:raise SystemExit(result.returncode)
 manifest=json.loads((bundle/'work/release-build-manifest.json').read_text())
 report={'schema_version':reproducible_build.REPORT_SCHEMA,'source_commit':head,'tag':tag,
         'source_date_epoch':manifest['source_date_epoch'],'go_version':manifest['go_version'],
         'build_recipe_version':release_artifacts.RECIPE_VERSION,
         'artifacts':reproducible_build.artifact_inventory(bundle,support_matrix.load_policy(),tag)}
 (bundle/reproducible_build.REPORT_NAME).write_text(json.dumps(report))
 comparison=reproducible_build.compare_bundles(bundle,bundle,tag,head)
 assert comparison['passed']
 comparison.setdefault('verified_artifacts',report['artifacts'])
 comparison.setdefault('go_version',manifest['go_version'])
 comparison.setdefault('build_recipe_version',manifest['build_recipe_version'])
 comparison.setdefault('source_date_epoch',manifest['source_date_epoch'])
 print(json.dumps(comparison))
else:raise SystemExit(92)
''',
        }
        for name, code in programs.items():
            path = root / 'bin' / name
            path.write_text('#!' + sys.executable + '\n' + code.replace('GO_VERSION_FIXTURE', release_scanner.SCANNER_GO_VERSION))
            path.chmod(0o700)
        (root / 'bin/installation.json').write_text(json.dumps({
            'schema': 'evydence-release-tool.v1', 'recipe_sha256': release_evidence_tools.recipe_digest(),
            'binary_sha256': hashlib.sha256((root / 'bin/syft').read_bytes()).hexdigest(),
        }))
        environment = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                           GOFLAGS='-tags=PRIVATE', GOEXPERIMENT='PRIVATE', GH_TOKEN='PRIVATE_SECRET',
                           EVYDENCE_TEST_DATABASE_URL='unused-fixture',
                           EVYDENCE_RELEASE_SYFT=str(root / 'bin/syft'),
                           EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64=base64.b64encode(bytes(64)).decode())
        environment.pop('EVYDENCE_CHANGELOG_PULL_REQUEST', None)
        self.initialize_history(root, environment, with_notes, tag)
        return root, environment

    def initialize_history(self, root, environment, with_notes, tag):
        """Run real note checks against deterministic local Git, never fake success."""
        git_environment = dict(environment, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                               GIT_AUTHOR_NAME='fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                               GIT_COMMITTER_NAME='fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                               GIT_AUTHOR_DATE='2023-11-14T22:13:20Z', GIT_COMMITTER_DATE='2023-11-14T22:13:20Z')
        def git(*arguments):
            result = subprocess.run([shutil.which('git'), '-c', 'core.hooksPath=' + os.devnull, *arguments],
                                    cwd=root, env=git_environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        (root / '.gitignore').write_text('bin/\ndist/\ntmp/\ncoverage.out\n__pycache__/\n'
                                         'build-requests.jsonl\nsource-change-mode\nsource-changed\n'
                                         'candidate-change\nartifact-phase-finished\n')
        (root / 'CHANGELOG.md').write_text('# Changelog\n\n## Unreleased\n\n- Earlier fixture source work.\n\n')
        git('init', '--initial-branch=master')
        git('add', '--all'); git('commit', '--quiet', '--message', 'feat: released fixture source')
        released = git('rev-parse', 'HEAD')
        (root / 'release/current.json').write_text(json.dumps({'repository': 'aatuh/evydence',
            'current_public_release': {'tag': 'v0.0.0-rc.1', 'source_commit': released}}))
        git('add', '--all'); git('commit', '--quiet', '--message', 'feat: adoption fixture source')
        adoption = git('rev-parse', 'HEAD')
        body = change_fragments.section((root / 'CHANGELOG.md').read_text(), 'Unreleased')[0]
        policy = {'schema': 'evydence-change-policy.v1', 'adoption_commit': adoption,
                  'legacy_release_commit': released, 'legacy_section_sha256': hashlib.sha256(body.encode()).hexdigest()}
        (root / 'changes/fragments').mkdir(parents=True)
        (root / 'changes/policy.json').write_text(json.dumps(policy))
        value = fragment()
        (root / 'changes/fragments' / (value['id'] + '.json')).write_text(json.dumps(value))
        plan = release_notes.history.inspect(root)
        (root / 'CHANGELOG.md').write_text(change_fragments.update_changelog(
            plan['changelog'], plan['fragments'], policy, plan['include_legacy']))
        if with_notes:
            (root / ('docs/reference/release-notes-' + tag + '.md')).write_text(release_notes.generate(root, tag))
        git('add', '--all'); git('commit', '--quiet', '--message', 'feat: reviewed fixture notes')

    def test_missing_notes_stop_before_expensive_validation_and_preserve_existing_artifacts(self):
        root, environment = self.checkout('missing-notes', with_notes=False)
        target = root / 'dist' / TAG / 'existing-evidence.txt'
        target.parent.mkdir(parents=True)
        target.write_text('preserve previous evidence')
        result = self.run_package(root, environment)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((root / 'coverage.out').exists())
        self.assertFalse((root / 'artifact-phase-finished').exists())
        self.assertEqual(target.read_text(), 'preserve previous evidence')

    def test_missing_or_substituted_scanner_stops_before_expensive_validation(self):
        for mode in ['missing', 'substituted']:
            with self.subTest(mode=mode):
                root, environment = self.checkout('preflight-' + mode)
                if mode == 'missing':
                    del environment['EVYDENCE_RELEASE_SYFT']
                else:
                    with (root / 'bin/syft').open('ab') as output:
                        output.write(b'\n# substituted scanner\n')
                result = self.run_package(root, environment)
                self.assertEqual(result.returncode, 2)
                self.assertFalse((root / 'coverage.out').exists())
                self.assertFalse((root / 'artifact-phase-finished').exists())

    def run_package(self, root, environment):
        return subprocess.run(['bash', str(root / 'scripts/release_candidate_package.sh'), TAG],
                              cwd=root, env=environment, capture_output=True, text=True, timeout=20)

    def test_packaging_wires_fixed_manifest_and_identical_archives_from_different_roots(self):
        first, first_env = self.checkout('PRIVATE_FIRST')
        second, second_env = self.checkout('PRIVATE_SECOND')
        for root, environment in [(first, first_env), (second, second_env)]:
            result = self.run_package(root, environment)
            self.assertEqual(result.returncode, 91, result.stderr)
            self.assertTrue((root / 'artifact-phase-finished').is_file())
        a = first / 'dist' / TAG
        b = second / 'dist' / TAG
        manifest = json.loads((a / 'release-build-manifest.json').read_text())
        self.assertEqual(manifest['build_time'], '2023-11-14T22:13:20Z')
        self.assertEqual(manifest['source_date_epoch'], 1700000000)
        self.assertNotIn('PRIVATE', json.dumps(manifest))
        self.assertEqual((a / 'release-build-manifest.json').read_bytes(), (b / 'release-build-manifest.json').read_bytes())
        archives = sorted([*a.glob('*.tar.gz'), *a.glob('*.zip')])
        self.assertEqual(len(archives), 5)
        for archive in archives:
            self.assertEqual(archive.read_bytes(), (b / archive.name).read_bytes(), archive.name)
        builds = [json.loads(line) for line in (first / 'build-requests.jsonl').read_text().splitlines()]
        final_builds = [request for request in builds
                        if 'release-candidate' in request['args'][request['args'].index('-o') + 1]]
        self.assertEqual(len(final_builds), 8)
        self.assertEqual(len(builds), 16)  # Eight reference fixtures, then eight actual package payloads.
        for request in builds:
            self.assertIn('-trimpath', request['args'])
            self.assertIn('-buildvcs=false', request['args'])
            self.assertIn('-buildid=', request['args'][request['args'].index('-ldflags') + 1])
            self.assertEqual(request['cgo'], '0')
            self.assertEqual(request['goflags'], '-p=1')
            self.assertEqual(request['experiment'], '')
            self.assertFalse(request['secret_present'])

    def test_source_changes_during_build_stop_before_evidence_or_signing(self):
        for mode in ['head', 'dirty', 'git-error']:
            with self.subTest(mode=mode):
                root, environment = self.checkout(mode)
                (root / 'source-change-mode').write_text(mode)
                result = self.run_package(root, environment)
                self.assertEqual(result.returncode, 93 if mode == 'git-error' else 2, result.stderr)
                self.assertFalse((root / 'artifact-phase-finished').exists())
                self.assertFalse((root / 'dist' / TAG / 'evydence-release-manifest.sig.json').exists())

    def test_mismatching_final_payload_stops_before_evidence_or_signing(self):
        root, environment = self.checkout('different-final-payload')
        (root / 'candidate-change').write_text('different final build')
        result = self.run_package(root, environment)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((root / 'artifact-phase-finished').exists())
        self.assertFalse((root / 'dist' / TAG / 'evydence-release-manifest.sig.json').exists())


if __name__ == '__main__':
    unittest.main()
