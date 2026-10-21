#!/usr/bin/env python3
"""Release lifecycle policy and safe-default regression tests."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('release_lifecycle.py')
SPEC = importlib.util.spec_from_file_location('release_lifecycle', SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('cannot load lifecycle checker')
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)


def policy():
    return {
        'schema': 'evydence-release-lifecycle.v1',
        'security_support': {
            'development_ref': 'refs/heads/master',
            'release_selector': 'current_public_release',
            'window': {'starts': 'publication', 'ends': 'superseded-or-withdrawn'},
            'older_releases': 'best-effort-unless-commercial-agreement',
            'response_sla': None,
            'fixed_end_date': None,
        },
        'withdrawals': [],
    }


def metadata():
    return {'repository': 'aatuh/evydence', 'current_public_release': {
        'tag': 'v1.2.3-rc.1', 'source_commit': 'a' * 40,
    }}


def withdrawal(tag='v1.2.3-rc.1'):
    return {'tag': tag, 'source_commit': 'a' * 40,
            'recorded_at': '2026-10-21T00:00:00Z',
            'reason': 'Broken upgrade path; preserve historical evidence.',
            'notice_url': 'https://github.com/aatuh/evydence/releases/tag/' + tag,
            'replacement_tag': None}


class ReleaseLifecycleTests(unittest.TestCase):
    def fixture(self, root, withdrawn=False):
        (root / 'release').mkdir()
        p = policy()
        if withdrawn:
            p['withdrawals'] = [withdrawal()]
        (root / 'release/lifecycle-policy.json').write_text(json.dumps(p))
        (root / 'release/current.json').write_text(json.dumps(metadata()))

    def test_generated_reference_is_checked_and_never_follows_a_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            (root / 'docs/reference').mkdir(parents=True)
            path = root / 'docs/reference/release-support.md'
            expected = LIFECYCLE.render_reference(policy(), metadata())
            path.write_text(expected)
            command = [sys.executable, str(SCRIPT), '--root', folder, 'check', '--reference']
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            path.write_text('stale NEVER_ECHO_THIS_PRIVATE_CANARY')
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('NEVER_ECHO_THIS_PRIVATE_CANARY', result.stdout + result.stderr)
            path.unlink()
            target = root / 'other.md'
            target.write_text(expected)
            path.symlink_to(target)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)

    def test_valid_withdrawal_without_replacement_can_be_checked_and_rendered(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root, withdrawn=True)
            p = policy()
            p['withdrawals'] = [withdrawal()]
            (root / 'docs/reference').mkdir(parents=True)
            (root / 'docs/reference/release-support.md').write_text(
                LIFECYCLE.render_reference(p, metadata()))
            checked = subprocess.run([sys.executable, str(SCRIPT), '--root', folder,
                                      'check', '--reference'], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            default = subprocess.run([sys.executable, str(SCRIPT), '--root', folder,
                                      'default-tag'], capture_output=True, text=True)
            self.assertEqual(default.returncode, 2)
            self.assertEqual(default.stdout, '')

    def test_current_release_has_an_event_window_without_invented_sla(self):
        p = LIFECYCLE.validate_policy(policy())
        self.assertEqual(LIFECYCLE.default_tag(p, metadata()), 'v1.2.3-rc.1')
        text = LIFECYCLE.render_reference(p, metadata())
        self.assertIn('superseded or withdrawn', text)
        self.assertIn('best effort', text)
        self.assertIn('No fixed security support end date or response SLA', text)

    def test_withdrawal_blocks_default_and_explicit_use_but_remains_visible(self):
        p = policy()
        p['withdrawals'] = [withdrawal()]
        p = LIFECYCLE.validate_policy(p)
        with self.assertRaises(LIFECYCLE.PolicyError):
            LIFECYCLE.default_tag(p, metadata())
        with self.assertRaises(LIFECYCLE.PolicyError):
            LIFECYCLE.assert_not_withdrawn(p, 'v1.2.3-rc.1')
        text = LIFECYCLE.render_reference(p, metadata())
        self.assertIn('WITHDRAWN', text)
        self.assertIn('Broken upgrade path', text)
        self.assertIn('No default install', text)

    def test_replacement_does_not_silently_override_current_release_metadata(self):
        p = policy()
        w = withdrawal()
        w['replacement_tag'] = 'v1.2.3-rc.2'
        p['withdrawals'] = [w]
        p = LIFECYCLE.validate_policy(p)
        with self.assertRaises(LIFECYCLE.PolicyError):
            LIFECYCLE.default_tag(p, metadata())
        m = metadata()
        m['current_public_release'] = {'tag': 'v1.2.3-rc.2', 'source_commit': 'b' * 40}
        self.assertEqual(LIFECYCLE.default_tag(p, m), 'v1.2.3-rc.2')

    def test_rejects_conflicting_duplicate_and_unsafe_withdrawal_data(self):
        for mutate in [
            lambda p: p.update(schema='unknown'),
            lambda p: p.update(unexpected=True),
            lambda p: p['security_support'].update(response_sla='one hour'),
            lambda p: p['withdrawals'].append(copy.deepcopy(p['withdrawals'][0])),
            lambda p: p['withdrawals'][0].update(tag='../../escape'),
            lambda p: p['withdrawals'][0].update(source_commit='bad'),
            lambda p: p['withdrawals'][0].update(recorded_at='2026-02-30T00:00:00Z'),
            lambda p: p['withdrawals'][0].update(notice_url='https://github.com.attacker.test/notice'),
            lambda p: p['withdrawals'][0].update(notice_url='https://secret@github.com/aatuh/evydence/issues/1'),
            lambda p: p['withdrawals'][0].update(reason='secret\x1b[2J'),
            lambda p: p['withdrawals'][0].update(reason='invalid\ud800'),
            lambda p: p['withdrawals'][0].update(reason='spoof\u0085line'),
            lambda p: p['withdrawals'][0].update(reason='spoof\u202eorder'),
            lambda p: p['withdrawals'][0].update(replacement_tag='v1.2.3-rc.1'),
        ]:
            p = policy()
            p['withdrawals'] = [withdrawal()]
            mutate(p)
            with self.subTest(policy=p), self.assertRaises(LIFECYCLE.PolicyError):
                LIFECYCLE.validate_policy(p)

    def test_withdrawn_replacement_is_rejected(self):
        p = policy()
        p['withdrawals'] = [withdrawal(), withdrawal('v1.2.3-rc.2')]
        p['withdrawals'][0]['replacement_tag'] = 'v1.2.3-rc.2'
        with self.assertRaises(LIFECYCLE.PolicyError):
            LIFECYCLE.validate_policy(p)

    def test_current_withdrawal_cannot_claim_a_conflicting_source(self):
        p = policy()
        p['withdrawals'] = [withdrawal()]
        p['withdrawals'][0]['source_commit'] = 'b' * 40
        with self.assertRaises(LIFECYCLE.PolicyError):
            LIFECYCLE.render_reference(p, metadata())

    def test_public_history_escapes_html_links_and_table_delimiters(self):
        p = policy()
        p['withdrawals'] = [withdrawal()]
        p['withdrawals'][0]['reason'] = '<img src=x> | [click](javascript:unsafe)'
        text = LIFECYCLE.render_reference(p, metadata())
        self.assertNotIn('<img', text)
        self.assertNotIn('[click](javascript:', text)
        self.assertIn('\\|', text)

    def test_public_error_never_echoes_invalid_tag_or_policy_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'release').mkdir()
            (root / 'release/lifecycle-policy.json').write_text(json.dumps(policy()))
            (root / 'release/current.json').write_text(json.dumps(metadata()))
            result = subprocess.run([sys.executable, str(SCRIPT), '--root', folder,
                                     'check-tag', 'private-token-$(touch canary)'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('private-token', result.stdout + result.stderr)
            self.assertFalse((root / 'canary').exists())

    def test_duplicate_json_keys_and_symlinked_policy_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'release').mkdir()
            (root / 'release/current.json').write_text(json.dumps(metadata()))
            path = root / 'release/lifecycle-policy.json'
            path.write_text('{"schema":"one","schema":"two"}')
            result = subprocess.run([sys.executable, str(SCRIPT), '--root', folder, 'check'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            outside = root / 'private.env'
            outside.write_text(json.dumps(policy()))
            path.unlink()
            path.symlink_to(outside)
            result = subprocess.run([sys.executable, str(SCRIPT), '--root', folder, 'check'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_parent_symlink_valid_metadata_cannot_escape_the_selected_tree(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            root = Path(folder)
            external = Path(outside)
            (external / 'lifecycle-policy.json').write_text(json.dumps(policy()))
            (external / 'current.json').write_text(json.dumps(metadata()))
            (root / 'release').symlink_to(external, target_is_directory=True)
            result = subprocess.run([sys.executable, str(SCRIPT), '--root', folder, 'check'],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 2)

    def test_bounded_reader_rejects_absolute_and_parent_traversal_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            root = parent / 'tree'
            root.mkdir()
            outside = parent / 'private.json'
            outside.write_text(json.dumps(policy()))
            for path in [str(outside), '../private.json', '']:
                with self.subTest(path=path), self.assertRaises(LIFECYCLE.PolicyError):
                    LIFECYCLE.read_json(root, path)

    def test_oversized_nonfinite_and_nonregular_metadata_fail_without_raw_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'release').mkdir()
            (root / 'release/current.json').write_text(json.dumps(metadata()))
            path = root / 'release/lifecycle-policy.json'
            bodies = [
                json.dumps({'private': 'NEVER_ECHO_THIS_PRIVATE_CANARY', 'data': 'x' * LIFECYCLE.MAX_JSON_BYTES}),
                '{"private":"NEVER_ECHO_THIS_PRIVATE_CANARY","number":NaN}',
                '[' * 2000 + '0' + ']' * 2000,
            ]
            for body in bodies:
                path.write_text(body)
                result = subprocess.run([sys.executable, str(SCRIPT), '--root', folder, 'check'],
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('NEVER_ECHO_THIS_PRIVATE_CANARY', result.stdout + result.stderr)
                self.assertNotIn('Traceback', result.stderr)
            path.unlink()
            os.mkfifo(path)
            result = subprocess.run([sys.executable, str(SCRIPT), '--root', folder, 'check'],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 2)

    def shell_fixture(self, root, name, withdrawn=False):
        self.fixture(root, withdrawn)
        (root / 'scripts').mkdir()
        for script in [name, 'release_lifecycle.py']:
            shutil.copyfile(SCRIPT.parent / script, root / 'scripts' / script)
        (root / 'bin').mkdir()
        for binary in ['go', 'gh']:
            path = root / 'bin' / binary
            path.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$LIFECYCLE_CANARY"\nexit 91\n')
            path.chmod(0o700)
        env = dict(os.environ)
        env.pop('TAG', None)
        env.pop('EVYDENCE_RELEASE_REPO', None)
        env['PATH'] = str(root / 'bin') + os.pathsep + env['PATH']
        env['LIFECYCLE_CANARY'] = str(root / 'executed')
        env['EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64'] = 'PRIVATE_KEY_MUST_NOT_APPEAR'
        return env

    def test_withdrawn_tag_stops_download_and_packaging_before_side_effects(self):
        for name, arguments in [('public_release_verify.sh', []),
                                ('public_release_verify.sh', ['v1.2.3-rc.1']),
                                ('release_candidate_package.sh', ['v1.2.3-rc.1'])]:
            with self.subTest(script=name, arguments=arguments), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                env = self.shell_fixture(root, name, withdrawn=True)
                result = subprocess.run(['bash', str(root / 'scripts' / name), *arguments],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn('withdrawn', result.stderr)
                self.assertFalse((root / 'executed').exists())
                self.assertFalse((root / 'dist').exists())
                self.assertNotIn('PRIVATE_KEY_MUST_NOT_APPEAR', result.stdout + result.stderr)

    def test_active_default_is_selected_from_metadata_before_the_downloader(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = self.shell_fixture(root, 'public_release_verify.sh')
            result = subprocess.run(['bash', str(root / 'scripts/public_release_verify.sh')],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 91)
            self.assertIn('release download v1.2.3-rc.1 ', (root / 'executed').read_text())

    def test_metadata_children_never_receive_parent_release_or_provider_credentials(self):
        for name, args in [('public_release_verify.sh', []),
                           ('public_release_verify.sh', ['v1.2.3-rc.1']),
                           ('release_candidate_package.sh', ['v1.2.3-rc.1'])]:
            with self.subTest(script=name, args=args), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                env = self.shell_fixture(root, name, withdrawn=True)
                env.update(GH_TOKEN='PRIVATE_PROVIDER_CANARY',
                           AWS_SECRET_ACCESS_KEY='PRIVATE_PROVIDER_CANARY',
                           EVYDENCE_DATABASE_URL='PRIVATE_DATABASE_CANARY')
                script = root / 'scripts/release_lifecycle.py'
                actual = root / 'scripts/actual_lifecycle.py'
                script.rename(actual)
                leak = root / 'metadata-credential-leak'
                script.write_text('import os,pathlib,runpy\n'
                    'if any(k in os.environ for k in ["GH_TOKEN","AWS_SECRET_ACCESS_KEY",'
                    '"EVYDENCE_DATABASE_URL","EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64"]):\n'
                    ' pathlib.Path(' + repr(str(leak)) + ').touch()\n'
                    'runpy.run_path(' + repr(str(actual)) + ',run_name="__main__")\n')
                result = subprocess.run(['bash', str(root / 'scripts' / name), *args],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn('withdrawn', result.stderr)
                self.assertFalse(leak.exists(), 'metadata child inherited credentials')


if __name__ == '__main__':
    unittest.main()
