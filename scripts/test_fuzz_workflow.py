#!/usr/bin/env python3
"""Protect untrusted-source execution and the public fuzz artifact boundary."""
from pathlib import Path
import os
import re
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import patch

import dependency_actions as actions

ROOT = Path(__file__).resolve().parents[1]


class FuzzWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = actions.document((ROOT / '.github/workflows/fuzz.yml').read_bytes())

    def test_all_prs_and_scheduled_master_have_no_privileged_trigger(self):
        trigger = self.workflow['on']
        self.assertEqual(set(trigger), {'pull_request', 'push', 'schedule'})
        self.assertEqual(trigger['pull_request'], {'branches': ['master']})
        self.assertEqual(trigger['push'], {'branches': ['master']})
        self.assertEqual(len(trigger['schedule']), 1)
        self.assertEqual(self.workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', str(self.workflow))

    def test_serial_hard_memory_time_and_worker_limits(self):
        self.assertEqual(set(self.workflow['jobs']), {'fuzz'})
        job = self.workflow['jobs']['fuzz']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], '45')
        self.assertNotIn('strategy', job)
        self.assertNotIn('environment', job)
        step = next(s for s in job['steps'] if s.get('name') == 'Run bounded foreground fuzz work')
        run = step['run']
        subprocess.run(['bash', '-n'], input=run, text=True, check=True)
        for bound in ('systemd-run --scope', 'MemoryMax=4096M', 'MemorySwapMax=0',
                      '/usr/bin/setpriv', '--reset-env', '--no-new-privs'):
            self.assertIn(bound, run)
        for unsafe in ('--no-block', 'nohup', 'sudo python', 'sudo make', 'eval ', '${{'):
            self.assertNotIn(unsafe, run)
        self.assertIn('schedule) mode=campaign', run)
        self.assertIn('pull_request|push) mode=smoke', run)
        self.assertNotIn('runuser', run)
        self.assertIn('--clear-groups', run)
        self.assertIn('--bounding-set=-all', run)

    def test_actual_scope_limits_are_verified_before_driver_exec(self):
        run = next(s['run'] for s in self.workflow['jobs']['fuzz']['steps'] if s.get('name') == 'Run bounded foreground fuzz work')
        match = re.search(r"/usr/bin/python3 -c '(.*?)' \"\$mode\"", run, re.S)
        self.assertIsNotNone(match)
        program = textwrap.dedent(match[1])
        group = '/system.slice/evydence-fuzz-123-1.scope'
        base = '/sys/fs/cgroup' + group
        for cap, swap, selected, succeeds in [('4294967296', '0', group, True),
                                              ('max', '0', group, False),
                                              ('4294967296', '1', group, False),
                                              ('4294967296', '0', '/user.slice/session-1.scope', False)]:
            with self.subTest(cap=cap, swap=swap, group=selected):
                files = {'/proc/self/cgroup': '0::' + selected + '\n',
                         base + '/memory.max': cap + '\n', base + '/memory.swap.max': swap + '\n'}
                with patch.object(Path, 'read_text', lambda path: files[str(path)]), patch.object(os, 'execv') as execute, patch.object(sys, 'argv', ['-c', 'campaign']):
                    if succeeds:
                        exec(compile(program, '<fuzz-ci>', 'exec'), {})
                        self.assertEqual(execute.call_count, 1)
                        arguments = execute.call_args.args[1]
                        self.assertEqual(arguments[1:3], ['scripts/fuzz_driver.py', 'campaign'])
                        self.assertEqual(arguments[3:], ['--seconds', '30', '--timeout', '600', '--budget', '2400'])
                    else:
                        with self.assertRaises(SystemExit):
                            exec(compile(program, '<fuzz-ci>', 'exec'), {})
                        execute.assert_not_called()

    def test_pins_checkout_and_upload_only_permitted_public_outputs(self):
        steps = self.workflow['jobs']['fuzz']['steps']
        for step in steps:
            self.assertNotIn('continue-on-error', step)
            if 'uses' in step:
                self.assertRegex(step['uses'], r'^[A-Za-z0-9_./-]+@[0-9a-f]{40}$')
        checkout = next(s for s in steps if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        setup = next(s for s in steps if s.get('uses', '').startswith('actions/setup-go@'))
        self.assertEqual(setup['with'], {'go-version-file': 'go.mod', 'cache': 'false'})
        upload = next(s for s in steps if s.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['if'], '${{ always() }}')
        self.assertEqual(upload['with']['path'], 'tmp/fuzz/*/public/')
        self.assertEqual(upload['with']['retention-days'], '14')
        self.assertIn('github.sha', upload['with']['name'])


if __name__ == '__main__':
    unittest.main()
