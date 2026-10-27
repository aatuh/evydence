#!/usr/bin/env python3
"""The synchronous worker must retain its oracles and bounded input protocol."""
import base64
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import tooling_fuzz_properties as properties


WORKER = Path(__file__).resolve().with_name('tooling_fuzz.py')


class ToolingWorkerTests(unittest.TestCase):
    def test_bounded_corrupt_deflate_reaches_the_real_archive_owner(self):
        raw = bytes.fromhex('1f8b08000000000002ff') + b'\xff' + bytes(8)
        self.assertTrue(properties.archive_within_budget(raw, False))
        accepted, _ = properties.archives(raw, 0)
        self.assertFalse(accepted)

    def test_archive_preflight_rejects_observed_expansion_over_budget(self):
        raw = gzip.compress(b'x' * (128 * 1024 + 1), mtime=0)
        self.assertLess(len(raw), 4096)
        self.assertFalse(properties.archive_within_budget(raw, False))

    def test_repeatability_oracle_checks_nested_values_without_recursion(self):
        left, right, changed = 0, 0, False
        for _ in range(2000):
            left, right, changed = [left], [right], [changed]
        self.assertTrue(properties.same_json(left, right))
        self.assertFalse(properties.same_json(left, changed))
        self.assertFalse(properties.same_json({'value': 1}, {'value': 2}))

    def invoke(self, request, *, owner='backup', optimized=False, stream=False):
        with tempfile.TemporaryDirectory() as scratch:
            command = [sys.executable, '-I', '-B']
            if optimized:
                command.append('-O')
            arguments = ['--stream'] if stream else []
            body = ''.join(json.dumps(value) + '\n' for value in request) if stream else json.dumps(request)
            return subprocess.run(
                [*command, str(WORKER), '--owner', owner, *arguments],
                input=body, text=True, capture_output=True, timeout=10,
                cwd=scratch, env={'PATH': str(Path(sys.executable).parent), 'TMPDIR': scratch, 'LANG': 'C.UTF-8'},
            )

    def test_stream_preserves_fresh_fixtures_and_one_report_per_request(self):
        requests = [{'raw': '', 'mode': mode, 'seed': True} for mode in (0, 3, 6)]
        result = self.invoke(requests, stream=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        reports = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(reports), len(requests))
        for report in reports:
            self.assertEqual((report['owner'], report['status'], report['accepted']), ('backup', 'passed', False))
        self.assertEqual(reports[0]['seed'], reports[2]['seed'])

    def test_stream_budget_is_enforced_before_a_second_report(self):
        requests = [{'raw': '', 'mode': 0, 'seed': False},
                    {'raw': 'x' * (20 * 1024), 'mode': 0, 'seed': False}]
        result = self.invoke(requests, stream=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertIn('property request exceeds its budget', result.stderr)

    def test_optimized_interpreter_cannot_disable_properties(self):
        for stream in (False, True):
            request = {'raw': '', 'mode': 0, 'seed': True}
            result = self.invoke([request] if stream else request, optimized=True, stream=stream)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertIn('assertions must be enabled', result.stderr)

    def test_invalid_protocol_cannot_reach_a_property_or_echo_payload(self):
        cases = [None, [], {'raw': 'SENSITIVE_CANARY'},
                 {'raw': '', 'mode': True, 'seed': False},
                 {'raw': '', 'mode': 256, 'seed': False},
                 {'raw': base64.b64encode(b'x' * 4097).decode(), 'mode': 0, 'seed': False}]
        for request in cases:
            with self.subTest(request_type=type(request).__name__):
                result = self.invoke(request)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('SENSITIVE_CANARY', result.stderr)

    def test_every_owner_returns_a_bounded_synthetic_or_public_seed(self):
        for owner in ('evidence', 'checksums', 'archives', 'signing', 'backup'):
            with self.subTest(owner=owner):
                result = self.invoke({'raw': '', 'mode': 0, 'seed': True}, owner=owner)
                self.assertEqual(result.returncode, 0, result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual(set(value), {'owner', 'status', 'accepted', 'seed'})
                self.assertEqual((value['owner'], value['status']), (owner, 'passed'))
                self.assertGreater(len(base64.b64decode(value['seed'], validate=True)), 0)
                self.assertLessEqual(len(base64.b64decode(value['seed'], validate=True)), 4096)


if __name__ == '__main__':
    unittest.main()
