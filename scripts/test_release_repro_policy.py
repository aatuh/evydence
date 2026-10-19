#!/usr/bin/env python3
"""Verify release jobs depend on actual independent build and byte-comparison jobs."""
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ReproducibilityPolicyTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)

    def test_distinct_hosted_jobs_build_without_caches_signing_secrets_or_publication(self):
        workflow = self.workflow('reproducible-builds.yml')
        self.assertIn('workflow_call', workflow['on'])
        self.assertIn('pull_request', workflow['on'])
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        job = workflow['jobs']['build']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['strategy']['matrix']['slot'], ['first', 'second'])
        self.assertEqual(job['strategy']['max-parallel'], '1')
        steps = job['steps']
        checkout = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
        setup = next(step for step in steps if step.get('uses', '').startswith('actions/setup-go@'))
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        self.assertEqual(setup['with']['cache'], 'false')
        run = '\n'.join(step.get('run', '') for step in steps)
        self.assertIn('scripts/reproducible_build.py build', run)
        self.assertIn('--expected-commit', run)
        self.assertIn('--bundle', run)
        self.assertIn('export GOCACHE=', run)
        self.assertNotIn('${{', run)
        self.assertNotIn('secrets.', str(workflow))
        self.assertNotIn('contents: write', str(workflow))

    def test_comparison_reads_both_bundles_and_keeps_failure_evidence(self):
        workflow = self.workflow('reproducible-builds.yml')
        job = workflow['jobs']['compare']
        self.assertEqual(job['needs'], 'build')
        run = '\n'.join(step.get('run', '') for step in job['steps'])
        self.assertIn('scripts/reproducible_build.py compare', run)
        self.assertIn('release-repro-first', run)
        self.assertIn('release-repro-second', run)
        self.assertIn('--output', run)
        uploads = [step for step in job['steps'] if step.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertTrue(any(step.get('if') == 'always()' for step in uploads))
        self.assertNotIn('continue-on-error', str(job))

    def test_signed_packaging_requires_successful_reusable_comparison(self):
        jobs = self.workflow('release-artifacts.yml')['jobs']
        self.assertEqual(jobs['verify-reproducible-builds']['uses'], './.github/workflows/reproducible-builds.yml')
        self.assertEqual(jobs['package']['needs'], 'verify-reproducible-builds')
        self.assertNotIn('always()', jobs['package'].get('if', ''))


if __name__ == '__main__':
    unittest.main()
