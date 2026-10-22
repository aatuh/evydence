#!/usr/bin/env python3
"""The required head result must come from trusted evaluation and a narrow reporter."""
from pathlib import Path
import re
import unittest

import dependency_actions as actions

ROOT=Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow=actions.document((ROOT/'.github/workflows/dependency-review.yml').read_bytes())

    def test_every_master_pr_uses_target_workflow_without_untrusted_filters_or_manual_override(self):
        trigger=self.workflow['on'];self.assertEqual(set(trigger),{'pull_request_target'})
        self.assertEqual(trigger['pull_request_target']['branches'],['master'])
        self.assertCountEqual(trigger['pull_request_target']['types'],['opened','synchronize','reopened','edited','ready_for_review'])
        self.assertEqual(set(trigger['pull_request_target']),{'branches','types'})
        self.assertEqual(self.workflow['permissions'],{'contents':'read'})

    def test_evaluation_has_read_only_credentials_and_only_checks_out_the_base_commit(self):
        job=self.workflow['jobs']['evaluate'];self.assertEqual(job['permissions'],{'contents':'read','pull-requests':'read'})
        steps=job['steps'];checkouts=[s for s in steps if s.get('uses','').startswith('actions/checkout@')]
        self.assertEqual(len(checkouts),1)
        self.assertEqual(checkouts[0]['with'],{'ref':'${{ github.event.pull_request.base.sha }}','persist-credentials':'false'})
        setup=next(s for s in steps if s.get('uses','').startswith('actions/setup-go@'))
        self.assertEqual(setup['with'],{'go-version-file':'go.mod','cache':'false'})
        for step in steps:
            self.assertNotIn('continue-on-error',step)
            if 'run' in step:self.assertNotIn('${{',step['run'])
            if 'uses' in step:self.assertRegex(step['uses'],r'^[A-Za-z0-9_./-]+@[0-9a-f]{40}$')
        self.assertTrue(any(s.get('run')=='make dependency-policy-check' for s in steps))
        self.assertEqual(job['outputs']['assessment_day'],'${{ steps.clock.outputs.day }}')
        clock=next(s for s in steps if s.get('id')=='clock')
        self.assertIn('date -u +%F',clock['run'])
        self.assertLess(steps.index(clock),next(i for i,s in enumerate(steps) if s.get('run')=='make dependency-policy-check'))
        scripts='\n'.join(s.get('run','') for s in steps)
        for unsafe in ['git fetch','gh pr checkout','npm install','make tools','go run']:
            self.assertNotIn(unsafe,scripts)

    def test_reporter_always_handles_failed_evaluation_with_only_narrow_write_authority(self):
        job=self.workflow['jobs']['report'];self.assertEqual(job['needs'],['evaluate'])
        self.assertIn('always()',job['if'])
        self.assertEqual(job['permissions'],{'contents':'read','pull-requests':'read','checks':'write'})
        script=next(s for s in job['steps'] if s.get('run')=='python3 scripts/dependency_check_publish.py')
        self.assertEqual(script['run'],'python3 scripts/dependency_check_publish.py')
        self.assertEqual(script['env']['DEPENDENCY_JOB_RESULT'],'${{ needs.evaluate.result }}')
        self.assertEqual(script['env']['DEPENDENCY_ASSESSMENT_DAY'],'${{ needs.evaluate.outputs.assessment_day }}')
        self.assertNotIn('${{',script['run'])
        checkout=next(s for s in job['steps'] if 'uses' in s)
        self.assertEqual(checkout['with']['ref'],'${{ github.event.pull_request.base.sha }}')
        self.assertEqual(checkout['with']['persist-credentials'],'false')
        bootstrap=next(s for s in job['steps'] if '--require-hashes --only-binary=:all:' in s.get('run',''))
        self.assertIn('tools/requirements-qa.txt',bootstrap['run'])
        self.assertNotIn('GH_TOKEN',bootstrap.get('env',{}))

    def test_fixed_report_upload_never_publishes_private_scratch_or_proposed_source(self):
        steps=self.workflow['jobs']['evaluate']['steps']
        upload=next(s for s in steps if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with']['path'],'tmp/dependency-review/report.json')
        self.assertEqual(upload['with']['retention-days'],'14')
        self.assertNotIn('secrets.',str(self.workflow))
        source=(ROOT/'Makefile').read_text();match=re.search(r'^dependency-policy-check:[^\n]*\n([^\n]+)',source,re.M)
        self.assertIsNotNone(match);self.assertEqual(match.group(1),'\t@python3 scripts/dependency_review.py --environment')


if __name__=='__main__':unittest.main()
