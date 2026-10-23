#!/usr/bin/env python3
"""Only a trusted completed evaluation may publish the exact current PR head check."""
import copy
from datetime import datetime,timezone
import json
import unittest
from unittest.mock import Mock,patch

import dependency_check_publish as publish
from test_dependency_admission import BASE,HEAD
from test_dependency_review_provider import pull


def environment():
    return {'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'pull_request_target',
        'GITHUB_REPOSITORY':'aatuh/evydence','GITHUB_REF':'refs/heads/master','GITHUB_SHA':BASE,
        'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','DEPENDENCY_PULL_REQUEST':'30',
        'DEPENDENCY_TARGET_BASE':BASE,'DEPENDENCY_SOURCE_COMMIT':HEAD,
        'DEPENDENCY_HEAD_REPOSITORY':'contributor/fork','DEPENDENCY_JOB_RESULT':'success'}


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.clock=patch.object(publish,'datetime');mock=self.clock.start()
        mock.now.return_value=datetime(2026,10,22,12,tzinfo=timezone.utc);self.addCleanup(self.clock.stop)
    def api(self):
        api=Mock();value=pull();value['base']['sha']=BASE;value['head']['sha']=HEAD
        api.get.return_value=value
        return api

    def post(self,payload):
        return json.dumps({**payload,'id':999,'app':{'slug':'github-actions','id':15368}}).encode()

    def test_success_and_all_nonpassing_outcomes_are_bound_to_the_exact_current_head(self):
        for outcome in ['success','failure','cancelled','skipped']:
            with self.subTest(outcome=outcome):
                env=environment();env['DEPENDENCY_JOB_RESULT']=outcome;env['DEPENDENCY_ASSESSMENT_DAY']='2026-10-22';api=self.api();calls=[]
                def send(payload):calls.append(payload);return self.post(payload)
                result=publish.run(env,api,post=send)
                payload=calls[0];self.assertEqual(payload['head_sha'],HEAD)
                self.assertEqual(payload['conclusion'],'success' if outcome=='success' else 'failure')
                self.assertEqual(payload['name'],'Dependency Policy');self.assertEqual(payload['status'],'completed')
                self.assertIn(BASE,payload['external_id']);self.assertIn('123',payload['details_url'])
                self.assertEqual(result['check_id'],999);api.get.assert_called_once_with('pulls/30')

    def test_midnight_or_missing_assessment_day_cannot_publish_an_expired_success(self):
        for day in [None,'2026-10-21','2026-10-23','PRIVATE_CANARY']:
            env=environment()
            if day is not None:env['DEPENDENCY_ASSESSMENT_DAY']=day
            calls=[]
            def send(payload):calls.append(payload);return self.post(payload)
            with self.subTest(day=day):
                result=publish.run(env,self.api(),post=send)
                self.assertEqual(result['conclusion'],'failure');self.assertEqual(calls[0]['conclusion'],'failure')
                self.assertNotIn('CANARY',json.dumps(calls))

    def test_local_non_target_untrusted_ref_run_or_forged_outcome_never_writes(self):
        mutations=[('GITHUB_ACTIONS','false'),('GITHUB_EVENT_NAME','pull_request'),
            ('GITHUB_REPOSITORY','contributor/fork'),('GITHUB_REF','refs/pull/30/merge'),('GITHUB_SHA',HEAD),
            ('GITHUB_RUN_ID','PRIVATE_CANARY'),('DEPENDENCY_JOB_RESULT','neutral'),('DEPENDENCY_TARGET_BASE','bad'),
            ('DEPENDENCY_SOURCE_COMMIT','PRIVATE_CANARY'),('DEPENDENCY_PULL_REQUEST','0')]
        for key,value in mutations:
            env=environment();env[key]=value;post=Mock()
            with self.subTest(key=key),self.assertRaises(publish.PublishError) as error:publish.run(env,self.api(),post=post)
            post.assert_not_called();self.assertNotIn('CANARY',str(error.exception))

    def test_stale_base_head_repository_or_closed_pr_cannot_publish_a_new_success(self):
        for reason in ['base','head','repository','closed']:
            api=self.api();value=api.get.return_value
            if reason=='base':value['base']['sha']='f'*40
            if reason=='head':value['head']['sha']='f'*40
            if reason=='repository':value['head']['repo']['full_name']='other/fork'
            if reason=='closed':value['state']='closed';value['merged']=True
            post=Mock()
            with self.subTest(reason=reason),self.assertRaises(publish.PublishError):publish.run(environment(),api,post=post)
            post.assert_not_called()

    def test_provider_response_identity_and_actions_app_binding_are_verified(self):
        for key,value in [('head_sha',BASE),('conclusion','neutral'),('name','other'),('id',True),
                          ('app',{'slug':'other','id':15368}),('app',{'slug':'github-actions','id':99})]:
            def send(payload):return json.dumps({**payload,'id':999,'app':{'slug':'github-actions','id':15368},key:value}).encode()
            with self.subTest(key=key),self.assertRaises(publish.PublishError):publish.run(environment(),self.api(),post=send)

    def test_writer_posts_fixed_endpoint_json_stdin_without_ambient_command_execution_or_secrets(self):
        env={**environment(),'PATH':'/usr/bin','HOME':'/private/home','GH_TOKEN':'PRIVATE_CANARY',
             'UNRELATED_SECRET':'PRIVATE_CANARY'}
        with patch.dict(publish.os.environ,env,clear=True),patch.object(publish.inventory,'_run',return_value=b'{}') as run:
            publish.post_check({'head_sha':HEAD,'output':{'summary':'literal $(do not execute)'}})
        args=run.call_args.args;self.assertEqual(args[0][-1],'repos/aatuh/evydence/check-runs')
        self.assertIn('--input',args[0]);self.assertEqual(json.loads(run.call_args.kwargs['data'])['head_sha'],HEAD)
        self.assertNotIn('UNRELATED_SECRET',args[2]);self.assertNotIn('CANARY',str(args[0]))


if __name__=='__main__':unittest.main()
