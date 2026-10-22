#!/usr/bin/env python3
"""Trusted review orchestration must bind every stage and never pass partial work."""
import copy
from datetime import datetime,timezone
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import dependency_review as review
import dependency_image_admission as image_admission
import dependency_action_advisories as action_advisories
from test_dependency_admission import BASE,HEAD,RULES,collection
from test_dependency_collection import revision
from test_dependency_review_provider import pull
from test_dependency_exception_reviews import rules as exception_rules


class ReviewTests(unittest.TestCase):
    def setup_job(self):
        snapshot={'schema':review.provider.SCHEMA,'repository':'aatuh/evydence','pull_request':30,
            'base':BASE,'comparison_base':BASE,'head':HEAD,'head_repository':'contributor/fork','changed_files':2,
            'provider_authenticated':True,'file_listing_verified':True,'dependency_rows':[],'receipts':[]}
        api=Mock();api.snapshot.return_value=snapshot
        raw=pull();raw['base']['sha']=BASE;raw['head']['sha']=HEAD;api.get.return_value=raw;api.receipts=[]
        return api,snapshot

    def operation(self,root,api,*,join_result=None,missing=False):
        def read(_reader,commit):
            observed,contents=revision();observed['commit']=commit
            if missing:observed['missing_required']=['go:go.sum']
            return observed,contents
        def collect(_reader,base,source,*_args,**_kwargs):
            value=collection(source,[]);value['inventory']['remaining_scopes']=['images'];return value
        artifact=Mock();artifact.receipt={'trusted_base':BASE}
        result={'package_decision_passed':True,'dependency_coverage_verified':False} if join_result is None else join_result
        patches=[patch.object(review.objects,'RemoteGit',return_value=object()),
            patch.object(review.admission,'load_policy',return_value=(RULES,{})),
            patch.object(review.inputs,'revision',side_effect=read),
            patch.object(review.classifiers,'build',return_value=artifact),
            patch.object(review.collection,'collect',side_effect=collect),patch.object(review.join,'assess',return_value=result),
            patch.object(image_admission,'assess',return_value={'image_decision_passed':False,
                'image_coverage_verified':False,'coverage_gaps':['qualified-scanner-unavailable'],'exception_reviews':[]})]
        handles=[item.start() for item in patches]
        self.addCleanup(lambda:[item.stop() for item in reversed(patches)])
        return handles,artifact

    def test_serial_collections_share_one_base_artifact_and_partial_result_stays_failed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,snapshot=self.setup_job();handles,artifact=self.operation(root,api)
            result=review.run(api,30,BASE,HEAD,'contributor/fork',root,{})
            handles[3].assert_called_once();self.assertEqual(handles[4].call_count,2)
            self.assertIs(handles[4].call_args_list[0].kwargs['classifier'],artifact)
            self.assertIs(handles[4].call_args_list[1].kwargs['classifier'],artifact)
            self.assertEqual(handles[4].call_args_list[0].args[2],BASE);self.assertEqual(handles[4].call_args_list[1].args[2],HEAD)
            self.assertFalse(result['passed']);self.assertFalse(result['dependency_coverage_verified'])
            self.assertIn('source:images',result['coverage_gaps'])
            self.assertEqual(handles[5].call_args.kwargs['review_api'],api)
            self.assertNotIn(str(root),str(result))

    def test_missing_inputs_or_outdated_source_stop_before_classifier_and_collections(self):
        for reason in ['missing','outdated','unauthenticated']:
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);api,snapshot=self.setup_job();handles,_=self.operation(root,api,missing=reason=='missing')
                if reason=='outdated':snapshot['comparison_base']='f'*40
                if reason=='unauthenticated':snapshot['provider_authenticated']=False
                with self.assertRaises(review.ReviewError):review.run(api,30,BASE,HEAD,'contributor/fork',root,{})
                handles[3].assert_not_called();handles[4].assert_not_called()
                self.doCleanups()

    def test_image_verdict_and_coverage_are_required_and_share_trusted_context_and_advisory_client(self):
        for passed in [False,True]:
            with self.subTest(passed=passed),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);api,_=self.setup_job()
                handles,_=self.operation(root,api,join_result={'package_decision_passed':True,'dependency_coverage_verified':True})
                handles[6].return_value={'image_decision_passed':passed,'image_coverage_verified':True,
                                        'coverage_gaps':[],'exception_reviews':[]}
                syft=root/'qualified-syft';result=review.run(api,30,BASE,HEAD,'contributor/fork',root,{},syft=syft)
                self.assertEqual(result['passed'],passed);self.assertNotIn('source:images',result['coverage_gaps'])
                self.assertIs(handles[5].call_args.args[8],handles[6].call_args.args[7])
                self.assertEqual(handles[6].call_args.args[1:3],(BASE,HEAD))
                self.assertEqual(handles[6].call_args.kwargs['syft'],syft)
                self.assertIs(handles[6].call_args.kwargs['review_api'],api)
                self.doCleanups()

    def test_missing_image_coverage_cannot_pass_even_without_a_source_scope_marker(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,_=self.setup_job()
            handles,_=self.operation(root,api,join_result={'package_decision_passed':True,'dependency_coverage_verified':True})
            def collect(_reader,base,source,*_args,**_kwargs):
                value=collection(source,[]);value['inventory']['remaining_scopes']=[];return value
            handles[4].side_effect=collect
            handles[6].return_value={'image_decision_passed':True,'image_coverage_verified':False,
                                    'coverage_gaps':[],'exception_reviews':[]}
            result=review.run(api,30,BASE,HEAD,'contributor/fork',root,{})
            self.assertFalse(result['passed']);self.assertFalse(result['dependency_coverage_verified'])

    def test_image_approval_cannot_be_omitted_from_the_final_live_recheck(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,_=self.setup_job()
            handles,_=self.operation(root,api,join_result={'package_decision_passed':True,'dependency_coverage_verified':True})
            handles[6].return_value={'image_decision_passed':True,'image_coverage_verified':True,'coverage_gaps':[],
                                    'exception_reviews':[{'exception_id':'DEP-0001'}]}
            with self.assertRaises(review.ReviewError):review.run(api,30,BASE,HEAD,'contributor/fork',root,{})

    def test_changed_action_tag_binding_cannot_write_a_review_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,_=self.setup_job();self.operation(root,api)
            args=['--root',str(root),'--pull-request','30','--base',BASE,'--head',HEAD,
                  '--head-repository','contributor/fork','--work-root',str(root),'--output','report.json']
            with patch.object(review.provider,'GitHub',return_value=api), \
                 patch.object(action_advisories.Client,'verify',side_effect=action_advisories.ActionAdvisoryError()), \
                 patch.object(review.sys,'stderr',io.StringIO()):
                self.assertEqual(review.main(args),2)
            self.assertFalse((root/'report.json').exists())

    def test_policy_failure_is_not_replaced_with_a_head_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,_=self.setup_job();handles,_=self.operation(root,api)
            handles[1].side_effect=review.admission.AdmissionError()
            with self.assertRaises(review.ReviewError):review.run(api,30,BASE,HEAD,'contributor/fork',root,{})
            handles[1].assert_called_once();self.assertEqual(handles[1].call_args.args[1],BASE)
            handles[3].assert_not_called();handles[4].assert_not_called()

    def test_cleanup_removes_revoked_base_waiver_while_new_unreviewed_proposal_stops_before_build(self):
        for cleanup in [True,False]:
            with self.subTest(cleanup=cleanup),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);api,_=self.setup_job();handles,_=self.operation(root,api)
                def load(_reader,commit,_today):
                    value=exception_rules() if (commit==BASE)==cleanup else copy.deepcopy(RULES)
                    return value,{'commit':commit,'expired_exceptions':[]}
                handles[1].side_effect=load
                if cleanup:
                    result=review.run(api,30,BASE,HEAD,'contributor/fork',root,{})
                    self.assertEqual(result['proposed_policy']['commit'],HEAD);self.assertEqual(result['proposed_policy_reviews'],[])
                    self.assertTrue(all(call.args[0]=='pulls/30' for call in api.get.call_args_list))
                else:
                    with self.assertRaises(review.ReviewError):review.run(api,30,BASE,HEAD,'contributor/fork',root,{})
                    handles[3].assert_not_called()
                self.doCleanups()

    def test_live_run_crossing_the_utc_expiry_day_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,_=self.setup_job();self.operation(root,api)
            with patch.object(review,'datetime') as clock:
                clock.now.side_effect=[datetime(2026,10,22,23,59,tzinfo=timezone.utc),datetime(2026,10,23,0,1,tzinfo=timezone.utc)]
                with self.assertRaises(review.ReviewError):review.run(api,30,BASE,HEAD,'contributor/fork',root,{})

    def test_final_pr_head_change_cannot_write_output_or_succeed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);api,_=self.setup_job();self.operation(root,api)
            api.get.return_value['head']['sha']='f'*40
            args=['--root',str(root),'--pull-request','30','--base',BASE,'--head',HEAD,
                  '--head-repository','contributor/fork','--work-root',str(root),'--output','report.json']
            with patch.object(review.provider,'GitHub',return_value=api),patch.object(review.sys,'stderr',io.StringIO()):
                self.assertEqual(review.main(args),2)
            self.assertFalse((root/'report.json').exists())

    def test_cli_preserves_owner_output_before_provider_work_and_partial_observations_exit_one(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);output=root/'report.json';output.write_text('PRIVATE_CANARY owner file')
            args=['--root',str(root),'--pull-request','30','--base',BASE,'--head',HEAD,
                  '--head-repository','contributor/fork','--work-root',str(root),'--output','report.json','--replace']
            with patch.object(review.provider,'GitHub') as api,patch.object(review.sys,'stderr',io.StringIO()):
                self.assertEqual(review.main(args),2)
            api.assert_not_called();self.assertIn('CANARY',output.read_text());output.unlink()
            api,_=self.setup_job();self.operation(root,api)
            with patch.object(review.provider,'GitHub',return_value=api):self.assertEqual(review.main(args[:-1]),1)
            self.assertTrue(output.exists())


if __name__=='__main__':unittest.main()
