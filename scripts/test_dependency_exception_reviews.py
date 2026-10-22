#!/usr/bin/env python3
"""An exception needs a current owner-authored, exact-scope provider approval."""
import copy
from datetime import date
import json
import unittest

import dependency_exception_reviews as reviews
import dependency_admission as admission
from test_dependency_admission import Reader,API,BASE,MERGE,HEAD,collection,component

TODAY=date(2026,10,22)


def exception():
    return {'id':'DEP-0001','ecosystem':'npm','name':'lodash','version':'4.17.11','kind':'license',
            'value':'GPL-3.0-only','owner':'aatuh','reason':'Synthetic test, no actual approval.',
            'reviewed_on':'2026-10-21','expires_on':'2026-11-20',
            'review_url':'https://github.com/aatuh/evydence/pull/123#issuecomment-456'}


def rules():
    return {'schema':'evydence-dependency-policy.v1','allowed_licenses':['MIT'],'allowed_with':[],
            'exceptions':[exception()]}


def comment(row):
    return {'id':456,'html_url':row['review_url'],'issue_url':'https://api.github.com/repos/aatuh/evydence/issues/123',
            'user':{'login':'aatuh','type':'User'},'author_association':'OWNER',
            'body':json.dumps(reviews.approval_payload(row)),'created_at':'2026-10-20T00:00:00Z',
            'updated_at':'2026-10-21T00:00:00Z','performed_via_github_app':None}


class Provider:
    authenticated=True
    def __init__(self,data):self.data=data;self.calls=[]
    def get(self,endpoint):self.calls.append(endpoint);return copy.deepcopy(self.data)


class ReviewTests(unittest.TestCase):
    def test_owner_comment_binds_scope_without_self_referential_url_or_raw_body_export(self):
        value=rules();row=value['exceptions'][0];api=Provider(comment(row))
        proof=reviews.verify(value,api,TODAY)
        self.assertEqual(api.calls,['issues/comments/456']);self.assertEqual(proof[0]['exception_id'],'DEP-0001')
        self.assertEqual(proof[0]['reviewer'],'aatuh');self.assertNotIn('body',proof[0])
        changed={**row,'review_url':'https://github.com/aatuh/evydence/pull/124#issuecomment-999'}
        self.assertEqual(reviews.approval_payload(changed),reviews.approval_payload(row))
        self.assertEqual(reviews.verify({**value,'exceptions':[]},None,TODAY),[])

    def test_approved_pull_review_has_exact_parent_state_scope_and_submission_date(self):
        value=rules();row=value['exceptions'][0];row['review_url']='https://github.com/aatuh/evydence/pull/123#pullrequestreview-456'
        data=comment(row);data.update(state='APPROVED',submitted_at='2026-10-21T00:00:00Z',
            pull_request_url='https://api.github.com/repos/aatuh/evydence/pulls/123')
        api=Provider(data);self.assertEqual(len(reviews.verify(value,api,TODAY)),1)
        self.assertEqual(api.calls,['pulls/123/reviews/456'])
        for change in [{'state':'DISMISSED'},{'state':'PENDING'},{'submitted_at':None},
                       {'pull_request_url':'https://api.github.com/repos/other/repo/pulls/123'}]:
            with self.subTest(change=change),self.assertRaises(reviews.ReviewError):reviews.verify(value,Provider({**data,**change}),TODAY)

    def test_wrong_actor_edited_scope_forged_identity_or_review_date_cannot_activate_waiver(self):
        value=rules();data=comment(value['exceptions'][0])
        changes=[{'user':{'login':'attacker','type':'User'}},{'user':{'login':'aatuh','type':'Bot'}},
                 {'author_association':'NONE'},{'id':True},{'id':999},{'body':'PRIVATE_CANARY'},
                 {'html_url':'https://github.com/other/repo/pull/123#issuecomment-456'},
                 {'issue_url':'https://api.github.com/repos/aatuh/evydence/issues/124'},
                 {'updated_at':'2026-10-22T00:00:00Z'},{'created_at':'2026-10-22T00:00:00Z'},
                 {'performed_via_github_app':{'id':1}}]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(reviews.ReviewError) as error:
                reviews.verify(value,Provider({**data,**change}),TODAY)
            self.assertNotIn('CANARY',str(error.exception))

    def test_every_material_exception_field_is_bound_and_authentication_is_required(self):
        value=rules();data=comment(value['exceptions'][0])
        for field,replacement in [('expires_on','2026-11-21'),('reason','Different reason'),('owner','different-owner'),
                                  ('name','different-package'),('version','4.17.21'),('value','GPL-2.0-only'),('id','DEP-0002')]:
            changed=copy.deepcopy(value);changed['exceptions'][0][field]=replacement
            with self.subTest(field=field),self.assertRaises(reviews.ReviewError):reviews.verify(changed,Provider(data),TODAY)
        api=Provider(data);api.authenticated=False
        with self.assertRaises(reviews.ReviewError):reviews.verify(value,api,TODAY)
        with self.assertRaises(reviews.ReviewError):reviews.verify(value,None,TODAY)
        for reference in ['https://github.com/aatuh/evydence/pull/123',
                          'https://github.com/aatuh/evydence/commit/'+'a'*40,
                          'https://github.com/attacker/repo/pull/123#issuecomment-456']:
            changed=copy.deepcopy(value);changed['exceptions'][0]['review_url']=reference
            with self.subTest(reference=reference),self.assertRaises(reviews.ReviewError):reviews.verify(changed,Provider(data),TODAY)

    def test_verified_review_only_waives_its_exact_license_and_is_rechecked_after_decisions(self):
        value=rules();api=Provider(comment(value['exceptions'][0]))
        result=admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),
            collection(HEAD,[component(license='GPL-3.0-only')]),API(),TODAY,review_api=api)
        self.assertTrue(result['package_decision_passed']);self.assertEqual(result['changes'][0]['exceptions'],['DEP-0001'])
        self.assertEqual(len(result['exception_reviews']),1);self.assertEqual(len(api.calls),2)
        result=admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),
            collection(HEAD,[component(license='GPL-3.0-only')]),
            API(vulnerabilities=[{'id':'GHSA-aaaa-bbbb-cccc','severity':'critical'}]),TODAY,review_api=api)
        self.assertFalse(result['package_decision_passed'])
        class Changed(Provider):
            def get(self,endpoint):
                value=super().get(endpoint)
                if len(self.calls)>1:value['body']='revoked'
                return value
        with self.assertRaises(admission.AdmissionError):
            admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),
                collection(HEAD,[component(license='GPL-3.0-only')]),API(),TODAY,review_api=Changed(comment(value['exceptions'][0])))

    def test_expired_base_waiver_is_inactive_without_deadlocking_its_removal(self):
        value=rules();value['exceptions'][0].update(reviewed_on='2026-07-01',expires_on='2026-07-31')
        selected,proof=admission.load_policy(Reader(value),BASE,TODAY)
        self.assertEqual(selected['exceptions'],[]);self.assertEqual(proof['expired_exceptions'],['DEP-0001'])
        result=admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),collection(HEAD,[]),API(),TODAY)
        self.assertTrue(result['package_decision_passed'])
        result=admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),
            collection(HEAD,[component(license='GPL-3.0-only')]),API(),TODAY)
        self.assertFalse(result['package_decision_passed'])
        value['exceptions'][0]['expires_on']='2026-11-01'
        with self.assertRaises(admission.AdmissionError):admission.load_policy(Reader(value),BASE,TODAY)

    def test_revoked_unused_base_approval_does_not_deadlock_policy_cleanup(self):
        value=rules();api=Provider({**comment(value['exceptions'][0]),'body':'revoked'})
        result=admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),collection(HEAD,[]),API(),TODAY,review_api=api)
        self.assertTrue(result['package_decision_passed']);self.assertEqual(result['exception_reviews'],[]);self.assertEqual(api.calls,[])
        with self.assertRaises(admission.AdmissionError):
            admission.assess_changes(Reader(value),BASE,MERGE,HEAD,collection(MERGE,[]),
                collection(HEAD,[component(license='GPL-3.0-only')]),API(),TODAY,review_api=api)


if __name__=='__main__':unittest.main()
