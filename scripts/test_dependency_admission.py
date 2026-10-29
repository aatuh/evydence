#!/usr/bin/env python3
"""Current-target policy and exact component changes must govern admission."""
import copy
from datetime import date,datetime,timezone
import hashlib
import json
from pathlib import Path
import unittest

import dependency_admission as admission
import dependency_advisories as advisories
import dependency_git_objects as objects
import dependency_exception_reviews as reviews

BASE='a'*40; MERGE='b'*40; HEAD='c'*40; TODAY=date(2026,10,22)
RULES={'schema':'evydence-dependency-policy.v1','allowed_licenses':['MIT'],'allowed_with':[],'exceptions':[]}

# Exact material approved by owner GitHub records on 2026-10-29.
# Expiry remains 2026-11-27; authenticated live verification remains mandatory.
# This offline pin does not replace authenticated live review verification.
# Entries may be removed; new or renewed material requires a new review.
REVIEWED_EXCEPTION_MATERIAL = {
    'DEP-121301': '1b583a3f9e35a9aea7d0e3a27f655e2a4bd584bd6cd9f9413edf5f712e1ba552',
    'DEP-121302': 'a7603b1aff04952f06a6884e10d6d1329ce1d6d6cfe673bbba7c0232ec10d2fe',
    'DEP-121303': '92bdf38764e86a7bb81f7adc348fd69b6a95aa5caf5e9dd1d299aacd26025c4f',
    'DEP-121304': 'd3d6a1defed19cf0e545a9d47bd57e05118e9d77cf36a2759e7117b030b7b4a0',
    'DEP-121305': '8ec731b5141fb97f9c799fb38a7a34c64705b0840c6ed481fe3c3a2c765fcea1',
    'DEP-121306': '8427de5e9520e8738f7c2907e2e5d7ff3ea47d9cb8e724ff54d4891843e6ab34',
}



class Reader:
    def __init__(self,rules=None):self.rules=copy.deepcopy(RULES if rules is None else rules);self.requests=[]
    def tree(self,commit):
        self.requests.append(commit)
        rules=self.rules if commit==BASE else {**RULES,'allowed_licenses':['MIT','GPL-3.0-only']}
        self.raw=json.dumps(rules).encode()
        return 'd'*40,{admission.POLICY_PATH:{'type':'blob','mode':'100644','sha':objects.object_id('blob',self.raw)}}
    def blob(self,_identity):return self.raw


def component(**changes):
    return {'ecosystem':'npm','name':'lodash','version':'4.17.11','license':'MIT','license_status':'artifact-declared',
            'origins':['marketing'],'source':{'verification':'sha512-verified','sha256':'d'*64},**changes}


def collection(commit,rows):
    return {'schema':'evydence-dependency-collection.v1','trusted_base':BASE,'source_bytes_verified':True,
            'source':{'commit':commit},'inventory':{'schema':'evydence-dependency-inventory.v1','components':rows}}


class API:
    def __init__(self,status='observed',vulnerabilities=None):self.calls=[];self.receipts=[];self.status=status;self.vulnerabilities=[] if vulnerabilities is None else vulnerabilities
    def observe(self,row):
        coords=advisories.identity(row);self.calls.append(coords)
        return {'component':coords,'status':self.status,'vulnerabilities':self.vulnerabilities if self.status=='observed' else None,'receipt_indexes':[]}


def assess(before,after,api=None,reader=None):
    return admission.assess_changes(reader or Reader(),BASE,MERGE,HEAD,
        collection(MERGE,before),collection(HEAD,after),api or API(),TODAY)


class PolicyTests(unittest.TestCase):
    def test_policy_comes_only_from_current_target_and_bytes_are_verified(self):
        reader=Reader();rules,source=admission.load_policy(reader,BASE,TODAY)
        self.assertEqual(reader.requests,[BASE]);self.assertEqual(rules,RULES)
        self.assertEqual(source['commit'],BASE);self.assertEqual(source['sha256'],hashlib.sha256(reader.raw).hexdigest())
        reader=Reader();original=reader.blob;reader.blob=lambda identity:original(identity)+b'PRIVATE_CANARY'
        with self.assertRaises(admission.AdmissionError) as error:admission.load_policy(reader,BASE,TODAY)
        self.assertNotIn('CANARY',str(error.exception))
        for entries in [{},{admission.POLICY_PATH:{'type':'blob','mode':'120000','sha':'e'*40}}]:
            reader=Reader();reader.tree=lambda _commit:('d'*40,entries)
            with self.subTest(entries=entries),self.assertRaises(admission.AdmissionError):admission.load_policy(reader,BASE,TODAY)

    def test_head_or_merge_base_policy_cannot_approve_a_disallowed_addition(self):
        reader=Reader();result=assess([], [component(license='GPL-3.0-only')],reader=reader)
        self.assertFalse(result['package_decision_passed']);self.assertEqual(reader.requests,[BASE])
        self.assertIn('disallowed_license',result['changes'][0]['violations'])
        self.assertFalse(result['dependency_coverage_verified'])
        with self.assertRaises(admission.AdmissionError):
            admission.assess_changes(Reader(),HEAD,MERGE,HEAD,collection(MERGE,[]),collection(HEAD,[]),API(),TODAY)

    def test_repository_policy_is_strict_and_has_no_invented_exceptions(self):
        raw=(Path(__file__).parents[1]/admission.POLICY_PATH).read_bytes()
        rules=admission.policy.validate_policy(admission.policy.parse_document(raw),datetime.now(timezone.utc).date())
        for entry in rules['exceptions']:
            with self.subTest(exception_id=entry['id']):
                self.assertIn(entry['id'],REVIEWED_EXCEPTION_MATERIAL)
                self.assertEqual(reviews.approval_payload(entry)['exception_sha256'],
                                 REVIEWED_EXCEPTION_MATERIAL[entry['id']])
                self.assertRegex(entry['review_url'],
                    r'\Ahttps://github\.com/aatuh/evydence/pull/54#issuecomment-[1-9][0-9]*\Z')
        self.assertTrue(admission.policy.license_allowed('MIT AND Apache-2.0',rules))
        self.assertFalse(admission.policy.license_allowed('GPL-3.0-only',rules))

    def test_exception_syntax_cannot_substitute_for_provider_verified_review(self):
        rules=copy.deepcopy(RULES);rules['exceptions']=[{'id':'DEP-0001','ecosystem':'npm','name':'lodash','version':'4.17.11',
            'kind':'license','value':'GPL-3.0-only','owner':'aatuh','reason':'Synthetic fixture, no actual approval.',
            'reviewed_on':'2026-10-21','expires_on':'2026-11-20','review_url':'https://github.com/aatuh/evydence/pull/123'}]
        with self.assertRaises(admission.AdmissionError):assess([], [component(license='GPL-3.0-only')],reader=Reader(rules))


class DecisionTests(unittest.TestCase):
    def test_additions_metadata_changes_and_new_origins_are_checked_but_removals_are_not_admitted(self):
        api=API();value=component();result=assess([value],[copy.deepcopy(value)],api)
        self.assertTrue(result['package_decision_passed']);self.assertEqual(api.calls,[])
        for changed in [component(version='4.17.21'),component(license='GPL-3.0-only'),
                        component(origins=['application','marketing']),component(source={'sha256':'e'*64})]:
            with self.subTest(changed=changed):
                api=API();result=assess([value],[changed],api)
                self.assertEqual(len(result['changes']),1);self.assertEqual(len(api.calls),1)
        api=API();result=assess([component(origins=['application','marketing'])],[value],api)
        self.assertEqual(api.calls,[])
        result=assess([component(license='GPL-3.0-only')],[],api)
        self.assertTrue(result['package_decision_passed']);self.assertEqual(len(result['removed']),1)

    def test_high_critical_unknown_and_unavailable_advisories_block_and_low_is_not_a_safety_claim(self):
        for severity in ['low','moderate','high','critical','unknown']:
            result=assess([], [component()],API(vulnerabilities=[{'id':'GHSA-aaaa-bbbb-cccc','severity':severity}]))
            self.assertEqual(result['package_decision_passed'],severity in {'low','moderate'})
            self.assertFalse(result['dependency_coverage_verified'])
        for status in ['unsupported','unavailable']:
            result=assess([], [component()],API(status))
            self.assertFalse(result['package_decision_passed']);self.assertIsNone(result['changes'][0]['vulnerabilities'])
            self.assertEqual(result['changes'][0]['violations'],['advisory_coverage_unknown'])

    def test_missing_license_or_invalid_provenance_does_not_pass(self):
        for changes in [{'license':None},{'license_status':'unknown'}]:
            self.assertFalse(assess([], [component(**changes)])['package_decision_passed'])
        for operation in ['source','trusted-base','verified','duplicate','origins']:
            before=collection(MERGE,[]);after=collection(HEAD,[component()])
            if operation=='source':after['source']['commit']='f'*40
            if operation=='trusted-base':after['trusted_base']=MERGE
            if operation=='verified':after['source_bytes_verified']=False
            if operation=='duplicate':after['inventory']['components'].append(component())
            if operation=='origins':after['inventory']['components'][0]['origins']=['PRIVATE_CANARY\n']
            with self.subTest(operation=operation),self.assertRaises(admission.AdmissionError) as error:
                admission.assess_changes(Reader(),BASE,MERGE,HEAD,before,after,API(),TODAY)
            self.assertNotIn('CANARY',str(error.exception))

    def test_advisory_response_cannot_be_rebound_to_another_package_or_hide_missing_findings(self):
        class Wrong(API):
            def observe(self,row):return {'component':{**advisories.identity(row),'version':'other'},'status':'observed','vulnerabilities':[]}
        with self.assertRaises(admission.AdmissionError):assess([], [component()],Wrong())
        class UnboundData(API):
            def observe(self,row):return {'component':advisories.identity(row),'status':'not-applicable-data-fixture',
                                         'profile':'utf8-test-data.v1','vulnerabilities':None}
        with self.assertRaises(admission.AdmissionError):assess([], [component()],UnboundData())
        for findings in [None,[],[{'id':'GHSA-aaaa-bbbb-cccc','severity':'high'}]]:
            api=API();api.vulnerabilities=findings
            if findings is None:
                with self.assertRaises(admission.AdmissionError):assess([], [component()],api)
            else:self.assertEqual(assess([], [component()],api)['package_decision_passed'],not findings)


if __name__=='__main__':unittest.main()
