#!/usr/bin/env python3
"""Data applicability needs immutable inert payloads; licenses still apply."""
import copy
from datetime import date
import hashlib
import json
import unittest

import dependency_fixture_advisories as fixtures
import dependency_git_objects as objects
from test_dependency_admission import BASE,MERGE,HEAD,Reader,API,RULES,collection

TODAY=date(2026,10,22)
PATH='scripts/testdata/lint-policy/example.go.txt'
NOTICE='testdata/licenses/example.LICENSE'


def context(raw=b'package example\n',*,mode='100644',license='MIT'):
    contents={PATH:raw,NOTICE:b'MIT license fixture\n'}
    tree={path:{'type':'blob','mode':mode if path==PATH else '100644',
                'sha':objects.object_id('blob',value)} for path,value in contents.items()}
    files=[{'path':path,'mode':tree[path]['mode'],'git_blob':tree[path]['sha'],
            'sha256':hashlib.sha256(value).hexdigest(),'bytes':len(value)} for path,value in contents.items()]
    row={'ecosystem':'fixture','name':'example','version':hashlib.sha256(raw).hexdigest(),'origins':['fixtures'],
         'license':license,'license_status':'recorded-declaration','license_evidence':[],
         'source':{'kind':'project','verification':'local-digests-checked','files':[{'path':PATH,'sha256':files[0]['sha256']}],
                   'notices':['example']},
         'license_notices':[{'id':'example','license':license,'path':NOTICE,'sha256':files[1]['sha256'],'source':None}]}
    observed=collection(HEAD,[row]);observed['source'].update(tree='d'*40,files=files)
    observed['inventory']['inputs']={path:hashlib.sha256(value).hexdigest() for path,value in contents.items()}
    class SourceReader(Reader):
        def tree(self,commit):
            if commit==HEAD:return 'd'*40,tree
            return super().tree(commit)
        def blob(self,identity):
            for value in contents.values():
                if objects.object_id('blob',value)==identity:return value
            return super().blob(identity)
    return SourceReader(),observed,row,contents,tree


class ApplicabilityTests(unittest.TestCase):
    def test_bound_data_has_null_findings_explicit_applicability_and_no_payload_output(self):
        reader,observed,row,_,_=context(b'package PRIVATE_CANARY\n')
        result=fixtures.observe(reader,observed,row)
        self.assertEqual(result['status'],'not-applicable-data-fixture')
        self.assertIsNone(result['vulnerabilities']);self.assertEqual(result['profile'],'utf8-test-data.v1')
        self.assertEqual(result['source_commit'],HEAD);self.assertEqual(len(result['files']),1)
        self.assertNotIn('PRIVATE_CANARY',json.dumps(result))

    def test_malformed_parser_fragments_remain_data_without_becoming_executable(self):
        reader,observed,row,contents,tree=context(b'{"intentionally": "unfinished')
        old=PATH;new='scripts/testdata/parser/invalid.fragment'
        contents[new]=contents.pop(old);tree[new]=tree.pop(old)
        for item in observed['source']['files']:
            if item['path']==old:item['path']=new
        observed['inventory']['inputs'][new]=observed['inventory']['inputs'].pop(old)
        row['source']['files'][0]['path']=new
        self.assertEqual(fixtures.observe(reader,observed,row)['status'],'not-applicable-data-fixture')

    def test_original_executable_symlink_binary_and_script_payloads_cannot_claim_data_applicability(self):
        for mode,raw in [('100755',b'{}'),('120000',b'target'),('100644',b'\x7fELFpayload'),
                         ('100644',b'{}\0PRIVATE_CANARY'),('100644',b'\xef\xbb\xbf \n#!/bin/sh\necho PRIVATE_CANARY'),
                         ('100644',b'\xff')]:
            reader,observed,row,_,_=context(raw,mode=mode)
            with self.subTest(mode=mode,raw=raw),self.assertRaises(fixtures.FixtureError) as error:
                fixtures.observe(reader,observed,row)
            self.assertNotIn('CANARY',str(error.exception))

    def test_unclassified_or_executable_suffix_cannot_use_data_profile(self):
        for new in ['scripts/testdata/example.sh','scripts/testdata/example.go','outside/example.json','testdata/licenses/example.json']:
            reader,observed,row,contents,tree=context()
            contents[new]=contents.pop(PATH);tree[new]=tree.pop(PATH)
            observed['source']['files'][0]['path']=new
            observed['inventory']['inputs'][new]=observed['inventory']['inputs'].pop(PATH)
            row['source']['files'][0]['path']=new
            with self.subTest(path=new),self.assertRaises(fixtures.FixtureError):fixtures.observe(reader,observed,row)

    def test_source_bytes_modes_collection_and_combined_version_must_remain_bound(self):
        for operation in ['blob','sha','mode','tree','version','input','unverified','source','duplicate']:
            reader,observed,row,contents,tree=context()
            if operation=='blob':contents[PATH]+=b'PRIVATE_CANARY'
            if operation=='sha':row['source']['files'][0]['sha256']='f'*64
            if operation=='mode':observed['source']['files'][0]['mode']='100755'
            if operation=='tree':observed['source']['tree']='e'*40
            if operation=='version':row['version']='f'*64
            if operation=='input':observed['inventory']['inputs'][PATH]='f'*64
            if operation=='unverified':observed['source_bytes_verified']=False
            if operation=='source':row['source']['verification']='unchecked'
            if operation=='duplicate':row['source']['files'].append(copy.deepcopy(row['source']['files'][0]))
            with self.subTest(operation=operation),self.assertRaises(fixtures.FixtureError):fixtures.observe(reader,observed,row)

    def test_notices_need_exact_coverage_and_source_bytes(self):
        for operation in ['missing','extra','unbound','license','bytes']:
            reader,observed,row,contents,_=context()
            if operation=='missing':row['license_notices']=[]
            if operation=='extra':row['source']['notices'].append('other')
            if operation=='unbound':row['license_notices'][0]['sha256']='f'*64
            if operation=='license':row['license_notices'][0]['license']='Apache-2.0'
            if operation=='bytes':contents[NOTICE]+=b'PRIVATE_CANARY'
            with self.subTest(operation=operation),self.assertRaises(fixtures.FixtureError):fixtures.observe(reader,observed,row)

    def test_missing_origins_licenses_and_changed_collector_rows_do_not_gain_profile(self):
        for changes in [{'origins':['application']},{'license_status':'unknown'},{'ecosystem':'npm'}]:
            reader,observed,row,_,_=context();row.update(changes)
            with self.subTest(changes=changes),self.assertRaises(fixtures.FixtureError):fixtures.observe(reader,observed,row)
        reader,observed,row,_,_=context();detached=copy.deepcopy(row);detached['name']='other'
        with self.assertRaises(fixtures.FixtureError):fixtures.observe(reader,observed,detached)


class AdmissionTests(unittest.TestCase):
    def test_provider_required_rows_cannot_claim_unverified_data_applicability(self):
        import dependency_admission as admission
        reader,observed,row,_,_=context()
        class UnboundData(API):
            required_components={tuple(fixtures.advisories.identity(row).values())}
            def observe(self,value):return {'component':fixtures.advisories.identity(value),'status':'not-applicable-data-fixture',
                                            'profile':'utf8-test-data.v1','vulnerabilities':None}
        with self.assertRaises(admission.AdmissionError):
            admission.assess_changes(reader,BASE,MERGE,HEAD,collection(MERGE,[]),observed,UnboundData(),TODAY)

    def test_data_addition_does_not_query_advisories_but_disallowed_license_still_blocks(self):
        import dependency_admission as admission
        for license,passes in [('MIT',True),('GPL-3.0-only',False)]:
            reader,observed,row,_,_=context(license=license);api=API('unsupported')
            result=admission.assess_changes(reader,BASE,MERGE,HEAD,collection(MERGE,[]),observed,api,TODAY)
            self.assertEqual(result['package_decision_passed'],passes);self.assertEqual(api.calls,[])
            self.assertEqual(result['changes'][0]['advisory_status'],'not-applicable-data-fixture')
            self.assertIsNone(result['changes'][0]['vulnerabilities'])
            self.assertFalse(result['dependency_coverage_verified'])

    def test_license_waiver_requires_real_scoped_approval_and_data_unknowns_do_not_pass(self):
        import dependency_admission as admission
        reader,observed,row,_,_=context(license='GPL-3.0-only')
        reader.rules={**RULES,'exceptions':[{'id':'DEP-0001','ecosystem':'fixture','name':row['name'],'version':row['version'],
            'kind':'license','value':'GPL-3.0-only','owner':'aatuh','reason':'Synthetic test, no approval.',
            'reviewed_on':'2026-10-21','expires_on':'2026-11-20','review_url':'https://github.com/aatuh/evydence/pull/123'}]}
        with self.assertRaises(admission.AdmissionError):
            admission.assess_changes(reader,BASE,MERGE,HEAD,collection(MERGE,[]),observed,API(),TODAY)
        reader,observed,row,_,_=context();observed['source']['files'][0]['mode']='100755'
        with self.assertRaises(admission.AdmissionError):
            admission.assess_changes(reader,BASE,MERGE,HEAD,collection(MERGE,[]),observed,API(),TODAY)


if __name__=='__main__':unittest.main()
