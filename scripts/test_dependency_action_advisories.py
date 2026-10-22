#!/usr/bin/env python3
"""Pinned Actions need exact commit/version evidence independent of graph alerts."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
from urllib.parse import parse_qs,urlsplit

import dependency_action_advisories as actions
import dependency_advisories as advisories
from test_dependency_admission import BASE,HEAD,collection

PIN='d'*40


def component(name='actions/checkout',**changes):
    parts=name.split('/')
    return {'ecosystem':'github-actions','name':name,'version':PIN,'license':'MIT','license_status':'candidate','origins':['ci'],
        'source':{'verification':'github-git-objects','repository':'/'.join(parts[:2]),'path':'/'.join(parts[2:]),
                  'commit':PIN,'root_tree':'e'*40},**changes}


def tag(name='v1.2.3',commit=PIN,repo='actions/checkout'):
    return {'name':name,'commit':{'sha':commit,'url':'https://api.github.com/repos/'+repo+'/commits/'+commit},
            'zipball_url':'PRIVATE_CANARY','node_id':'PRIVATE_CANARY'}


class API:
    def __init__(self,status='observed'):self.calls=[];self.receipts=[];self.status=status
    def observe_query(self,value,request):
        self.calls.append((copy.deepcopy(value),copy.deepcopy(request)))
        findings=[] if request['version'].removeprefix('v')=='1.2.3' else [{'id':'GHSA-aaaa-bbbb-cccc','severity':'high'}]
        return {'component':advisories.identity(value),'status':self.status,
                'vulnerabilities':findings if self.status=='observed' else None,'withdrawn':[],'receipt_indexes':[]}
    def observe(self,value):
        return {'component':advisories.identity(value),'status':'observed','vulnerabilities':[]}


def query_for(rows):
    return Mock(side_effect=lambda repo,page:json.dumps(
        {'full_name':repo,'private':False,'description':'PRIVATE_CANARY'} if page is None else rows).encode())


def client(rows,tag_rows,api=None):
    query=query_for(tag_rows)
    tags=actions.Tags(query=query)
    api=api or API()
    return actions.Client(api,collection(HEAD,rows),BASE,HEAD,tags=tags,action_api=api),query


class LookupTests(unittest.TestCase):
    def test_exact_pinned_commit_maps_all_full_versions_and_omits_aliases_and_provider_prose(self):
        value=component();api=API()
        lookup,query=client([value],[tag('v1'),tag('v1.2.3'),tag('v1.2.4'),tag('v9.0.0',commit='a'*40)],api)
        result=lookup.observe(value)
        self.assertEqual(result['status'],'observed');self.assertEqual(result['component'],advisories.identity(value))
        self.assertEqual(result['release_versions'],['v1.2.3','v1.2.4'])
        self.assertEqual(result['vulnerabilities'],[{'id':'GHSA-aaaa-bbbb-cccc','severity':'high'}])
        self.assertEqual(len(api.calls),2);lookup.verify();self.assertEqual(query.call_count,4)
        self.assertNotIn('CANARY',json.dumps(lookup.evidence()));self.assertNotIn('CANARY',json.dumps(result))

    def test_subactions_use_repository_advisories_but_keep_exact_component_scope(self):
        first=component('github/codeql-action/init');second=component('github/codeql-action/analyze');api=API()
        lookup,query=client([first,second],[tag('v1.2.3',repo='github/codeql-action')],api)
        a=lookup.observe(first);b=lookup.observe(second)
        self.assertEqual(a['component']['name'],first['name']);self.assertEqual(b['component']['name'],second['name'])
        self.assertEqual(api.calls[0][1]['package'],{'ecosystem':'GitHub Actions','name':'github/codeql-action'})
        self.assertEqual(len(api.calls),1);self.assertEqual(query.call_count,2)
        a['vulnerabilities'].append({'tampered':True});self.assertEqual(lookup.observe(first)['vulnerabilities'],[])

    def test_no_matching_full_version_and_unavailable_or_partial_queries_remain_unknown(self):
        for rows in [[],[tag('v1')],[tag('v1.2.3',commit='a'*40)]]:
            value=component();lookup,_=client([value],rows)
            result=lookup.observe(value)
            self.assertEqual(result['status'],'unsupported');self.assertIsNone(result['vulnerabilities'])
        value=component();lookup,_=client([value],[tag()],API('unavailable'))
        result=lookup.observe(value);self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['vulnerabilities'])
        lookup,_=client([value],[tag(),tag('v1.2.4')]);lookup.api.observe_query=Mock(side_effect=[
            {'component':advisories.identity(value),'status':'observed','vulnerabilities':[],'withdrawn':[],'receipt_indexes':[]},
            {'component':advisories.identity(value),'status':'unavailable','vulnerabilities':None,'withdrawn':[],'receipt_indexes':[]}])
        self.assertEqual(lookup.observe(value)['status'],'unavailable')

    def test_source_identity_commit_path_or_collection_cannot_be_rebound(self):
        for operation in ['commit','repository','path','tree','verified','base','source']:
            value=component();observed=collection(HEAD,[value])
            if operation=='commit':value['source']['commit']='a'*40
            if operation=='repository':value['source']['repository']='other/repository'
            if operation=='path':value['source']['path']='other'
            if operation=='tree':value['source']['root_tree']='PRIVATE_CANARY'
            if operation=='verified':observed['source_bytes_verified']=False
            if operation=='base':observed['trusted_base']=HEAD
            if operation=='source':observed['source']['commit']=BASE
            with self.subTest(operation=operation),self.assertRaises(actions.ActionAdvisoryError) as error:
                actions.Client(API(),observed,BASE,HEAD)
            self.assertNotIn('CANARY',str(error.exception))

    def test_final_tag_move_deletion_or_new_matching_version_invalidates_lookup(self):
        for mutation in ['move','delete','addition']:
            value=component();rows=[tag()];lookup,_=client([value],rows);lookup.observe(value)
            if mutation=='move':rows[0]['commit'].update(sha='a'*40,url='https://api.github.com/repos/actions/checkout/commits/'+'a'*40)
            if mutation=='delete':rows.clear()
            if mutation=='addition':rows.append(tag('v1.2.4'))
            with self.subTest(mutation=mutation),self.assertRaises(actions.ActionAdvisoryError):lookup.verify()

    def test_other_package_and_image_source_queries_still_use_the_shared_client(self):
        lookup,_=client([],[]);value={'ecosystem':'npm','name':'example','version':'1.2.3'}
        self.assertEqual(lookup.observe(value)['status'],'observed')
        query={'package':{'ecosystem':'Alpine:v3.23','name':'openssl'},'version':'1.2.3-r0'}
        api=Mock();lookup.api=api;lookup.observe_query(value,query);api.observe_query.assert_called_once_with(value,query)

    def test_joined_admission_uses_real_lookup_status_and_preserves_both_finding_sources(self):
        from test_dependency_review_join import assess,row
        for tag_rows,provider_findings,passes in [([tag()],[],True),([],[],False),([tag('v1.2.4')],[],False),
            ([tag()],[{'advisory_ghsa_id':'GHSA-1111-2222-3333','severity':'high'}],False)]:
            value=component();lookup,_=client([value],tag_rows)
            provider_row=row(ecosystem='actions',name=value['name'],version=PIN,
                manifest='.github/workflows/ci.yml',package_url='pkg:githubactions/'+value['name']+'@'+PIN,
                vulnerabilities=provider_findings)
            result=assess([provider_row],components=[value],api=lookup);lookup.verify()
            self.assertEqual(result['package_decision_passed'],passes)
            self.assertFalse(result['dependency_coverage_verified'])


class TagsTests(unittest.TestCase):
    def test_repository_visibility_and_identity_are_checked_before_tags_and_at_final_recheck(self):
        for private in [True,False]:
            state={'private':private}
            query=Mock(side_effect=lambda repo,page:json.dumps(
                {'full_name':repo,**state} if page is None else [tag()]).encode())
            tags=actions.Tags(query=query)
            if private:
                with self.assertRaises(actions.ActionAdvisoryError):tags.versions('actions/checkout',PIN)
                self.assertEqual(query.call_count,1)
            else:
                tags.versions('actions/checkout',PIN);state['private']=True
                with self.assertRaises(actions.ActionAdvisoryError):tags.verify()
        query=Mock(return_value=json.dumps({'full_name':'other/repository','private':False}).encode())
        with self.assertRaises(actions.ActionAdvisoryError):actions.Tags(query=query).versions('actions/checkout',PIN)

    def test_pages_are_complete_and_receipts_hash_actual_bytes(self):
        first=[tag('ignored-'+str(index)) for index in range(100)];second=[tag()]
        query=Mock(side_effect=[json.dumps({'full_name':'actions/checkout','private':False}).encode(),
                              json.dumps(first).encode(),json.dumps(second).encode()]);tags=actions.Tags(query=query)
        self.assertEqual(tags.versions('actions/checkout',PIN),['v1.2.3'])
        self.assertEqual(query.call_args_list[-1].args,('actions/checkout',2));self.assertEqual(len(tags.receipts),3)
        self.assertTrue(all(len(row['sha256'])==64 for row in tags.receipts))

    def test_duplicate_truncated_malformed_and_oversized_pages_never_become_empty_results(self):
        for raw in [b'{"error":"PRIVATE_CANARY"}',b'[{"name":"x","name":"y"}]',json.dumps([tag(),tag()]).encode(),
                    json.dumps([tag(repo='other/repository')]).encode(),json.dumps([tag(commit='invalid')]).encode()]:
            tags=actions.Tags(query=Mock(side_effect=lambda repo,page:json.dumps({'full_name':repo,'private':False}).encode() if page is None else raw))
            with self.subTest(raw=raw),self.assertRaises(actions.ActionAdvisoryError) as error:tags.versions('actions/checkout',PIN)
            self.assertNotIn('CANARY',str(error.exception))
        rows=[tag('ignored-'+str(index)) for index in range(100)]
        with patch.object(actions,'MAX_PAGES',1),self.assertRaises(actions.ActionAdvisoryError):
            actions.Tags(query=query_for(rows)).versions('actions/checkout',PIN)
        for bound in ['MAX_REQUESTS','MAX_TOTAL_BYTES','MAX_RESPONSE_BYTES']:
            with self.subTest(bound=bound),patch.object(actions,bound,0),self.assertRaises(actions.ActionAdvisoryError):
                actions.Tags(query=Mock(return_value=b'[]')).versions('actions/checkout',PIN)

    def test_transport_has_fixed_hostname_get_endpoint_and_no_inherited_proxy_or_host_override(self):
        with patch.object(actions,'capture',return_value=b'[]') as capture,patch.dict(os.environ,
            {'GH_TOKEN':'SECRET_CANARY','HTTP_PROXY':'PRIVATE_CANARY','GH_HOST':'PRIVATE_CANARY'}):
            self.assertEqual(actions.api('actions/checkout',1),b'[]')
        arguments,_,environment,maximum,timeout=capture.call_args.args
        self.assertEqual(arguments[:7],['gh','api','--hostname','github.com','--method','GET','-H'])
        self.assertEqual(arguments[-1],'repos/actions/checkout/tags?per_page=100&page=1')
        self.assertNotIn('GH_HOST',environment);self.assertNotIn('HTTP_PROXY',environment)
        self.assertEqual(maximum,actions.MAX_RESPONSE_BYTES);self.assertLessEqual(timeout,45)
        for repo,page in [('owner/../PRIVATE_CANARY',1),('actions/checkout',True),('actions/checkout',0)]:
            with self.subTest(repo=repo,page=page),self.assertRaises(actions.ActionAdvisoryError):actions.api(repo,page)


class VersionTests(unittest.TestCase):
    def test_full_published_tag_prefix_is_preserved_and_supported(self):
        query={'package':{'ecosystem':'GitHub Actions','name':'actions/checkout'},'version':'v1.2.3'}
        actions.query_version(query)
        tags=actions.Tags(query=query_for([tag()]))
        self.assertEqual(tags.versions('actions/checkout',PIN),['v1.2.3'])

    def test_only_exact_repository_and_full_release_versions_enter_action_queries(self):
        valid={'package':{'ecosystem':'GitHub Actions','name':'actions/checkout'},'version':'1.2.3'}
        actions.query_version(valid)
        for value in [{**valid,'version':PIN},{**valid,'version':'v1'},
                      {**valid,'package':{'ecosystem':'GitHub Actions','name':'github/codeql-action/init'}}]:
            with self.subTest(value=value),self.assertRaises(actions.ActionAdvisoryError):actions.query_version(value)


def wire(rows,link=None):
    headers='HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n'
    if link is not None:headers+='Link: '+link+'\r\n'
    return (headers+'\r\n'+json.dumps(rows)).encode()


def advisory(identifier='GHSA-aaaa-bbbb-cccc',kind='reviewed',**changes):
    return {'ghsa_id':identifier,'severity':'high','type':kind,'withdrawn_at':None,
        'vulnerabilities':[{'package':{'ecosystem':'actions','name':'actions/checkout'}}],
        'summary':'PRIVATE_CANARY','description':'PRIVATE_CANARY',**changes}


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.component=advisories.identity(component())
        self.request={'package':{'ecosystem':'GitHub Actions','name':'actions/checkout'},'version':'v1.2.3'}

    def test_all_types_are_observed_and_unknown_severity_is_never_lowered(self):
        def query(_repo,_version,kind,_cursor):
            return wire([advisory(kind=kind,severity='low' if kind=='reviewed' else 'critical' if kind=='malware' else None)])
        api=actions.Advisories(query=query);result=api.observe_query(self.component,self.request)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['vulnerabilities'],[{'id':'GHSA-aaaa-bbbb-cccc','severity':'unknown'}])
        self.assertEqual(len(api.receipts),3);self.assertNotIn('CANARY',json.dumps(result))
        self.assertNotIn('CANARY',json.dumps(api.receipts))

    def test_cursor_pagination_binds_filters_and_all_pages_before_a_passing_observation(self):
        link='<https://api.github.com/advisories?ecosystem=actions&affects=actions%2Fcheckout%40v1.2.3&type=reviewed&is_withdrawn=false&per_page=100&sort=published&direction=asc&after=next-cursor>; rel="next"'
        query=Mock(side_effect=lambda _repo,_version,kind,cursor:
            wire([advisory()],link) if kind=='reviewed' and cursor is None else wire([]))
        result=actions.Advisories(query=query).observe_query(self.component,self.request)
        self.assertEqual(result['status'],'observed');self.assertEqual(query.call_args_list[1].args[-1],'next-cursor')
        for changed in [link.replace('api.github.com','attacker.invalid'),link.replace('v1.2.3','v9.9.9'),
                        link.replace('actions%2Fcheckout','other%2Frepository'),link.replace('/advisories?','/other?'),
                        link.replace('after=next-cursor','after=next-cursor&after=other')]:
            with self.subTest(link=changed):
                api=actions.Advisories(query=Mock(return_value=wire([],changed)))
                self.assertEqual(api.observe_query(self.component,self.request)['status'],'unavailable')
        api=actions.Advisories(query=Mock(return_value=wire([],link)))
        self.assertEqual(api.observe_query(self.component,self.request)['status'],'unavailable')

    def test_mismatches_malformed_headers_duplicate_json_and_partial_service_failure_stay_unknown(self):
        for raw in [b'[]',wire([advisory(vulnerabilities=[])]),wire([advisory(type='malware')]),
                    wire([advisory(ghsa_id='PRIVATE_CANARY')]),wire([advisory(),advisory()]),
                    b'HTTP/2.0 200 OK\r\nContent-Type: text/html\r\n\r\n[]',
                    b'HTTP/2.0 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/html\r\n\r\n[]',
                    b'HTTP/2.0 200 OK\r\n\r\n[{"ghsa_id":"x","ghsa_id":"y"}]']:
            with self.subTest(raw=raw):
                result=actions.Advisories(query=Mock(return_value=raw)).observe_query(self.component,self.request)
                self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['vulnerabilities'])
        query=Mock(side_effect=[wire([]),OSError('PRIVATE_CANARY')])
        result=actions.Advisories(query=query).observe_query(self.component,self.request)
        self.assertEqual(result['status'],'unavailable');self.assertNotIn('CANARY',json.dumps(result))

    def test_transport_uses_documented_version_filter_and_cursor_with_fixed_host(self):
        with patch.object(actions,'capture',return_value=wire([])) as capture:
            actions.advisory_api('actions/checkout','v1.2.3','malware','opaque-cursor')
        argv=capture.call_args.args[0];self.assertIn('--include',argv)
        self.assertEqual(argv[:6],['gh','api','--hostname','github.com','--method','GET'])
        parsed=parse_qs(urlsplit('https://api.github.com/'+argv[-1]).query)
        self.assertEqual(parsed['affects'],['actions/checkout@v1.2.3']);self.assertEqual(parsed['type'],['malware'])
        self.assertEqual(parsed['after'],['opaque-cursor'])
        for repo,version,kind in [('other/../PRIVATE_CANARY','v1.2.3','reviewed'),
            ('actions/checkout',PIN,'reviewed'),('actions/checkout','v1.2.3','PRIVATE_CANARY')]:
            with self.subTest(repo=repo,version=version,kind=kind),self.assertRaises(actions.ActionAdvisoryError):
                actions.advisory_api(repo,version,kind,None)

    def test_exhausted_advisory_budgets_cannot_produce_empty_passing_observations(self):
        for bound in ['MAX_REQUESTS','MAX_TOTAL_BYTES','MAX_RESPONSE_BYTES','MAX_PAGES']:
            with self.subTest(bound=bound),patch.object(actions,bound,0):
                result=actions.Advisories(query=Mock(return_value=wire([]))).observe_query(self.component,self.request)
                self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['vulnerabilities'])


if __name__=='__main__':unittest.main()
