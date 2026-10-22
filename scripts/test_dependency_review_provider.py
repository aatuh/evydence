#!/usr/bin/env python3
"""Authenticated PR identity, immutable Git coverage and safe provider I/O."""
import copy
from contextlib import redirect_stderr
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import dependency_review_provider as provider

BASE='a'*40; HEAD='b'*40; A='c'*40; B='d'*40; N='e'*40; T='f'*40


def git_tree(payload):
    return subprocess.run(['git','hash-object','-t','tree','--stdin'],input=payload,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout.decode().strip()


def tree(files):
    payload=b''.join(b'100644 '+name.encode()+b'\0'+bytes.fromhex(sha) for name,sha in sorted(files.items()))
    return {'sha':git_tree(payload),'truncated':False,'tree':[{'path':name,'mode':'100644','type':'blob','sha':sha} for name,sha in files.items()]}


def pull():
    return {'number':30,'state':'open','merged':False,'merged_at':None,'labels':[], 'changed_files':2,
            'base':{'ref':'master','sha':BASE,'repo':{'full_name':'aatuh/evydence'}},
            'head':{'sha':HEAD,'repo':{'full_name':'contributor/fork'}}}


def dependency():
    return {'change_type':'added','manifest':'go.mod','ecosystem':'gomod','name':'example.org/module',
            'version':'1.2.3','package_url':'pkg:golang/example.org/module@1.2.3','license':'MIT',
            'vulnerabilities':[],'source_repository_url':'https://PRIVATE_CANARY.invalid','private':'PRIVATE_CANARY'}


class FakeGitHub(provider.GitHub):
    def __init__(self):
        super().__init__(); self.authenticated=True; self.calls=[]
        old=tree({'go.mod':A,'unchanged.txt':T}); new=tree({'go.mod':B,'new.txt':N,'unchanged.txt':T})
        self.responses={'pulls/30':[pull(),pull()],
            'compare/'+BASE+'...'+HEAD+'?per_page=1&page=1':{'base_commit':{'sha':BASE,'commit':{'tree':{'sha':old['sha']}}},
                'merge_base_commit':{'sha':BASE,'commit':{'tree':{'sha':old['sha']}}}},
            'git/commits/'+HEAD:{'sha':HEAD,'tree':{'sha':new['sha']}},
            'git/trees/'+old['sha']+'?recursive=1':old,'git/trees/'+new['sha']+'?recursive=1':new,
            'pulls/30/files?per_page=1&page=1':[{'filename':'go.mod','status':'modified','sha':B,'patch':'PRIVATE_CANARY'}],
            'pulls/30/files?per_page=1&page=2':[{'filename':'new.txt','status':'added','sha':N}],
            'dependency-graph/compare/'+BASE+'...'+HEAD:[dependency()]}
    def get(self,endpoint):
        self.calls.append(endpoint); value=self.responses[endpoint]
        if endpoint=='pulls/30': value=value.pop(0)
        if isinstance(value,Exception): raise value
        return copy.deepcopy(value)


def snapshot(client):
    with patch.object(provider,'PER_PAGE',1):
        return client.snapshot(30,base=BASE,head=HEAD,head_repository='contributor/fork')


class TreeTests(unittest.TestCase):
    def test_git_filenames_support_astro_routes_without_becoming_shell_or_filesystem_paths(self):
        value=tree({'[...slug].astro':A,'a file (copy).txt':B})
        result=provider.git_tree(value,value['sha'])
        self.assertEqual(set(result),{'[...slug].astro','a file (copy).txt'})
        for value in ['../escape','/absolute','a/./file','a//file','a\\file','line\nfile']:
            with self.subTest(value=value),self.assertRaises(provider.ProviderError): provider.git_path(value)

    def test_tree_hashes_follow_git_directory_sorting_and_preserve_modes(self):
        child_payload=b'100644 file.txt\0'+bytes.fromhex(A); child=git_tree(child_payload)
        root_payload=b'100755 thing.ext\0'+bytes.fromhex(B)+b'40000 thing\0'+bytes.fromhex(child)
        value={'sha':git_tree(root_payload),'truncated':False,'tree':[
            {'path':'thing','mode':'040000','type':'tree','sha':child},
            {'path':'thing/file.txt','mode':'100644','type':'blob','sha':A},
            {'path':'thing.ext','mode':'100755','type':'blob','sha':B}]}
        result=provider.git_tree(value,value['sha'])
        self.assertEqual(result['thing.ext'],{'mode':'100755','type':'blob','sha':B})
        self.assertEqual(set(result),{'thing.ext','thing/file.txt'})
        for mutate in [lambda data:data.update(truncated=True),lambda data:data.update(sha='0'*40),
                       lambda data:data['tree'].append(copy.deepcopy(data['tree'][0])),
                       lambda data:data['tree'][0].update(sha='0'*40),
                       lambda data:data['tree'][1].update(path='../PRIVATE_CANARY'),
                       lambda data:data['tree'][1].update(mode='040000')]:
            bad=copy.deepcopy(value); mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises(provider.ProviderError): provider.git_tree(bad,value['sha'])


class SnapshotTests(unittest.TestCase):
    def test_mode_only_change_is_not_hidden_by_an_unchanged_blob_id(self):
        api=FakeGitHub(); old=tree({'go.mod':A})
        new={'sha':git_tree(b'100755 go.mod\0'+bytes.fromhex(A)),'truncated':False,
             'tree':[{'path':'go.mod','mode':'100755','type':'blob','sha':A}]}
        compare=api.responses['compare/'+BASE+'...'+HEAD+'?per_page=1&page=1']
        compare['base_commit']['commit']['tree']['sha']=old['sha']; compare['merge_base_commit']['commit']['tree']['sha']=old['sha']
        api.responses['git/commits/'+HEAD]['tree']['sha']=new['sha']
        api.responses['git/trees/'+old['sha']+'?recursive=1']=old; api.responses['git/trees/'+new['sha']+'?recursive=1']=new
        for context in api.responses['pulls/30']: context['changed_files']=1
        api.responses['pulls/30/files?per_page=1&page=1']=[{'filename':'go.mod','status':'modified','sha':A}]
        result=snapshot(api)
        self.assertEqual(result['files'][0]['mode'],'100755'); self.assertEqual(result['files'][0]['sha'],A)

    def test_full_paged_listing_is_bound_to_git_trees_and_rechecked_pr(self):
        api=FakeGitHub(); result=snapshot(api)
        self.assertTrue(result['provider_authenticated']); self.assertTrue(result['file_listing_verified'])
        self.assertFalse(result['dependency_coverage_verified'])
        self.assertEqual(len(result['files']),2); self.assertEqual(result['comparison_base'],BASE)
        self.assertEqual(api.calls.count('pulls/30'),2)
        self.assertEqual(result['dependency_rows'][0]['version'],'1.2.3')
        self.assertNotIn('CANARY',json.dumps(result))

    def test_expected_event_source_and_concurrent_pr_changes_fail(self):
        for mutate in [lambda data:data['head'].update(sha='0'*40),
                       lambda data:data['base'].update(sha='0'*40),
                       lambda data:data['head']['repo'].update(full_name='different/fork'),
                       lambda data:data.update(changed_files=1),lambda data:data.update(state='closed')]:
            api=FakeGitHub(); mutate(api.responses['pulls/30'][1])
            with self.subTest(mutate=mutate),self.assertRaises(provider.ProviderError): snapshot(api)
        api=FakeGitHub()
        with self.assertRaises(provider.ProviderError): api.snapshot(30,base='master',head=HEAD,head_repository='contributor/fork')
        self.assertEqual(api.calls,[])

    def test_page_duplicates_omissions_wrong_blob_and_hidden_tree_changes_fail(self):
        for case in ['duplicate','missing','wrong-blob','not-listed','truncated-tree','manifest-absent']:
            api=FakeGitHub()
            if case=='duplicate': api.responses['pulls/30/files?per_page=1&page=2']=api.responses['pulls/30/files?per_page=1&page=1']
            if case=='missing': api.responses['pulls/30/files?per_page=1&page=2']=[]
            if case=='wrong-blob': api.responses['pulls/30/files?per_page=1&page=1'][0]['sha']='0'*40
            if case=='not-listed':
                api.responses['pulls/30'][0]['changed_files']=1; api.responses['pulls/30'][1]['changed_files']=1
            if case=='truncated-tree':
                key=next(key for key in api.responses if key.startswith('git/trees/')); api.responses[key]['truncated']=True
            if case=='manifest-absent': api.responses['dependency-graph/compare/'+BASE+'...'+HEAD][0]['manifest']='absent/go.mod'
            with self.subTest(case=case),self.assertRaises(provider.ProviderError): snapshot(api)

    def test_merge_base_is_separate_from_target_base(self):
        api=FakeGitHub(); value=api.responses['compare/'+BASE+'...'+HEAD+'?per_page=1&page=1']
        value['merge_base_commit']['sha']='1'*40
        result=snapshot(api)
        self.assertEqual(result['base'],BASE); self.assertEqual(result['comparison_base'],'1'*40)

    def test_rename_paths_and_mode_changes_are_part_of_tree_coverage(self):
        api=FakeGitHub(); old=tree({'old.txt':A}); new=tree({'new.txt':B})
        value=api.responses['compare/'+BASE+'...'+HEAD+'?per_page=1&page=1']
        value['base_commit']['commit']['tree']['sha']=old['sha']; value['merge_base_commit']['commit']['tree']['sha']=old['sha']
        api.responses['git/commits/'+HEAD]['tree']['sha']=new['sha']
        api.responses['git/trees/'+old['sha']+'?recursive=1']=old; api.responses['git/trees/'+new['sha']+'?recursive=1']=new
        for context in api.responses['pulls/30']: context['changed_files']=1
        api.responses['pulls/30/files?per_page=1&page=1']=[{'filename':'new.txt','previous_filename':'old.txt','status':'renamed','sha':B}]
        api.responses['dependency-graph/compare/'+BASE+'...'+HEAD]=[]
        self.assertEqual(snapshot(api)['files'][0]['previous_filename'],'old.txt')
        api=FakeGitHub()
        with patch.object(provider,'MAX_FILES',1),self.assertRaises(provider.ProviderError): snapshot(api)


class EventAndTransportTests(unittest.TestCase):
    def test_larger_input_profile_is_explicit_and_does_not_change_the_default_budget(self):
        api=provider.GitHub(source_inputs=True); api.authenticated=True; api.count=provider.MAX_REQUESTS
        with patch.object(provider.inventory,'_run',return_value=b'{}'):
            self.assertEqual(api.get('git/blobs/'+A),{})
        standard=provider.GitHub(); standard.authenticated=True; standard.count=provider.MAX_REQUESTS
        with patch.object(provider.inventory,'_run') as run,self.assertRaises(provider.ProviderError):
            standard.get('git/blobs/'+A)
        run.assert_not_called()

    def test_cli_refuses_unrelated_output_and_conflicting_context_before_provider_work(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); target=root/'owner.json'; target.write_text('owner data')
            common=['--root',folder,'--output','owner.json','--replace','--pull-request','30',
                    '--base',BASE,'--head',HEAD,'--head-repository','contributor/fork']
            with patch.object(provider,'GitHub') as api,redirect_stderr(StringIO()):
                self.assertEqual(provider.main(common),2)
                self.assertEqual(provider.main(common+['--event',str(root/'event.json'),'--event-name','pull_request']),2)
            api.assert_not_called(); self.assertEqual(target.read_text(),'owner data')

    def test_event_identity_matches_only_supported_pr_context(self):
        value={'repository':{'full_name':'aatuh/evydence'},'number':30,'pull_request':pull()}
        result=provider.event_context(json.dumps(value).encode(),'pull_request_target')
        self.assertEqual(result['head'],HEAD); self.assertEqual(result['head_repository'],'contributor/fork')
        for name in ['push','workflow_dispatch']:
            with self.assertRaises(provider.ProviderError): provider.event_context(json.dumps(value).encode(),name)
        value['repository']['full_name']='other/repo'
        with self.assertRaises(provider.ProviderError): provider.event_context(json.dumps(value).encode(),'pull_request')

    def test_transport_is_authenticated_get_only_fixed_host_and_bounded_without_env_leaks(self):
        api=provider.GitHub()
        with patch.object(provider.inventory,'_run',side_effect=[b'authenticated',b'{}']) as run, \
             patch.dict(provider.os.environ,{'AWS_SECRET_ACCESS_KEY':'PRIVATE_CANARY','GH_HOST':'PRIVATE_CANARY'}):
            self.assertEqual(api.get('pulls/30'),{})
        calls=run.call_args_list
        self.assertEqual(calls[0].args[0][:4],['gh','auth','status','--hostname'])
        self.assertIn('GET',calls[1].args[0]); self.assertIn('github.com',calls[1].args[0])
        self.assertNotIn('AWS_SECRET_ACCESS_KEY',calls[1].args[2]); self.assertNotIn('GH_HOST',calls[1].args[2])
        self.assertEqual(api.receipts[0]['bytes'],2)
        for endpoint in ['https://PRIVATE_CANARY.invalid','../issues','issues/30','pulls/30?secret=PRIVATE_CANARY']:
            with self.subTest(endpoint=endpoint),patch.object(provider.inventory,'_run') as run,self.assertRaises(provider.ProviderError) as error: api.get(endpoint)
            run.assert_not_called(); self.assertNotIn('CANARY',str(error.exception))
        with patch.object(provider,'MAX_REQUESTS',0),self.assertRaises(provider.ProviderError): api.get('pulls/30')
        api=provider.GitHub(); api.authenticated=True
        with patch.object(provider,'MAX_TOTAL_BYTES',1),patch.object(provider.inventory,'_run',return_value=b'{}'),self.assertRaises(provider.ProviderError): api.get('pulls/30')
        self.assertEqual(api.receipts,[])
        api=provider.GitHub()
        with patch.object(provider.inventory,'_run',side_effect=provider.inventory.InventoryError('PRIVATE_CANARY')) as run,self.assertRaises(provider.ProviderError) as error:
            api.get('pulls/30')
        self.assertEqual(run.call_count,1); self.assertFalse(api.authenticated)
        self.assertNotIn('CANARY',str(error.exception))


if __name__=='__main__': unittest.main()
