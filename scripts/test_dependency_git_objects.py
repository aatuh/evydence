#!/usr/bin/env python3
"""Exact-byte Git input readers must not trust body metadata or working-tree files."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import dependency_git_objects as objects


def oid(kind,raw):
    return subprocess.run(['git','hash-object','-t',kind,'--stdin'],input=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout.decode().strip()


class BlobTests(unittest.TestCase):
    def fixture(self,raw=b'input\n'):
        value={'sha':oid('blob',raw),'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()+'\n'}
        return raw,value
    def test_declared_size_canonical_base64_and_object_id_all_bind(self):
        for raw in [b'',b'input\n',b'\x00\xff']:
            expected,value=self.fixture(raw)
            self.assertEqual(objects.decode_blob(value,value['sha']),expected)
        raw,value=self.fixture()
        for changes in [{'sha':'0'*40},{'encoding':'utf-8'},{'size':True},{'size':0},
                        {'content':'PRIVATE_CANARY%'},{'content':'aW5wdXQK\t'},
                        {'content':base64.b64encode(b'tamper').decode()}]:
            bad={**value,**changes}
            with self.subTest(changes=changes),self.assertRaises(objects.ObjectError) as error: objects.decode_blob(bad,value['sha'])
            self.assertNotIn('CANARY',str(error.exception))
        with patch.object(objects,'MAX_BLOB_BYTES',1),self.assertRaises(objects.ObjectError): objects.decode_blob(value,value['sha'])
        raw,value=self.fixture(b'i'); value['content']='aR=='
        with self.assertRaises(objects.ObjectError): objects.decode_blob(value,value['sha'])
    def test_remote_reader_caches_verified_bytes_and_bounds_the_cache(self):
        raw,value=self.fixture()
        class API:
            source_inputs=True; authenticated=True
            def get(self,endpoint): return value
        api=API(); reader=objects.RemoteGit(api)
        with patch.object(api,'get',wraps=api.get) as get:
            self.assertEqual(reader.blob(value['sha']),raw); self.assertEqual(reader.blob(value['sha']),raw)
        self.assertEqual(get.call_count,1)
        with patch.object(objects,'MAX_TOTAL_BLOB_BYTES',1),self.assertRaises(objects.ObjectError):
            objects.RemoteGit(api).blob(value['sha'])
        api.source_inputs=False
        with self.assertRaises(objects.ObjectError): objects.RemoteGit(api)


class LocalTests(unittest.TestCase):
    def fixture(self,root):
        environment={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
                     'GIT_AUTHOR_NAME':'Test','GIT_AUTHOR_EMAIL':'test@example.invalid',
                     'GIT_COMMITTER_NAME':'Test','GIT_COMMITTER_EMAIL':'test@example.invalid'}
        def git(*args,input=None):
            return subprocess.run(['git','-c','maintenance.auto=false','-c','gc.auto=0','-C',str(root),*args],
                input=input,env=environment,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout.strip()
        git('init','-q'); raw=b'module example.org/original\n'; blob=git('hash-object','-w','--stdin',input=raw).decode()
        tree=git('mktree',input=('100644 blob '+blob+'\tgo.mod\n').encode()).decode()
        commit=git('commit-tree',tree,input=b'test input source\n').decode()
        return git,raw,blob,tree,commit
    def test_local_reader_uses_git_objects_ignores_replacements_and_preserves_worktree(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); git,raw,blob,tree,commit=self.fixture(root)
            (root/'go.mod').write_text('owner working-tree edit')
            replacement=git('hash-object','-w','--stdin',input=b'PRIVATE_CANARY replacement').decode()
            git('replace',blob,replacement)
            reader=objects.LocalGit(root)
            actual_tree,entries=reader.tree(commit)
            self.assertEqual(actual_tree,tree); self.assertEqual(entries['go.mod']['sha'],blob)
            self.assertEqual(reader.blob(blob),raw)
            self.assertEqual((root/'go.mod').read_text(),'owner working-tree edit')
            for invalid in ['HEAD','../PRIVATE_CANARY','--help']:
                with self.subTest(invalid=invalid),self.assertRaises(objects.ObjectError): reader.blob(invalid)
    def test_git_subprocess_is_read_only_no_lazy_fetch_and_drops_provider_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.fixture(root); reader=objects.LocalGit(root)
            with patch.object(objects.inventory,'_run',return_value=b'1\n') as run, \
                 patch.dict(os.environ,{'GH_TOKEN':'PRIVATE_CANARY','GIT_CONFIG_PARAMETERS':'PRIVATE_CANARY'}):
                reader.run(['cat-file','-s','a'*40])
            args,cwd,environment=run.call_args.args
            self.assertIn('--no-lazy-fetch',args); self.assertEqual(environment['GIT_NO_REPLACE_OBJECTS'],'1')
            self.assertNotIn('GH_TOKEN',environment); self.assertNotIn('GIT_CONFIG_PARAMETERS',environment)
            self.assertEqual(environment['GIT_CONFIG_GLOBAL'],os.devnull)
            with patch.object(objects.inventory,'_run') as run,self.assertRaises(objects.ObjectError): reader.run(['push'])
            run.assert_not_called()


if __name__=='__main__': unittest.main()
