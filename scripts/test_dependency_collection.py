#!/usr/bin/env python3
"""Verified proposed files are data; trusted base selects executable tooling."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import dependency_collection as collection
import dependency_git_objects as objects

BASE='a'*40; HEAD='b'*40


def revision():
    contents={'go.mod':b'module example.org/proposed\n','go.sum':b'',
              'scripts/dependency_inventory.py':b'raise RuntimeError("PRIVATE_CANARY must not execute")',
              'tools/cmd/license-inventory/main.go':b'package main // PRIVATE_CANARY not compiled'}
    files=[{'path':path,'git_blob':objects.object_id('blob',raw),'mode':'100644',
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'roles':['tooling']}
           for path,raw in sorted(contents.items())]
    return {'commit':HEAD,'tree':'c'*40,'files':files,'missing_required':[],
            'unclassified_manifests':[],'schemas_verified':[]},contents


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.observed,self.contents=revision()
        self.artifact=Mock();self.artifact.receipt={'trusted_base':BASE,'binary_sha256':'d'*64}
        self.reader=object(); self.inventory={'schema':'evydence-dependency-inventory.v1','complete':False,
            'components':[],'generator':{'classifier':copy.deepcopy(self.artifact.receipt)}}

    def run_collection(self,work,collect=None):
        with patch.object(collection.inputs,'revision',return_value=(self.observed,self.contents)) as read, \
             patch.object(collection.classifiers,'build',return_value=self.artifact) as build, \
             patch.object(collection.inventory,'collect',side_effect=collect or (lambda *_args,**_kw:self.inventory)) as collect_mock:
            result=collection.collect(self.reader,BASE,HEAD,work,{'GH_TOKEN':'SECRET_CANARY'})
        return result,read,build,collect_mock

    def test_export_is_private_digest_bound_data_and_only_base_selects_the_classifier(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);owner=root/'owner-file';owner.write_text('preserve')
            def collect(source,work,parent,*,classifier):
                self.assertIs(classifier,self.artifact)
                self.assertTrue(source.is_relative_to(root));self.assertEqual(source.stat().st_mode&0o777,0o700)
                for path,raw in self.contents.items():
                    self.assertEqual((source/path).read_bytes(),raw)
                    self.assertEqual((source/path).stat().st_mode&0o777,0o600)
                return self.inventory
            result,read,build,_=self.run_collection(root,collect)
            read.assert_called_once_with(self.reader,HEAD)
            self.assertEqual(build.call_args.args[:2],(self.reader,BASE))
            self.assertEqual(result['source']['commit'],HEAD);self.assertEqual(result['trusted_base'],BASE)
            self.assertTrue(result['source_bytes_verified']);self.assertFalse(result['dependency_coverage_verified'])
            self.assertNotIn('CANARY',json.dumps(result));self.assertNotIn(str(root),json.dumps(result))
            self.assertEqual(owner.read_text(),'preserve')

    def test_missing_unknown_or_substituted_source_fails_before_build_or_provider_collection(self):
        for mutation in ['missing','unknown','bytes','hash','path','duplicate','count']:
            self.setUp()
            if mutation=='missing':self.observed['missing_required']=['go:go.sum']
            if mutation=='unknown':self.observed['unclassified_manifests']=['new/package.json']
            if mutation=='bytes':self.contents['go.mod']=b'PRIVATE_CANARY changed body'
            if mutation=='hash':self.observed['files'][0]['sha256']='0'*64
            if mutation=='path':self.observed['files'][0]['path']='../PRIVATE_CANARY'
            if mutation=='duplicate':self.observed['files'].append(copy.deepcopy(self.observed['files'][0]))
            if mutation=='count':self.observed['files'][0]['bytes']=True
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as folder, \
                 patch.object(collection.inputs,'revision',return_value=(self.observed,self.contents)), \
                 patch.object(collection.classifiers,'build') as build,patch.object(collection.inventory,'collect') as collect, \
                 self.assertRaises(collection.CollectionError) as error:
                collection.collect(self.reader,BASE,HEAD,Path(folder),{})
            build.assert_not_called();collect.assert_not_called();self.assertNotIn('CANARY',str(error.exception))

    def test_export_edits_added_files_or_links_abort_without_hiding_owner_changes(self):
        for mutation in ['edit','add','link']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);source_path=[]
                def collect(source,*_args,**_kwargs):
                    source_path.append(source)
                    if mutation=='edit':(source/'go.mod').write_text('PRIVATE_CANARY concurrent edit')
                    if mutation=='add':(source/'go.work').write_text('PRIVATE_CANARY late source')
                    if mutation=='link':(source/'late-directory').symlink_to(root,target_is_directory=True)
                    return self.inventory
                with self.assertRaises(collection.CollectionError) as error:self.run_collection(root,collect)
                self.assertNotIn('CANARY',str(error.exception));self.assertTrue(source_path[0].exists())

    def test_driver_source_edits_and_mismatched_classifier_base_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);code=root/'trusted-code';code.mkdir();work=root/'work';work.mkdir()
            for path in collection.DRIVER_FILES:
                target=code/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('trusted source')
            def mutate(*_args,**_kwargs):
                (code/collection.DRIVER_FILES[0]).write_text('PRIVATE_CANARY owner change')
                return self.inventory
            with patch.object(collection,'ROOT',code),self.assertRaises(collection.CollectionError):self.run_collection(work,mutate)
            self.assertIn('CANARY',(code/collection.DRIVER_FILES[0]).read_text())
            self.artifact.receipt['trusted_base']='f'*40
            with self.assertRaises(collection.CollectionError):self.run_collection(work)

    def test_cli_preflights_output_before_build_and_preserves_existing_owner_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);owner=root/'owner.json';owner.write_text('PRIVATE_CANARY owner content')
            args=['--root',str(root),'--local-repository',str(root),'--trusted-base',BASE,'--source',HEAD,
                  '--work-root',str(root),'--output','owner.json','--replace']
            error=io.StringIO()
            with patch.object(collection,'collect') as collect,patch.object(collection.sys,'stderr',error):
                self.assertEqual(collection.main(args),2)
            collect.assert_not_called();self.assertIn('CANARY',owner.read_text());self.assertNotIn('CANARY',error.getvalue())

    def test_one_verified_base_classifier_can_be_shared_without_rebuilding_or_rebinding(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);workspace=root/'classifier';workspace.mkdir()
            binary=workspace/'license-classifier';binary.write_bytes(b'verified executable')
            receipt={'trusted_base':BASE,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
            artifact=collection.classifiers.BuiltClassifier(workspace,receipt,{})
            self.inventory['generator']['classifier']=receipt
            with patch.object(collection.inputs,'revision',return_value=(self.observed,self.contents)), \
                 patch.object(collection.classifiers,'build') as build, \
                 patch.object(collection.inventory,'collect',return_value=self.inventory) as collect:
                for _ in range(2):collection.collect(self.reader,BASE,HEAD,root,{},classifier=artifact)
                build.assert_not_called();self.assertEqual(collect.call_count,2)
                artifact.receipt['trusted_base']='f'*40
                with self.assertRaises(collection.CollectionError):collection.collect(self.reader,BASE,HEAD,root,{},classifier=artifact)

    def test_remote_cli_uses_current_target_base_and_rechecks_live_pr_before_writing(self):
        for changed in [False,True]:
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);context={'pull_request':30,'base':BASE,'head':HEAD,
                    'head_repository':'aatuh/evydence','changed_files':1}
                snapshot={**context,'repository':'aatuh/evydence','comparison_base':'e'*40}
                api=Mock();api.snapshot.return_value=snapshot;api.receipts=[]
                final={**context,'head':'f'*40} if changed else context
                with patch.object(collection.provider,'GitHub',return_value=api), \
                     patch.object(collection.provider,'pull_context',return_value=final), \
                     patch.object(collection.objects,'RemoteGit') as reader, \
                     patch.object(collection,'collect',return_value={'schema':collection.SCHEMA}) as collect, \
                     patch.object(collection.sys,'stderr',io.StringIO()):
                    result=collection.main(['--root',str(root),'--pull-request','30','--trusted-base',BASE,
                        '--source',HEAD,'--head-repository','aatuh/evydence','--work-root',str(root),'--output','report.json'])
                self.assertEqual(collect.call_args.args[1:3],(BASE,HEAD))
                self.assertEqual(result,2 if changed else 0)
                self.assertEqual((root/'report.json').exists(),not changed)


if __name__=='__main__':unittest.main()
