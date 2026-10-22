#!/usr/bin/env python3
"""Classifier builds must use base objects, never proposed tooling or credentials."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_classifier as classifier
import dependency_git_objects as objects
import dependency_inventory as inventory

BASE='a'*40


class Reader:
    def __init__(self):
        self.files={
            'tools/go.mod':b'module github.com/aatuh/evydence/tools\n',
            'tools/go.sum':b'base sums\n',
            'tools/cmd/license-inventory/main.go':b'package main // trusted base\n',
            'tools/cmd/license-inventory/main_test.go':b'PRIVATE_CANARY not built\n',
            'release/support-matrix.json':(Path(__file__).parents[1]/'release/support-matrix.json').read_bytes(),
        }
        self.entries={path:{'mode':'100644','type':'blob','sha':objects.object_id('blob',raw)}
                      for path,raw in self.files.items()}
        self.requests=[]
    def tree(self,commit):
        self.requests.append(commit)
        if commit!=BASE: raise AssertionError('proposed or merge-base source was requested')
        return 'b'*40,copy.deepcopy(self.entries)
    def blob(self,identity):
        return next(raw for raw in self.files.values() if objects.object_id('blob',raw)==identity)


class SourcesTests(unittest.TestCase):
    def test_sources_are_verified_base_blobs_and_test_code_is_not_executed(self):
        reader=Reader(); files,receipt=classifier.sources(reader,BASE)
        self.assertEqual(reader.requests,[BASE]); self.assertEqual(receipt['trusted_base'],BASE)
        self.assertNotIn('tools/cmd/license-inventory/main_test.go',files)
        self.assertEqual(set(files),set(receipt['sources']))
        for name,raw in files.items():
            self.assertEqual(receipt['sources'][name]['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(receipt['sources'][name]['git_blob'],objects.object_id('blob',raw))
        self.assertNotIn('PRIVATE_CANARY',json.dumps(receipt))

    def test_missing_nonregular_unexpected_or_tampered_build_inputs_fail(self):
        for mutation in ['missing','symlink','gitlink','extra','nested','tampered','size']:
            reader=Reader(); name='tools/cmd/license-inventory/main.go'
            if mutation=='missing': del reader.entries['tools/go.sum']
            if mutation=='symlink': reader.entries[name]['mode']='120000'
            if mutation=='gitlink': reader.entries[name].update(mode='160000',type='commit')
            if mutation in {'extra','nested'}:
                path='tools/cmd/license-inventory/'+('private.txt' if mutation=='extra' else 'nested/extra.go')
                reader.entries[path]=reader.entries[name].copy()
            if mutation=='tampered': reader.files[name]=b'PRIVATE_CANARY modified bytes'
            if mutation=='size': reader.files[name]=b'x'*(objects.MAX_BLOB_BYTES+1)
            with self.subTest(mutation=mutation),self.assertRaises(classifier.ClassifierError) as error:
                classifier.sources(reader,BASE)
            self.assertNotIn('CANARY',str(error.exception))


class BuildTests(unittest.TestCase):
    def fake_run(self,args,cwd,environment,**_kwargs):
        self.calls.append((args,Path(cwd),dict(environment)))
        if args==['go','telemetry','off']: return b''
        if args==['go','env','GOTELEMETRY']: return b'off\n'
        if args==['go','version']: return b'go version go1.27.3 linux/amd64\n'
        if args==['go','mod','edit','-json']:
            return json.dumps({'Module':{'Path':'github.com/aatuh/evydence/tools'},'Replace':self.replacements,
                               'Exclude':None}).encode()
        if args[:2]==['go','build']:
            self.assertEqual((Path(cwd)/'go.mod').read_bytes(),Reader().files['tools/go.mod'])
            self.assertEqual((Path(cwd)/'cmd/license-inventory/main.go').read_bytes(),Reader().files['tools/cmd/license-inventory/main.go'])
            self.assertFalse((Path(cwd)/'cmd/license-inventory/main_test.go').exists())
            Path(args[args.index('-o')+1]).write_bytes(b'trusted executable')
            if self.change_locks: (Path(cwd)/'go.sum').write_text('PRIVATE_CANARY changed lock')
            return b''
        if args==['go','mod','verify']: return b'all modules verified\n'
        raise AssertionError('unexpected subprocess')
    def setUp(self):
        self.calls=[]; self.replacements=None; self.change_locks=False

    def test_build_is_private_serial_and_uses_base_locks_without_ambient_credentials(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(inventory,'_run',side_effect=self.fake_run):
            root=Path(folder); owner=root/'owner-file'; owner.write_text('preserve')
            parent={'PATH':'/trusted/bin','HOME':'/PRIVATE_CANARY','GH_TOKEN':'PRIVATE_CANARY',
                    'GOAUTH':'PRIVATE_CANARY','GOFLAGS':'-toolexec=PRIVATE_CANARY',
                    'GOPROXY':'https://PRIVATE_CANARY','GOTOOLCHAIN':'auto','GOOS':'PRIVATE_CANARY',
                    'GOCACHE':str(root/'cache'),'GOMODCACHE':str(root/'modules')}
            result=classifier.build(Reader(),BASE,root,parent)
            self.assertEqual(result.receipt['binary_sha256'],hashlib.sha256(b'trusted executable').hexdigest())
            self.assertEqual(result.receipt['trusted_base'],BASE)
            self.assertEqual(owner.read_text(),'preserve')
            self.assertEqual(result.workspace.stat().st_mode&0o777,0o700)
            self.assertEqual(result.executable.read_bytes(),b'trusted executable')
            self.assertEqual([args[:2] for args,_,_ in self.calls],
                             [['go','telemetry'],['go','version'],['go','env'],['go','mod'],['go','build'],['go','mod']])
            for _args,cwd,environment in self.calls:
                self.assertTrue(cwd.is_relative_to(result.workspace))
                self.assertNotIn('PRIVATE_CANARY',json.dumps(environment))
                self.assertEqual(environment['GOTOOLCHAIN'],'local')
                self.assertEqual(environment['GOAUTH'],'off')
                self.assertEqual(environment['GOVCS'],'*:off')
                self.assertNotIn('GOTELEMETRY',environment)
                self.assertEqual(environment['CGO_ENABLED'],'0')
                self.assertEqual(environment['GOWORK'],'off')
            self.assertNotIn(str(root),json.dumps(result.receipt))
            self.assertEqual(result.receipt['telemetry'],'off')

    def test_wrong_compiler_or_enabled_telemetry_prevents_build_execution(self):
        for command in [['go','version'],['go','env','GOTELEMETRY']]:
            self.setUp()
            def run(args,*pos,**kwargs):
                if args==command: return b'PRIVATE_CANARY untrusted tool output'
                return self.fake_run(args,*pos,**kwargs)
            with self.subTest(command=command),tempfile.TemporaryDirectory() as folder, \
                 patch.object(inventory,'_run',side_effect=run),self.assertRaises(classifier.ClassifierError) as error:
                classifier.build(Reader(),BASE,Path(folder),{})
            self.assertNotIn('CANARY',str(error.exception))
            self.assertFalse(any(args[:2]==['go','build'] for args,_,_ in self.calls))

    def test_overrides_changed_locks_and_failed_verification_cannot_produce_an_artifact(self):
        for mutation in ['replace','changed-lock','verify']:
            self.setUp()
            if mutation=='replace': self.replacements=[{'Old':{'Path':'example.org/base'},'New':{'Path':'/PRIVATE_CANARY'}}]
            if mutation=='changed-lock': self.change_locks=True
            def run(args,*pos,**kwargs):
                if mutation=='verify' and args==['go','mod','verify']:
                    raise inventory.InventoryError('PRIVATE_CANARY private tool diagnostic')
                return self.fake_run(args,*pos,**kwargs)
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as folder, \
                 patch.object(inventory,'_run',side_effect=run),self.assertRaises(classifier.ClassifierError) as error:
                classifier.build(Reader(),BASE,Path(folder),{})
            self.assertNotIn('CANARY',str(error.exception))

    def test_modified_or_symlinked_executable_is_rejected_before_any_scan(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(inventory,'_run',side_effect=self.fake_run):
            result=classifier.build(Reader(),BASE,Path(folder),{})
            for mutation in ['changed','symlink']:
                if mutation=='changed': result.executable.write_bytes(b'PRIVATE_CANARY tamper')
                else:
                    result.executable.unlink(); result.executable.symlink_to(Path(folder)/'owner-file')
                with self.subTest(mutation=mutation),patch.object(inventory,'_classify_files') as scan, \
                     self.assertRaises(classifier.ClassifierError): result.classify([])
                scan.assert_not_called()

    def test_valid_scans_use_distinct_private_directories_and_the_verified_executable(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(inventory,'_run',side_effect=self.fake_run):
            result=classifier.build(Reader(),BASE,Path(folder),{})
            with patch.object(inventory,'_classify_files',return_value={'verified':'result'}) as scan:
                for _ in range(2): self.assertEqual(result.classify([]),{'verified':'result'})
            first,second=scan.call_args_list
            self.assertNotEqual(first.args[4],second.args[4])
            self.assertEqual(first.args[1],result.executable)
            self.assertEqual(first.args[2],result.workspace)

    def test_executable_changed_during_classification_cannot_return_results(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(inventory,'_run',side_effect=self.fake_run):
            result=classifier.build(Reader(),BASE,Path(folder),{})
            def tamper(*_args):
                result.executable.write_bytes(b'PRIVATE_CANARY changed during scan')
                return {'untrusted':'result'}
            with patch.object(inventory,'_classify_files',side_effect=tamper),self.assertRaises(classifier.ClassifierError):
                result.classify([])

    def test_cli_protects_existing_owner_output_before_starting_a_build(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); output=root/'owner.json'; output.write_text('PRIVATE_CANARY owner content')
            args=['--root',str(root),'--trusted-base',BASE,'--work-root',str(root),
                  '--output','owner.json','--replace']
            error=io.StringIO()
            with patch.object(classifier,'build') as build,patch.object(classifier.sys,'stderr',error):
                self.assertEqual(classifier.main(args),2)
            build.assert_not_called()
            self.assertEqual(output.read_text(),'PRIVATE_CANARY owner content')
            self.assertNotIn('CANARY',error.getvalue())


if __name__=='__main__': unittest.main()
