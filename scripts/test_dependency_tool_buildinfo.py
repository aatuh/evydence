#!/usr/bin/env python3
"""Build-tool metadata is checksum-bound data; targets and private flags never run."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_tool_buildinfo as buildinfo
from test_dependency_build_tools import archive,component

SUM='h1:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE='


def document():
    return {'GoVersion':'go1.27.3','Path':'helm.sh/helm/v4/cmd/helm',
        'Main':{'Path':'helm.sh/helm/v4','Version':'(devel)'},
        'Deps':[{'Path':'example.org/library','Version':'v1.2.3','Sum':SUM}],
        'Settings':[{'Key':'GOOS','Value':'linux'},{'Key':'GOARCH','Value':'amd64'},
                    {'Key':'CGO_ENABLED','Value':'0'},{'Key':'-ldflags','Value':'PRIVATE_CANARY'},
                    {'Key':'vcs.revision','Value':'PRIVATE_CANARY'}]}


class ProjectionTests(unittest.TestCase):
    def test_public_coordinates_sums_and_platform_are_retained_without_invented_main_version(self):
        result=buildinfo.project(json.dumps(document()).encode())
        self.assertEqual(result['go_version'],'go1.27.3');self.assertEqual(result['main']['name'],'helm.sh/helm/v4')
        self.assertIsNone(result['main']['version']);self.assertEqual(result['main']['version_state'],'development')
        self.assertEqual(result['modules'][0]['sum'],SUM)
        self.assertEqual(result['platform'],{'goos':'linux','goarch':'amd64','cgo_enabled':False})
        self.assertNotIn('CANARY',json.dumps(result));self.assertNotIn('ldflags',json.dumps(result))

    def test_omitted_fields_and_unknown_compiler_or_module_versions_stay_explicit(self):
        data=document();data.pop('GoVersion');data.pop('Deps');data.pop('Settings');data['Main'].pop('Version')
        result=buildinfo.project(json.dumps(data).encode())
        self.assertIsNone(result['go_version']);self.assertIsNone(result['main']['version'])
        self.assertEqual(result['modules'],[]);self.assertIsNone(result['platform']['cgo_enabled'])
        data=document();data['Deps'][0].pop('Sum')
        self.assertIsNone(buildinfo.project(json.dumps(data).encode())['modules'][0]['sum'])

    def test_replacements_remain_distinct_and_local_paths_are_not_exported(self):
        data=document();data['Deps'][0]['Replace']={'Path':'../PRIVATE_CANARY','Version':''}
        result=buildinfo.project(json.dumps(data).encode())
        self.assertEqual(result['modules'][0]['replacement']['kind'],'local')
        self.assertNotIn('CANARY',json.dumps(result))
        data['Deps'][0]['Replace']={'Path':'example.org/fork','Version':'v1.2.4','Sum':SUM}
        result=buildinfo.project(json.dumps(data).encode())
        self.assertEqual(result['modules'][0]['replacement']['name'],'example.org/fork')
        self.assertEqual(result['modules'][0]['replacement']['kind'],'module')

    def test_duplicates_malformed_sums_paths_settings_and_replacement_chains_fail_safely(self):
        for operation in ['duplicate','sum','path','settings','chain','shape']:
            data=document()
            if operation=='duplicate':data['Deps'].append(copy.deepcopy(data['Deps'][0]))
            if operation=='sum':data['Deps'][0]['Sum']='h1:PRIVATE_CANARY'
            if operation=='path':data['Main']['Path']='/PRIVATE_CANARY/private'
            if operation=='settings':data['Settings'].append({'Key':'GOOS','Value':'windows'})
            if operation=='chain':data['Deps'][0]['Replace']={'Path':'example.org/fork','Version':'v1.2.4','Replace':{}}
            if operation=='shape':data['Deps']=None
            with self.subTest(operation=operation),self.assertRaises(buildinfo.BuildInfoError) as error:
                buildinfo.project(json.dumps(data).encode())
            self.assertNotIn('CANARY',str(error.exception))
        for raw in [b'{"Main":{},"Main":{}}',b'NaN',b'[]']:
            with self.subTest(raw=raw),self.assertRaises(buildinfo.BuildInfoError):buildinfo.project(raw)


class InspectionTests(unittest.TestCase):
    def test_only_named_verified_binary_is_materialized_nonexecutable_and_inspected_as_data(self):
        raw=archive();row=component(raw)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);calls=[]
            def run(arguments,work,environment,**options):
                calls.append(arguments)
                self.assertEqual(environment['GOTOOLCHAIN'],'local');self.assertEqual(environment['GOAUTH'],'off')
                self.assertNotIn('GH_TOKEN',environment);self.assertNotIn('PRIVATE_CANARY',environment)
                if arguments==['go','version']:return b'go version go1.27.3 linux/amd64\n'
                self.assertEqual(arguments[:4],['go','version','-m','-json'])
                target=Path(arguments[4]);self.assertEqual(target.read_bytes(),b'unexecuted binary')
                self.assertEqual(target.stat().st_mode&0o777,0o600)
                self.assertIsNone(options.get('log'))
                return json.dumps(document()).encode()
            with patch.object(buildinfo.inventory,'_run',side_effect=run):
                result=buildinfo.inspect(raw,row,root,{'PATH':'/usr/bin','GH_TOKEN':'PRIVATE_CANARY'},'go1.27.3')
            self.assertEqual(len(calls),2);self.assertEqual(result['binary_sha256'],hashlib.sha256(b'unexecuted binary').hexdigest())
            self.assertNotIn(str(root),json.dumps(result));self.assertNotIn('CANARY',json.dumps(result))

    def test_bad_archive_does_not_reach_go_or_create_a_target_and_existing_files_are_preserved(self):
        raw=archive();row=component(raw)
        with tempfile.TemporaryDirectory() as folder,patch.object(buildinfo.inventory,'_run') as run:
            root=Path(folder)
            with self.assertRaises(buildinfo.BuildInfoError):buildinfo.inspect(raw+b'changed',row,root,{},'go1.27.3')
            run.assert_not_called();self.assertEqual(list(root.iterdir()),[])
            target=root/'artifact-go-binary';target.write_text('PRIVATE_CANARY owner file')
            with self.assertRaises(buildinfo.BuildInfoError):buildinfo.inspect(raw,row,root,{},'go1.27.3')
            self.assertIn('CANARY',target.read_text());run.assert_not_called()

    def test_reader_version_and_concurrent_binary_changes_cannot_be_accepted(self):
        for operation in ['reader','binary']:
            raw=archive();row=component(raw)
            with self.subTest(operation=operation),tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                def run(arguments,*_args,**_kwargs):
                    if arguments==['go','version']:return b'go version go1.27.2 linux/amd64' if operation=='reader' else b'go version go1.27.3 linux/amd64'
                    (root/'artifact-go-binary').write_text('PRIVATE_CANARY concurrent edit')
                    return json.dumps(document()).encode()
                with patch.object(buildinfo.inventory,'_run',side_effect=run),self.assertRaises(buildinfo.BuildInfoError):
                    buildinfo.inspect(raw,row,root,{},'go1.27.3')


if __name__=='__main__':unittest.main()
