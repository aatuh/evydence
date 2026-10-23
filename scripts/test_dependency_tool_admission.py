#!/usr/bin/env python3
"""Downloaded QA tools retain every bundled package's own policy decision."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import dependency_tool_admission as tools
from test_dependency_admission import API,BASE,HEAD,Reader,RULES,TODAY,collection
from test_dependency_build_tools import archive,component
from test_dependency_tool_buildinfo import SUM


class QueryAPI(API):
    def observe_query(self,component,_query):return self.observe(component)


def row():
    value=component(archive());value.update(license='Apache-2.0',license_status='candidate')
    value['source'].update(verification='sha256-verified',binary_sha256='d'*64)
    return value


def inspection(value):
    return {'archive_sha256':value['source']['sha256'],'binary_sha256':'d'*64,
        'reader_go_version':'go1.27.3','buildinfo_sha256':'e'*64,'buildinfo':{
        'go_version':'go1.27.1','main':{'name':'helm.sh/helm/v4','version':'v'+value['version'].removeprefix('v'),
            'replacement':None},'platform':{'goos':'linux','goarch':'amd64','cgo_enabled':False},
        'modules':[{'name':'example.org/library','version':'v1.2.3','sum':SUM,'replacement':None}]}}


class ToolTests(unittest.TestCase):
    def setup_client(self,folder,*,api=None,license='MIT'):
        value=row();observed=collection(HEAD,[value]);classifier=Mock();classifier.receipt={'trusted_base':BASE,'go_version':'go1.27.3'}
        deps=Mock()
        def resolve(name,version,checksum):
            return {'ecosystem':'gomod','name':name,'version':version,'license':license,
                    'license_status':'candidate','license_evidence':[],
                    'source':{'sum':checksum or SUM,'verification':'go-module-zip-h1'}}
        deps.resolve.side_effect=resolve
        def fetch(_row,work):
            (work/(_row['source']['sha256']+'.tar.gz')).write_bytes(archive())
            return {'binary_sha256':'d'*64},[]
        patches=[patch.object(tools.sources,'Sources',return_value=deps),
            patch.object(tools.build_tools,'fetch',side_effect=fetch),
            patch.object(tools.buildinfo,'inspect',return_value=inspection(value)),
            patch.object(tools.inventory,'attach_licenses',return_value=value)]
        handles=[p.start() for p in patches];self.addCleanup(lambda:[p.stop() for p in reversed(patches)])
        client=tools.Client(api or QueryAPI(),observed,BASE,HEAD,Path(folder),{},classifier,Reader(),TODAY)
        return client,value,handles,deps,classifier

    def test_exact_artifact_root_bundled_module_and_stdlib_are_separate_and_cached(self):
        with tempfile.TemporaryDirectory() as folder:
            client,value,handles,deps,classifier=self.setup_client(folder)
            result=client.observe(value);self.assertEqual(result['component'],tools.advisories.identity(value))
            self.assertEqual(result['status'],'observed');self.assertEqual(result['vulnerabilities'],[])
            self.assertEqual(client.observe(value),result);handles[1].assert_called_once()
            report=client.evidence();self.assertTrue(report['tool_decision_passed']);self.assertTrue(report['tool_coverage_verified'])
            self.assertEqual(len(report['package_changes']),2)
            self.assertEqual(report['package_changes'][0]['name'],'example.org/library')
            self.assertEqual(report['package_changes'][1]['name'],'stdlib')
            self.assertEqual(report['package_changes'][1]['version'],'go1.27.1')
            self.assertEqual(deps.resolve.call_args_list[1].args,('golang.org/toolchain','v0.0.1-go1.27.1.linux-amd64',None))
            self.assertNotIn(folder,str(report));classifier.verify.assert_called()

    def test_high_findings_and_disallowed_child_licenses_cannot_hide_under_root_license(self):
        for license,findings in [('GPL-3.0-only',[]),('MIT',[{'id':'GHSA-abcd-efgh-2345','severity':'high'}])]:
            with self.subTest(license=license),tempfile.TemporaryDirectory() as folder:
                client,value,*_=self.setup_client(folder,license=license,api=QueryAPI(vulnerabilities=findings))
                client.observe(value);report=client.evidence()
                self.assertFalse(report['tool_decision_passed']);self.assertTrue(report['tool_coverage_verified'])
                self.assertTrue(all(not row['passed'] for row in report['package_changes']))
                self.doCleanups()

    def test_unknown_or_unbound_platform_main_compiler_sum_and_replacements_fail(self):
        for reason in ['main','compiler','sum','replacement','cgo','binary','license']:
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as folder:
                client,value,handles,*_=self.setup_client(folder);metadata=handles[2].return_value
                if reason=='main':metadata['buildinfo']['main']['version']='v9.0.0'
                if reason=='compiler':metadata['buildinfo']['go_version']=None
                if reason=='sum':metadata['buildinfo']['modules'][0]['sum']=None
                if reason=='replacement':metadata['buildinfo']['modules'][0]['replacement']={'kind':'local'}
                if reason=='cgo':metadata['buildinfo']['platform']['cgo_enabled']=True
                if reason=='binary':metadata['binary_sha256']='f'*64
                if reason=='license':handles[3].return_value={**value,'license':'MIT'}
                with self.assertRaises(tools.ToolAdmissionError):client.observe(value)
                self.doCleanups()

    def test_unavailable_advisories_remain_null_and_block_child_decisions(self):
        with tempfile.TemporaryDirectory() as folder:
            client,value,*_=self.setup_client(folder,api=QueryAPI(status='unavailable'))
            result=client.observe(value);self.assertIsNone(result['vulnerabilities'])
            self.assertFalse(client.evidence()['tool_decision_passed'])
            for value in client.evidence()['package_changes']:
                self.assertIsNone(value['vulnerabilities']);self.assertIn('advisory_coverage_unknown',value['violations'])

    def test_uncollected_roots_unverified_classifier_and_child_approvals_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            client,value,*_=self.setup_client(folder)
            other={**value,'version':'99.0.0'}
            with self.assertRaises(tools.ToolAdmissionError):client.observe(other)
            client.observe(value)
            with patch.object(tools.reviews,'verify',return_value=[{'exception_id':'unexpected'}]),self.assertRaises(tools.ToolAdmissionError):
                client.verify()

    def test_non_generic_observations_use_the_same_underlying_advisory_client(self):
        with tempfile.TemporaryDirectory() as folder:
            api=API();client,*_=self.setup_client(folder,api=api)
            value={'ecosystem':'gomod','name':'example.org/other','version':'v1.0.0'}
            self.assertEqual(client.observe(value)['component'],value);self.assertEqual(api.calls,[value])

    def test_classifier_must_belong_to_the_current_target_base_before_artifact_work(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(tools.build_tools,'fetch') as fetch:
            classifier=Mock();classifier.receipt={'trusted_base':HEAD,'go_version':'go1.27.3'}
            with self.assertRaises(tools.ToolAdmissionError):
                tools.Client(QueryAPI(),collection(HEAD,[row()]),BASE,HEAD,Path(folder),{},classifier,Reader(),TODAY)
            fetch.assert_not_called()


if __name__=='__main__':unittest.main()
