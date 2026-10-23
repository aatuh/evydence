#!/usr/bin/env python3
"""Bounded read-only maintenance provider regression tests."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dependency_maintenance_sources as sources


class MetadataTests(unittest.TestCase):
    def test_repository_urls_accept_only_known_public_github_forms(self):
        for value in ['https://github.com/Owner/repo.git', 'git+https://github.com/Owner/repo',
                      'git://github.com/Owner/repo.git', 'git@github.com:Owner/repo.git']:
            self.assertEqual(sources.github_repository(value), 'owner/repo')
        for value in ['https://SECRET_CANARY@github.com/a/b', 'https://github.com/a/../b',
                      'https://github.com/a/b?secret=PRIVATE_CANARY', 'https://other.invalid/a/b']:
            self.assertIsNone(sources.github_repository(value))

    def test_go_proxy_origin_and_identity_are_bound_without_vanity_requests(self):
        value = {'Version':'v1.2.3', 'Time':'2024-01-01T00:00:00Z',
                 'Origin':{'VCS':'git','URL':'https://github.com/A/B','Hash':'a'*40}}
        with patch.object(sources,'read_json',return_value=value) as read:
            result = sources.go_metadata('example.org/A/module','v1.2.3')
        self.assertEqual(result['repository'],'a/b')
        self.assertEqual(read.call_args.args[0], 'https://proxy.golang.org/example.org/!a/module/@v/v1.2.3.info')
        value['Version']='v9.0.0'
        with patch.object(sources,'read_json',return_value=value), self.assertRaises(sources.SourceError):
            sources.go_metadata('example.org/A/module','v1.2.3')
        for name in ['../escape','example.org/a/../b','https://SECRET_CANARY@a/b']:
            with self.subTest(name=name), self.assertRaises(sources.SourceError): sources.go_metadata(name,'v1.2.3')

    def test_npm_uses_exact_version_time_repository_and_deprecation_without_public_prose(self):
        data={'name':'@scope/name','versions':{'1.2.3':{'name':'@scope/name','version':'1.2.3',
              'repository':{'url':'git+https://github.com/A/B.git'},'deprecated':'PRIVATE_CANARY prose'}},
              'time':{'1.2.3':'2024-01-01T00:00:00Z'}}
        with patch.object(sources,'read_json',return_value=data) as read:
            result=sources.npm_metadata('@scope/name','1.2.3')
        self.assertEqual(read.call_args.args[0],'https://registry.npmjs.org/%40scope%2Fname')
        self.assertEqual(result['repository'],'a/b'); self.assertTrue(result['deprecated'])
        self.assertNotIn('CANARY',json.dumps(result))
        data['versions']['1.2.3']['version']='9.0.0'
        with patch.object(sources,'read_json',return_value=data), self.assertRaises(sources.SourceError):
            sources.npm_metadata('@scope/name','1.2.3')

    def test_missing_or_oversized_metadata_is_explicit_and_never_healthy(self):
        for status in ['not-found','over-budget']:
            with patch.object(sources,'read_json',return_value={'unavailable':status}):
                result=sources.npm_metadata('name','1.2.3')
                self.assertEqual(result['metadata_status'],status)
                self.assertIsNone(result['repository'])
                self.assertIsNone(result['version_timestamp'])

    def test_python_identity_and_repository_are_projected_without_contact_fields(self):
        data={'info':{'name':'PyYAML','version':'6.0.3','author_email':'PRIVATE_CANARY',
                      'project_urls':{'Source':'https://github.com/yaml/pyyaml','Homepage':'https://pyyaml.org'}}}
        with patch.object(sources,'read_json',return_value=data):
            result=sources.pypi_metadata('PyYAML','6.0.3')
            self.assertEqual(result['repository'],'yaml/pyyaml')
            self.assertNotIn('CANARY',json.dumps(result))
            data['info']['name']=None
            with self.assertRaises(sources.SourceError): sources.pypi_metadata('PyYAML','6.0.3')


class GraphQLTests(unittest.TestCase):
    def test_cli_not_found_exit_keeps_json_but_auth_failures_do_not_become_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            executable=Path(folder)/'gh'
            executable.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"data":{"r0":null},"errors":[{"type":"NOT_FOUND","path":["r0"]}]}\'\nexit 1\n')
            executable.chmod(0o700)
            with patch.dict(os.environ, {'PATH':folder+':/usr/bin:/bin'}):
                result=sources.repositories({'a/b':{'commits':[],'releases':[]}})
                self.assertEqual(result['a/b']['metadata_status'],'not-found')
                executable.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"message":"PRIVATE_CANARY authentication failed"}\'\nexit 1\n')
                with self.assertRaises(sources.SourceError) as error:
                    sources.repositories({'a/b':{'commits':[],'releases':[]}})
                self.assertNotIn('CANARY',str(error.exception))

    def test_batches_project_only_public_status_and_commit_dates(self):
        response={'data':{'r0':{'nameWithOwner':'New/Name','isPrivate':False,'isArchived':True,
                   'isDisabled':False,'pushedAt':'2024-01-01T00:00:00Z','private':'PRIVATE_CANARY',
                   'c0':{'oid':'a'*40,'committedDate':'2020-01-01T00:00:00Z'}}}}
        with patch.object(sources,'graphql',return_value=response) as query:
            result=sources.repositories({'old/name':{'commits':['a'*40], 'releases':[]}})
        self.assertEqual(result['old/name']['canonical_repository'],'new/name')
        self.assertTrue(result['old/name']['archived'])
        self.assertEqual(result['old/name']['commits']['a'*40],'2020-01-01T00:00:00Z')
        self.assertNotIn('CANARY',json.dumps(result))
        self.assertNotIn('mutation',query.call_args.args[0])

    def test_not_found_is_a_gap_but_provider_and_identity_errors_fail(self):
        request={'a/b':{'commits':[], 'releases':[]}}
        response={'data':{'r0':None},'errors':[{'type':'NOT_FOUND','path':['r0'],'message':'PRIVATE_CANARY'}]}
        with patch.object(sources,'graphql',return_value=response):
            self.assertEqual(sources.repositories(request)['a/b']['metadata_status'],'not-found')
        for value in [{'errors':[{'type':'RATE_LIMITED','message':'PRIVATE_CANARY'}]},
                      {'data':{'r0':{'isPrivate':True}}},
                      {'data':{'r0':{'nameWithOwner':'a/b','isPrivate':False,'isArchived':'false','isDisabled':False,'pushedAt':None}}}]:
            with self.subTest(value=value), patch.object(sources,'graphql',return_value=value), self.assertRaises(sources.SourceError) as error:
                sources.repositories(request)
            self.assertNotIn('CANARY',str(error.exception))

    def test_limits_and_alias_validation_fail_before_provider_calls(self):
        for name in ['a/b/../c','SECRET_CANARY@a/b','a/b?query']:
            with self.subTest(name=name), patch.object(sources,'graphql') as query, self.assertRaises(sources.SourceError):
                sources.repositories({name:{'commits':[],'releases':[]}})
            query.assert_not_called()
        with patch.object(sources,'MAX_REPOSITORIES',0), patch.object(sources,'graphql') as query, self.assertRaises(sources.SourceError):
            sources.repositories({'a/b':{'commits':[],'releases':[]}})
        query.assert_not_called()


class HTTPTests(unittest.TestCase):
    def test_fixed_hosts_no_proxy_redirects_and_transport_budget(self):
        class Response(io.BytesIO):
            status=200; headers={}
            def geturl(self): return 'https://registry.npmjs.org/name'
        with patch.object(sources.urllib.request,'build_opener') as build:
            build.return_value.open.return_value=Response(b'{"name":"name"}')
            self.assertEqual(sources.read_json('https://registry.npmjs.org/name'),{'name':'name'})
            self.assertEqual(build.call_args.args[0].proxies,{})
        for url in ['http://registry.npmjs.org/name','https://SECRET_CANARY@registry.npmjs.org/name',
                    'https://other.invalid/name','https://registry.npmjs.org/name?secret=PRIVATE_CANARY']:
            with self.subTest(url=url), self.assertRaises(sources.SourceError) as error: sources.read_json(url)
            self.assertNotIn('CANARY',str(error.exception))
        with patch.object(sources,'MAX_BYTES',3), patch.object(sources.urllib.request,'build_opener') as build:
            build.return_value.open.return_value=Response(b'{"name":"name"}')
            self.assertEqual(sources.read_json('https://registry.npmjs.org/name'),{'unavailable':'over-budget'})


if __name__=='__main__': unittest.main()
