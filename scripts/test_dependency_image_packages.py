#!/usr/bin/env python3
"""Image package queries need bound distro/source metadata, never name guesses."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import dependency_image_packages as packages
import dependency_advisories as advisories


def apk():
    return {'name':'libcrypto3','version':'3.5.4-r0','type':'apk',
            'purl':'pkg:apk/alpine/libcrypto3@3.5.4-r0?arch=x86_64&distro=alpine-3.23.6&upstream=openssl',
            'licenses':[{'spdxExpression':'Apache-2.0'}],'metadataType':'apk-db-entry',
            'metadata':{'package':'libcrypto3','originPackage':'openssl','version':'3.5.4-r0','architecture':'x86_64',
                        'maintainer':'PRIVATE_CANARY','description':'PRIVATE_CANARY','files':[],'installedSize':1}}


def deb():
    return {'name':'libssl3','version':'3.0.17-1~deb12u2+b1','type':'deb',
            'purl':'pkg:deb/debian/libssl3@3.0.17-1~deb12u2%2Bb1?arch=amd64&distro=debian-12.12',
            'licenses':[{'spdxExpression':'Apache-2.0'}],'metadataType':'dpkg-db-entry',
            'metadata':{'package':'libssl3','source':'openssl','version':'3.0.17-1~deb12u2+b1',
                        'sourceVersion':'3.0.17-1~deb12u2','architecture':'amd64','maintainer':'PRIVATE_CANARY'}}


class PackageTests(unittest.TestCase):
    def test_standard_library_uses_recorded_matching_go_version_without_inventing_main_versions(self):
        row={'name':'stdlib','version':'go1.27.3','type':'go-module','purl':'pkg:golang/stdlib@1.27.3',
             'licenses':[],'metadataType':'go-module-buildinfo-entry','metadata':{'goCompiledVersion':'go1.27.3'}}
        value=packages.project(row)
        expected={'package':{'ecosystem':'Go','name':'stdlib'},'version':'1.27.3'}
        self.assertEqual(value['advisory_query'],expected)
        advisories.validate_query(expected)
        for compiler in ['go1.27.2','go1.27rc1',None]:
            row['metadata']['goCompiledVersion']=compiler
            with self.subTest(compiler=compiler):self.assertIsNone(packages.project(row)['advisory_query'])
        for request in [{**expected,'version':'latest'},{**expected,'version':'go1.27.3'},
                        {**expected,'package':{'ecosystem':'Go','name':'cmd/go'}},
                        {**expected,'version':'1.27.3;PRIVATE_CANARY'}]:
            with self.subTest(request=request),self.assertRaises(advisories.AdvisoryError):advisories.validate_query(request)

    def test_alpine_uses_branch_and_bound_upstream_name_not_binary_subpackage(self):
        value=packages.project(apk())
        self.assertEqual(value['advisory_query'],{'package':{'ecosystem':'Alpine:v3.23','name':'openssl'},'version':'3.5.4-r0'})
        self.assertEqual(value['component'],{'ecosystem':'docker','name':'alpine/3.23/libcrypto3','version':'3.5.4-r0'})
        self.assertNotIn('CANARY',json.dumps(value));self.assertFalse(value['metadata_only'])

    def test_debian_uses_source_version_and_requires_evidence_for_binary_rebuilds(self):
        value=packages.project(deb())
        self.assertEqual(value['advisory_query'],{'package':{'ecosystem':'Debian:12','name':'openssl'},'version':'3.0.17-1~deb12u2'})
        self.assertEqual(value['component']['version'],'3.0.17-1~deb12u2+b1')
        for mutation in [{'sourceVersion':''},{'source':'','sourceVersion':''}]:
            row=deb();row['metadata'].update(mutation)
            self.assertIsNone(packages.project(row)['advisory_query'])
        row=deb();row['version']='3.0.17-1~deb12u2';row['purl']=row['purl'].replace('%2Bb1','');row['metadata'].update(version=row['version'],source='',sourceVersion='')
        self.assertEqual(packages.project(row)['advisory_query']['package']['name'],'libssl3')

    def test_go_metadata_keeps_public_integrity_without_paths_contacts_or_invented_versions(self):
        row={'name':'example.org/pkg','version':'v1.2.3','type':'go-module','purl':'pkg:golang/example.org/pkg@v1.2.3',
             'licenses':[],'metadataType':'go-module-buildinfo-entry','metadata':{'h1Digest':'h1:'+'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
             'goCompiledVersion':'go1.27.3','mainModule':'PRIVATE_CANARY','goBuildSettings':[{'key':'-ldflags','value':'PRIVATE_CANARY'}]}}
        value=packages.project(row)
        self.assertEqual(value['component'],{'ecosystem':'gomod','name':'example.org/pkg','version':'v1.2.3'})
        self.assertEqual(value['advisory_query']['package'],{'ecosystem':'Go','name':'example.org/pkg'})
        self.assertIn('h1:',value['module_sum']);self.assertNotIn('CANARY',json.dumps(value))
        row.update(name='cmd/asm',version='UNKNOWN',purl='pkg:golang/cmd/asm');row['metadata'].pop('h1Digest')
        self.assertIsNone(packages.project(row)['advisory_query'])

    def test_missing_contradictory_or_unsupported_context_never_silently_uses_a_query(self):
        for mutation in ['source','distro','namespace','arch','metadata-type','upstream']:
            row=apk()
            if mutation=='source':row['metadata']['package']='other'
            if mutation=='distro':row['purl']=row['purl'].replace('alpine-3.23.6','alpine-edge')
            if mutation=='namespace':row['purl']=row['purl'].replace('apk/alpine/','apk/other/')
            if mutation=='arch':row['metadata']['architecture']='arm64'
            if mutation=='metadata-type':row['metadataType']='other'
            if mutation=='upstream':row['metadata']['originPackage']='other'
            with self.subTest(mutation=mutation):self.assertIsNone(packages.project(row)['advisory_query'])

    def test_only_empty_named_virtual_apk_records_are_metadata_only(self):
        row=apk();row.update(name='.rundeps',version='20261022.1234',purl='pkg:apk/alpine/.rundeps@20261022.1234?arch=noarch&distro=alpine-3.23.6')
        row['metadata'].update(package=row['name'],originPackage=row['name'],version=row['version'],architecture='noarch',installedSize=0,files=[])
        value=packages.project(row);self.assertTrue(value['metadata_only']);self.assertIsNone(value['advisory_query'])
        row['metadata']['files']=[{'path':'/bin/executable'}];self.assertFalse(packages.project(row)['metadata_only'])
        row['metadata']['files']=[];row['metadata']['installedSize']=1;self.assertFalse(packages.project(row)['metadata_only'])

    def test_scanner_bytes_are_bound_and_duplicate_metadata_cannot_rebind_source_queries(self):
        raw=json.dumps({'artifacts':[apk()]}).encode();observation={'scanner_output_sha256':hashlib.sha256(raw).hexdigest()}
        self.assertEqual(len(packages.from_scanner(raw,observation)),1)
        with self.assertRaises(packages.PackageError):packages.from_scanner(raw+b' ',observation)
        duplicate=apk();duplicate['metadata']['originPackage']='other'
        raw=json.dumps({'artifacts':[apk(),duplicate]}).encode();observation['scanner_output_sha256']=hashlib.sha256(raw).hexdigest()
        with self.assertRaises(packages.PackageError):packages.from_scanner(raw,observation)


class QueryTests(unittest.TestCase):
    def test_cache_and_response_package_binding_include_exact_distribution_source_query(self):
        value=packages.project(apk());client=advisories.Client()
        original=value['advisory_query'];changed=copy.deepcopy(original)
        changed['package']['ecosystem']='Alpine:v3.22'
        with patch.object(client,'request',return_value={}) as request:
            client.observe_query(value['component'],original)
            client.observe_query(value['component'],changed)
            client.observe_query(value['component'],original)
        self.assertEqual(request.call_count,2)
        record={'id':'CVE-2026-12345','modified':'2026-10-21T00:00:00Z',
                'affected':[{'package':{'ecosystem':'Alpine:v3.22','name':'openssl'}}]}
        with patch.object(advisories.Client,'request',return_value={'vulns':[record]}):
            result=advisories.Client().observe_query(value['component'],original)
        self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['vulnerabilities'])
        record['affected'][0]['package']={'ecosystem':'Alpine:v3.23','name':'libcrypto3'}
        with patch.object(advisories.Client,'request',return_value={'vulns':[record]}):
            self.assertEqual(advisories.Client().observe_query(value['component'],original)['status'],'unavailable')
        with self.assertRaises(advisories.AdvisoryError):
            advisories.Client().observe_query(value['component'],{**original,'page_token':'skip-first-page'})

    def test_supported_distro_query_is_not_confused_with_installed_package_identity(self):
        value=packages.project(apk());client=advisories.Client()
        record={'id':'CVE-2026-12345','modified':'2026-10-21T00:00:00Z','affected':[{'package':{'ecosystem':'Alpine:v3.23','name':'openssl'}}],
                'database_specific':{'severity':'HIGH'}}
        with patch.object(client,'request',return_value={'vulns':[record]}) as request:
            observed=client.observe_query(value['component'],value['advisory_query'])
        self.assertEqual(observed['component'],value['component']);self.assertEqual(observed['status'],'observed')
        self.assertEqual(observed['vulnerabilities'],[{'id':'CVE-2026-12345','severity':'high'}])
        request.assert_called_once_with(value['advisory_query'])
        for request in [{'package':{'ecosystem':'Alpine:edge','name':'openssl'},'version':'3.0.0-r0'},
                        {'package':{'ecosystem':'Debian:12','name':'../PRIVATE_CANARY'},'version':'1'},
                        {'package':{'ecosystem':'Debian:12','name':'openssl'},'version':'latest'}]:
            with self.subTest(request=request),self.assertRaises(advisories.AdvisoryError):advisories.validate_query(request)


if __name__=='__main__':unittest.main()
