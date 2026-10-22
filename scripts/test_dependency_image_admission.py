#!/usr/bin/env python3
"""Changed image declarations need real package evidence under current base policy."""
import copy
from datetime import date
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import dependency_image_admission as admission
import dependency_images as images
from test_dependency_admission import BASE,HEAD,Reader,API,collection
from test_dependency_image_packages import apk
from test_dependency_images import scanner
from test_dependency_exception_reviews import Provider,comment,exception

TODAY=date(2026,10,22)


def declaration(reference='docker.io/library/alpine:3.23',*,kind='registry',locations=None,**extra):
    return {'reference':reference,'kind':kind,'locations':locations or ['Dockerfile#base/0'],**extra}


def observed(commit,rows):
    return {'schema':admission.VIEW_SCHEMA,'source_commit':commit,'trusted_base':BASE,'declarations':rows,
            'source_input_sha256':{},'trusted_generator_sha256':{},'discovery_input_sha256':{}}


def package(*,version='3.5.4-r0',license='MIT',name='libcrypto3'):
    row=apk();row.update(name=name,version=version,licenses=[{'spdxExpression':license}])
    row['purl']=row['purl'].replace('libcrypto3',name).replace('3.5.4-r0',version)
    row['metadata'].update(package=name,version=version)
    return admission.packages.project(row)


class SourceAPI(API):
    def observe_query(self,row,query):
        self.calls.append((copy.deepcopy(row),copy.deepcopy(query)))
        return {'component':admission.advisories.identity(row),'status':self.status,
                'vulnerabilities':self.vulnerabilities if self.status=='observed' else None}


class ImageAdmissionTests(unittest.TestCase):
    def run_review(self,before,after,*,scans=None,api=None,scanner_available=True,reader=None,review_api=None):
        reader=Reader() if reader is None else reader;api=SourceAPI() if api is None else api
        instance=Mock();instance.receipt={'binary_sha256':'d'*64,'recipe_sha256':'e'*64};instance.receipts=[]
        instance.scan.side_effect=lambda row:scans[row['reference']]
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(admission,'view',side_effect=[observed(BASE,before),observed(HEAD,after)]), \
             patch.object(admission,'Scanner',return_value=instance) as create:
            result=admission.assess(reader,BASE,HEAD,collection(BASE,[]),collection(HEAD,[]),Path(folder),api,TODAY,
                                    syft=Path(folder)/'syft' if scanner_available else None,review_api=review_api)
        return result,instance,create,api

    def test_unchanged_declarations_and_removals_need_no_scanner_or_invented_package_scan(self):
        local=declaration('evydence-local-mc:20250813-7394ce0dd2a8',kind='source-build',recipe_sha256='a'*64)
        operator=declaration('${EVYDENCE_IMAGE:-evydence:local}',kind='operator-selected')
        for before,after in [([declaration(),local,operator],[declaration(),local,operator]),([declaration()],[])]:
            result,scan,create,api=self.run_review(before,after,scanner_available=False)
            self.assertTrue(result['image_decision_passed']);self.assertTrue(result['image_coverage_verified'])
            self.assertEqual(result['package_changes'],[]);create.assert_not_called();scan.scan.assert_not_called()
            self.assertEqual(api.calls,[]);self.assertFalse(result['complete_artifact_sbom'])

    def test_changed_image_checks_new_package_versions_and_preserves_unchanged_baseline_licenses(self):
        old=declaration('docker.io/library/alpine:3.23@sha256:'+'a'*64);new=declaration('docker.io/library/alpine:3.24')
        scans={old['reference']:[package(license='GPL-3.0-only'),package(name='other',version='1.0.0-r0')],
               new['reference']:[package(license='GPL-3.0-only'),package(name='other',version='1.0.1-r0')]}
        result,scan,_,api=self.run_review([old],[new],scans=scans)
        self.assertTrue(result['image_decision_passed']);self.assertEqual(scan.scan.call_count,2)
        self.assertEqual(len(result['package_changes']),1);self.assertEqual(result['package_changes'][0]['name'],'alpine/3.23/other')
        self.assertEqual(len(api.calls),1);self.assertEqual(api.calls[0][1]['package']['name'],'openssl')
        self.assertEqual(result['package_changes'][0]['added_origins'],[])

    def test_high_critical_unknown_advisories_and_disallowed_new_licenses_fail(self):
        new=declaration();scans={new['reference']:[package()]}
        for severity in ['low','high','critical','unknown']:
            result,*_=self.run_review([],[new],scans=scans,api=SourceAPI(vulnerabilities=[{'id':'CVE-2026-12345','severity':severity}]))
            self.assertEqual(result['image_decision_passed'],severity=='low')
        result,*_=self.run_review([],[new],scans={new['reference']:[package(license='GPL-3.0-only')]})
        self.assertFalse(result['image_decision_passed']);self.assertIn('disallowed_license',result['package_changes'][0]['violations'])
        result,*_=self.run_review([],[new],scans=scans,api=SourceAPI('unavailable'))
        self.assertFalse(result['image_decision_passed']);self.assertIsNone(result['package_changes'][0]['vulnerabilities'])

    def test_new_origin_is_admission_even_when_the_image_and_packages_already_exist(self):
        old=declaration(locations=['workflow.yml#jobs/qa/container'])
        new=declaration(locations=old['locations']+['compose.production-like.yml#services/api'])
        result,scan,_,api=self.run_review([old],[new],scans={old['reference']:[package(license='GPL-3.0-only')]})
        self.assertFalse(result['image_decision_passed']);self.assertEqual(scan.scan.call_count,1)
        self.assertEqual(result['package_changes'][0]['added_origins'],['compose.production-like.yml#services/api'])
        self.assertEqual(len(api.calls),1)

    def test_floating_baseline_tag_cannot_hide_new_admission_by_resolving_to_head_contents(self):
        old=declaration();new=declaration('docker.io/library/alpine:3.24')
        values=[package(license='GPL-3.0-only')]
        result,scan,_,_=self.run_review([old],[new],scans={old['reference']:values,new['reference']:values})
        self.assertFalse(result['image_decision_passed']);self.assertEqual(scan.scan.call_count,1)
        self.assertEqual(result['baseline_omissions'][0]['reason'],'mutable-baseline-reference')

    def test_changed_recipe_or_operator_choice_and_missing_scanner_remain_blocking(self):
        old=declaration('evydence-local-mc:20250813-7394ce0dd2a8',kind='source-build',recipe_sha256='a'*64)
        for before,after in [([old],[{**old,'recipe_sha256':'b'*64}]),
                             ([],[declaration('operator-selected',kind='operator-selected')]),
                             ([],[declaration()])]:
            result,scan,_,_=self.run_review(before,after,scanner_available=False)
            self.assertFalse(result['image_decision_passed']);self.assertFalse(result['image_coverage_verified'])
            self.assertTrue(result['coverage_gaps']);scan.scan.assert_not_called()

    def test_action_runtime_origins_do_not_change_only_because_action_commit_changed(self):
        old=declaration(locations=['owner/action@'+'a'*40+'#runtime/image'])
        new=declaration(locations=['owner/action@'+'b'*40+'#runtime/image'])
        result,_,create,_=self.run_review([old],[new],scanner_available=False)
        self.assertTrue(result['image_decision_passed']);create.assert_not_called()

    def test_unknown_unchanged_build_metadata_is_reassessed_on_image_replacement(self):
        old=declaration();new=declaration('docker.io/library/alpine:3.24')
        value=package();value['advisory_query']=None;value['metadata_profile']='unknown'
        result,*_=self.run_review([old],[new],scans={old['reference']:[value],new['reference']:[value]},api=SourceAPI('unsupported'))
        self.assertFalse(result['image_decision_passed']);self.assertEqual(len(result['package_changes']),1)
        result,_,_,api=self.run_review([],[new],scans={new['reference']:[value]},api=SourceAPI())
        self.assertFalse(result['image_decision_passed']);self.assertEqual(api.calls,[])

    def test_module_license_binding_requires_the_exact_verified_sum_and_preserves_conflicts(self):
        raw={'name':'example.org/module','version':'v1.2.3','type':'go-module','purl':'pkg:golang/example.org/module@v1.2.3',
             'licenses':[],'metadataType':'go-module-buildinfo-entry',
             'metadata':{'h1Digest':'h1:'+'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE='}}
        value=admission.packages.project(raw);key=tuple(value['component'].values())
        source={**value['component'],'license':'MIT','license_status':'candidate',
                'source':{'verification':'go-mod-verify','sum':value['module_sum']}}
        actual,profile=admission.effective(value,{key:source})
        self.assertEqual(actual['license'],'MIT');self.assertEqual(profile,'bound-module-source')
        changed=copy.deepcopy(source);changed['source']['sum']='h1:other'
        self.assertIsNone(admission.effective(value,{key:changed})[0]['license'])
        raw['licenses']=[{'spdxExpression':'GPL-3.0-only'}];conflict=admission.packages.project(raw)
        self.assertIsNone(admission.effective(conflict,{key:source})[0]['license'])

    def test_conflicting_or_rebound_package_evidence_and_untrusted_collections_cannot_pass(self):
        new=declaration();bad=package();bad['component']['name']='PRIVATE_CANARY'
        with self.assertRaises(admission.ImageAdmissionError):self.run_review([],[new],scans={new['reference']:[bad]})
        with self.assertRaises(admission.ImageAdmissionError):
            self.run_review([],[new],scans={new['reference']:[package(),package(license='GPL-3.0-only')]})
        with self.assertRaises(admission.ImageAdmissionError):self.run_review([],[new],scans={new['reference']:[]})
        with tempfile.TemporaryDirectory() as folder,self.assertRaises(admission.ImageAdmissionError):
            admission.assess(Reader(),BASE,HEAD,collection(BASE,[]),collection(BASE,[]),Path(folder),SourceAPI(),TODAY)

    def test_changed_unknown_license_observations_cannot_be_skipped_as_unchanged(self):
        old=declaration('docker.io/library/alpine:3.23@sha256:'+'a'*64);new=declaration('docker.io/library/alpine:3.24')
        raw=apk();raw['licenses']=[];previous=admission.packages.project(raw)
        raw['licenses']=[{'value':'NOASSERTION'}];proposed=admission.packages.project(raw)
        result,*_=self.run_review([old],[new],scans={old['reference']:[previous],new['reference']:[proposed]})
        self.assertFalse(result['image_decision_passed']);self.assertEqual(len(result['package_changes']),1)

    def test_only_verified_empty_virtual_records_have_no_payload_license_or_advisory_applicability(self):
        raw=apk();raw.update(name='.rundeps',version='20261022.1',
            purl='pkg:apk/alpine/.rundeps@20261022.1?arch=noarch&distro=alpine-3.23.6',licenses=[])
        raw['metadata'].update(package=raw['name'],originPackage=raw['name'],version=raw['version'],
                               architecture='noarch',installedSize=0,files=[])
        value=admission.packages.project(raw);new=declaration()
        result,_,_,api=self.run_review([],[new],scans={new['reference']:[value]})
        self.assertTrue(result['image_decision_passed']);self.assertEqual(api.calls,[])
        self.assertEqual(result['package_changes'][0]['license_applicability'],'not-applicable-no-payload')
        self.assertIsNone(result['package_changes'][0]['vulnerabilities'])
        bad=package();bad['metadata_only']=True
        with self.assertRaises(admission.ImageAdmissionError):self.run_review([],[new],scans={new['reference']:[bad]})

    def test_image_license_waiver_is_exact_scoped_and_rechecked_after_assessment(self):
        new=declaration();value=package(license='GPL-3.0-only')
        waiver={**exception(),**value['component']}
        rules={'schema':'evydence-dependency-policy.v1','allowed_licenses':['MIT'],'allowed_with':[],'exceptions':[waiver]}
        provider=Provider(comment(waiver))
        result,*_=self.run_review([],[new],scans={new['reference']:[value]},reader=Reader(rules),review_api=provider)
        self.assertTrue(result['image_decision_passed']);self.assertEqual(result['package_changes'][0]['exceptions'],['DEP-0001'])
        self.assertEqual(provider.calls,['issues/comments/456','issues/comments/456'])
        class Revoked(Provider):
            def get(self,path):
                if self.calls:self.data['body']='PRIVATE_CANARY revoked'
                return super().get(path)
        with self.assertRaises(admission.ImageAdmissionError):
            self.run_review([],[new],scans={new['reference']:[value]},reader=Reader(rules),review_api=Revoked(comment(waiver)))

    def test_package_origin_cross_product_has_a_total_bound_before_decision_allocation(self):
        row=declaration(locations=['workflow.yml#jobs/job'+str(index)+'/container' for index in range(512)])
        values=[package(name='package'+str(index)) for index in range(17)]
        with self.assertRaises(admission.ImageAdmissionError):admission.flatten([row],lambda _row:values,{})


class ViewTests(unittest.TestCase):
    def setup_view(self,root):
        helper='tools/cmd/license-inventory/main.go';script='scripts/dependency_inventory.py'
        self.code=root/'trusted';self.code.mkdir();(self.code/'scripts').mkdir()
        (self.code/script).write_bytes(b'trusted Python data')
        (self.code/'scripts/dependency_images.py').write_bytes(b'trusted discovery data')
        original={script:b'raise RuntimeError("PRIVATE_CANARY do not execute")',helper:b'PRIVATE_CANARY do not compile',
                  'Dockerfile':b'FROM alpine:3.23\n'}
        base_raw=b'package main // trusted base'
        files=[{'path':name,'git_blob':admission.objects.object_id('blob',raw),'mode':'100644','bytes':len(raw),
                'sha256':hashlib.sha256(raw).hexdigest(),'roles':['tooling']} for name,raw in sorted(original.items())]
        frozen={'commit':HEAD,'tree':'b'*40,'files':files,'missing_required':[],
                'unclassified_manifests':[],'schemas_verified':[]}
        entry={'type':'blob','mode':'100644','sha':admission.objects.object_id('blob',base_raw)}
        reader=Mock();reader.tree.return_value=('d'*40,{helper:entry});reader.blob.return_value=base_raw
        value=collection(HEAD,[]);value['source']=copy.deepcopy(frozen)
        value['inventory']['generator']={'files':{script:hashlib.sha256((self.code/script).read_bytes()).hexdigest(),
            helper:hashlib.sha256(base_raw).hexdigest()},'classifier':{'schema':admission.classifiers.SCHEMA,
            'trusted_base':BASE,'tree':'d'*40,'sources':{helper:{'git_blob':entry['sha'],'mode':'100644',
                'sha256':hashlib.sha256(base_raw).hexdigest()}}}}
        value['inventory']['inputs']={name:hashlib.sha256(raw).hexdigest() for name,raw in original.items()}
        return reader,value,frozen,original,helper,script,base_raw

    def test_large_non_action_inventory_stays_bound_without_entering_discovery_input(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);reader,value,frozen,original,helper,script,_=self.setup_view(root)
            value['inventory']['components']=[{'ecosystem':'npm','name':'example-'+str(index),'version':'1.2.3',
                'license':'MIT','license_status':'artifact-declared','origins':['marketing'],'source':{'bounded_data':'x'*300000}}
                for index in range(4)]
            def discover(work):
                projection=json.loads((work/'docs/reference/dependency-inventory.json').read_bytes())
                self.assertEqual(projection['components'],[])
                self.assertEqual(projection['scope'],'image-discovery-action-references-only')
                return [declaration()],{}
            with patch.object(admission,'ROOT',self.code),patch.object(admission.inputs,'revision',return_value=(frozen,original)), \
                 patch.object(admission.inventory,'GENERATOR_FILES',(script,helper)), \
                 patch.object(admission.images,'GENERATOR_FILES',('scripts/dependency_images.py',)), \
                 patch.object(admission.images,'discover',side_effect=discover):
                result=admission.view(reader,value,root)
            self.assertEqual(result['source_inventory_sha256'],admission.digest(value['inventory']))

    def test_original_git_data_and_trusted_generators_are_distinct_and_never_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);reader,value,frozen,original,helper,script,base_raw=self.setup_view(root)
            def discover(work):
                self.assertEqual((work/script).read_bytes(),b'trusted Python data')
                self.assertEqual((work/helper).read_bytes(),base_raw)
                self.assertEqual((work/script).stat().st_mode&0o777,0o600)
                self.assertEqual((work/'Dockerfile').read_bytes(),original['Dockerfile'])
                return [declaration()],{'Dockerfile':original['Dockerfile']}
            with patch.object(admission,'ROOT',self.code),patch.object(admission.inputs,'revision',return_value=(frozen,original)), \
                 patch.object(admission.inventory,'GENERATOR_FILES',(script,helper)), \
                 patch.object(admission.images,'GENERATOR_FILES',('scripts/dependency_images.py',)), \
                 patch.object(admission.images,'discover',side_effect=discover):
                result=admission.view(reader,value,root)
            self.assertEqual(result['source_commit'],HEAD);self.assertNotIn('CANARY',json.dumps(result))
            self.assertNotIn(str(root),json.dumps(result))
            substitution=result['generator_substitutions'][script]
            self.assertEqual(substitution['original_sha256'],hashlib.sha256(original[script]).hexdigest())
            self.assertNotEqual(substitution['trusted_sha256'],substitution['original_sha256'])
            self.assertIn(b'PRIVATE_CANARY',original[helper])

    def test_changed_source_classifier_receipt_and_late_export_edits_fail(self):
        for operation in ['source','base','generator','blob','export','trusted-code']:
            with self.subTest(operation=operation),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);reader,value,frozen,original,helper,script,_=self.setup_view(root)
                if operation=='source':value['source']['commit']=BASE
                if operation=='base':value['inventory']['generator']['classifier']['trusted_base']=HEAD
                if operation=='generator':value['inventory']['generator']['files'][script]='e'*64
                if operation=='blob':reader.blob.return_value=b'PRIVATE_CANARY different Git bytes'
                def discover(work):
                    if operation=='export':(work/'late').write_text('PRIVATE_CANARY')
                    if operation=='trusted-code':(self.code/script).write_text('PRIVATE_CANARY')
                    return [declaration()],{}
                with patch.object(admission,'ROOT',self.code),patch.object(admission.inputs,'revision',return_value=(frozen,original)), \
                     patch.object(admission.inventory,'GENERATOR_FILES',(script,helper)), \
                     patch.object(admission.images,'GENERATOR_FILES',('scripts/dependency_images.py',)), \
                     patch.object(admission.images,'discover',side_effect=discover),self.assertRaises(admission.ImageAdmissionError) as error:
                    admission.view(reader,value,root)
                self.assertNotIn('CANARY',str(error.exception))

    def test_source_build_recipe_changes_are_bound_even_when_the_tag_stays_the_same(self):
        recipes=[]
        for body,args in [(b'FROM alpine:3.23\n',False),(b'FROM alpine:3.24\n',False),(b'FROM alpine:3.23\n',True)]:
            with self.subTest(body=body,args=args),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);reader,value,frozen,original,helper,script,_=self.setup_view(root)
                build={'context':'./deploy/local-dependencies','target':'mc'}
                if args:build['args']={'UNREVIEWED':'PRIVATE_CANARY'}
                original['compose.production-like.yml']=json.dumps({'services':{'fixture':{'build':build}}}).encode()
                original['deploy/local-dependencies/Dockerfile']=body
                frozen['files']=[{'path':name,'git_blob':admission.objects.object_id('blob',raw),'mode':'100644',
                    'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'roles':['images']} for name,raw in sorted(original.items())]
                value['source']=copy.deepcopy(frozen)
                row=declaration('evydence-local-mc:20250813-7394ce0dd2a8',kind='source-build',
                                locations=['compose.production-like.yml#services/fixture'])
                with patch.object(admission,'ROOT',self.code),patch.object(admission.inputs,'revision',return_value=(frozen,original)), \
                     patch.object(admission.inventory,'GENERATOR_FILES',(script,helper)), \
                     patch.object(admission.images,'GENERATOR_FILES',('scripts/dependency_images.py',)), \
                     patch.object(admission.images,'discover',return_value=([row],{})):
                    if args:
                        with self.assertRaises(admission.ImageAdmissionError):admission.view(reader,value,root)
                    else:recipes.append(admission.view(reader,value,root)['declarations'][0]['recipe_sha256'])
        self.assertNotEqual(*recipes)

class ScannerTests(unittest.TestCase):
    def test_only_qualified_scanner_runs_and_supplemental_bytes_match_manifest_projection(self):
        raw,manifest,config=scanner();raw['artifacts']=[apk()];encoded=json.dumps(raw).encode()
        observation=images.project(encoded,manifest,config)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);binary=root/'syft';binary.write_bytes(b'trusted')
            def scan(_binary,_row,_resolution,work):
                (work/'scanner.json').write_bytes(encoded);return observation
            with patch.object(admission.images.tools,'verify_installation',return_value=binary), \
                 patch.object(admission.images.release_scanner,'verify_tool'), \
                 patch.object(admission.images.registry,'resolve',return_value={'manifest_digest':manifest,'config':{'digest':config}}), \
                 patch.object(admission.images,'scan',side_effect=scan):
                actual=admission.Scanner(binary,root);result=actual.scan(declaration())
                self.assertEqual(result,[admission.packages.project(apk())]);actual.verify()
                binary.write_bytes(b'PRIVATE_CANARY changed executable')
                with self.assertRaises(admission.ImageAdmissionError):actual.scan(declaration())
        self.assertNotIn('CANARY',json.dumps(result))


if __name__=='__main__':unittest.main()
