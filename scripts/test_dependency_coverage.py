#!/usr/bin/env python3
"""Combined coverage needs positive source evidence, not a promoted partial flag."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import dependency_coverage as coverage
from test_dependency_admission import BASE,HEAD,collection,component
from test_dependency_collection import revision


def fixture(commit):
    root=Path(__file__).resolve().parents[1]
    names={name for rows in coverage.inputs.GROUPS.values() for name in rows}
    names.update(coverage.REQUIRED_INPUTS);names.add('.github/workflows/ci.yml')
    contents={name:b'synthetic source bytes' for name in names}
    code={name:(root/name).read_bytes() for name in {*coverage.inventory.GENERATOR_FILES,
        *coverage.collection.DRIVER_FILES} if name.endswith('.py')}
    main='tools/cmd/license-inventory/main.go'
    receipt={'schema':coverage.classifiers.SCHEMA,'trusted_base':BASE,'go_version':'go1.27.3',
             'sources':{main:{'sha256':hashlib.sha256(b'base helper source').hexdigest()}}}
    observed={'commit':commit,'tree':'d'*40,'missing_required':[],'unclassified_manifests':[],
        'schemas_verified':sorted(coverage.REQUIRED_SCHEMAS),'files':[
        {'path':name,'roles':['tooling'],'mode':'100644','git_blob':coverage.objects.object_id('blob',raw),
         'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in sorted(contents.items())]}
    value=collection(commit,[component()]);value['source']=observed
    value['trusted_driver_files']={name:hashlib.sha256(code[name]).hexdigest() for name in coverage.collection.DRIVER_FILES}
    value['inventory'].update(complete=False,remaining_scopes=['images'],inputs={
        name:hashlib.sha256(contents[name]).hexdigest() for name in coverage.REQUIRED_INPUTS},
        generator={'go_version':'go1.27.3','classifier':receipt,'files':{
        name:hashlib.sha256(code[name]).hexdigest() if name.endswith('.py') else receipt['sources'][name]['sha256']
        for name in coverage.inventory.GENERATOR_FILES}})
    return value,contents,receipt,code


class CoverageTests(unittest.TestCase):
    def profile(self,value,contents,receipt,code):
        with patch.object(coverage.inputs,'revision',return_value=(copy.deepcopy(value['source']),contents)):
            return coverage.source_profile(object(),value,value['source']['commit'],BASE,receipt,code)

    def test_real_profile_requires_bound_inputs_and_does_not_relabel_inventory_or_partial_decision(self):
        value,contents,receipt,code=fixture(HEAD)
        result=self.profile(value,contents,receipt,code)
        self.assertTrue(result['source_coverage_verified']);self.assertEqual(result['coverage_gaps'],[])
        self.assertEqual(result['component_counts'],{'npm':1});self.assertFalse(value['inventory']['complete'])
        self.assertNotIn('synthetic source bytes',str(result))

    def test_missing_input_schema_original_bytes_driver_or_classifier_proof_cannot_qualify(self):
        for reason in ['required-input','schema','bytes','input-hash','generator','driver','helper','compiler','source']:
            value,contents,receipt,code=fixture(HEAD)
            if reason=='required-input':value['inventory']['inputs'].pop('go.mod')
            if reason=='schema':value['source']['schemas_verified']=[]
            if reason=='bytes':contents['go.mod']=b'PRIVATE_CANARY substituted bytes'
            if reason=='input-hash':value['inventory']['inputs']['go.mod']='f'*64
            if reason=='generator':value['inventory']['generator']['files'].pop('scripts/dependency_inventory.py')
            if reason=='driver':value['trusted_driver_files']['scripts/dependency_collection.py']='f'*64
            if reason=='helper':value['inventory']['generator']['files']['tools/cmd/license-inventory/main.go']='f'*64
            if reason=='compiler':value['inventory']['generator']['go_version']='go1.0.0'
            if reason=='source':value['source_bytes_verified']=False
            with self.subTest(reason=reason),self.assertRaises(coverage.CoverageError) as error:
                self.profile(value,contents,receipt,code)
            self.assertNotIn('CANARY',str(error.exception))

    def test_unsupported_origins_ecosystems_and_local_actions_remain_explicit_gaps(self):
        for reason in ['origin','ecosystem','local-action']:
            value,contents,receipt,code=fixture(HEAD)
            if reason=='origin':value['inventory']['components'][0]['origins']=['application']
            if reason=='ecosystem':value['inventory']['components'][0]['ecosystem']='docker'
            if reason=='local-action':value['inventory']['remaining_scopes'].append('action-local-references')
            with self.subTest(reason=reason):
                result=self.profile(value,contents,receipt,code)
                self.assertFalse(result['source_coverage_verified']);self.assertTrue(result['coverage_gaps'])

    def test_missing_or_unknown_remaining_scope_cannot_be_implicitly_complete(self):
        for scopes in [None,[],['other'],['images','images']]:
            value,contents,receipt,code=fixture(HEAD);value['inventory']['remaining_scopes']=scopes
            with self.subTest(scopes=scopes),self.assertRaises(coverage.CoverageError):self.profile(value,contents,receipt,code)

    def test_partial_flags_cannot_override_source_image_or_tool_gaps(self):
        source={'source_coverage_verified':True,'coverage_gaps':[]}
        image={'image_coverage_verified':True,'coverage_gaps':[]}
        tool={'tool_coverage_verified':True}
        result=coverage.combine([source,source],image,tool)
        self.assertTrue(result['dependency_coverage_verified']);self.assertFalse(result['complete_artifact_sbom'])
        for reason in ['source','image','tool','gap']:
            values=copy.deepcopy([source,source]);images=copy.deepcopy(image);tools=copy.deepcopy(tool)
            if reason=='source':values[0]['source_coverage_verified']=False
            if reason=='image':images['image_coverage_verified']=False
            if reason=='tool':tools['tool_coverage_verified']=False
            if reason=='gap':values[1]['coverage_gaps']=['unsupported-new-scope']
            with self.subTest(reason=reason):
                result=coverage.combine(values,images,tools)
                self.assertFalse(result['dependency_coverage_verified']);self.assertTrue(result['coverage_gaps'])


if __name__=='__main__':unittest.main()
