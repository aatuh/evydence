#!/usr/bin/env python3
"""All declared source families must be bound without trusting PR inventories."""
import hashlib
import json
import unittest
from unittest.mock import patch

import dependency_git_objects as objects
import dependency_inputs as inputs


COMMIT_A='a'*40; COMMIT_B='b'*40


def leaf(raw=b'input',mode='100644'):
    return {'mode':mode,'type':'blob','sha':objects.object_id('blob',raw)}


class Reader:
    kind='test-double'
    def __init__(self,versions):
        self.versions=versions; self.blobs={objects.object_id('blob',raw):raw for files in versions.values() for raw in files.values()}
    def tree(self,commit): return 'c'*40,{path:leaf(raw) for path,raw in self.versions[commit].items()}
    def blob(self,identity): return self.blobs[identity]


class CatalogTests(unittest.TestCase):
    def complete(self):
        tree={path:leaf() for paths in inputs.GROUPS.values() for path in paths}
        tree['.github/workflows/ci.yml']=leaf(); return tree
    def test_local_and_documented_action_metadata_is_an_action_input(self):
        tree=self.complete()
        for path in ['docs/github-actions/upload-build/action.yml','.github/actions/local/action.yaml']:
            tree[path]=leaf()
        result=inputs.catalog(tree)
        self.assertEqual(result['unclassified_manifests'],[])
        self.assertIn('actions',result['paths']['docs/github-actions/upload-build/action.yml'])
        self.assertIn('actions',result['paths']['.github/actions/local/action.yaml'])

    def test_current_declared_families_include_custom_locks_fixtures_images_and_build_recipes(self):
        tree=self.complete(); tree.update({'scripts/build-example.sh':leaf(),
            'deploy/helm/evydence/templates/new-sidecar.yaml':leaf(),
            'internal/app/parsers/sbom/testdata/example.json':leaf(),
            'testdata/licenses/source.LICENSE':leaf(),'.test.env':leaf(),
            'docs/reference/dependency-inventory.json':leaf()})
        result=inputs.catalog(tree)
        self.assertEqual(result['missing_required'],[]); self.assertEqual(result['unclassified_manifests'],[])
        self.assertIn('go-scanner',result['paths']['release/tools/syft.go.mod'])
        self.assertIn('fixtures',result['paths']['internal/app/parsers/sbom/testdata/example.json'])
        self.assertIn('tooling',result['paths']['scripts/build-example.sh'])
        self.assertIn('images',result['paths']['deploy/helm/evydence/templates/new-sidecar.yaml'])
        self.assertNotIn('.test.env',result['paths']); self.assertNotIn('docs/reference/dependency-inventory.json',result['paths'])
    def test_new_unclassified_manifests_and_missing_required_inputs_are_not_covered(self):
        tree=self.complete(); del tree['go.sum']
        for path in ['sdk/go/go.mod','new/package.json','tools/requirements-extra.txt','Dockerfile.extra','.gitmodules']:
            tree[path]=leaf()
        result=inputs.catalog(tree)
        self.assertIn('go-application:go.sum',result['missing_required'])
        self.assertEqual(result['unclassified_manifests'],sorted(['sdk/go/go.mod','new/package.json','tools/requirements-extra.txt','Dockerfile.extra','.gitmodules']))
    def test_selected_symlinks_gitlinks_bad_paths_and_source_count_excess_fail(self):
        for mode,kind in [('120000','blob'),('160000','commit')]:
            tree=self.complete(); tree['go.mod']={**leaf(), 'mode':mode,'type':kind}
            with self.subTest(mode=mode),self.assertRaises(inputs.InputError): inputs.catalog(tree)
        tree=self.complete(); tree['../PRIVATE_CANARY']=leaf()
        with self.assertRaises(inputs.InputError) as error: inputs.catalog(tree)
        self.assertNotIn('CANARY',str(error.exception))
        with patch.object(inputs,'MAX_INPUT_FILES',1),self.assertRaises(inputs.InputError): inputs.catalog(self.complete())


class RevisionTests(unittest.TestCase):
    def test_source_hashes_and_changes_omit_payloads_and_preserve_missing_scope_state(self):
        old={'go.mod':b'module example.org/old\n','go.sum':b'','scripts/build.sh':b'PRIVATE_CANARY old command'}
        new={**old,'go.mod':b'module example.org/new\n'}
        report=inputs.collect(Reader({COMMIT_A:old,COMMIT_B:new}),COMMIT_A,COMMIT_B)
        self.assertEqual([row['path'] for row in report['changes']],['go.mod'])
        self.assertTrue(report['selected_input_bytes_verified'])
        self.assertFalse(report['source_catalog_covered']); self.assertFalse(report['dependency_coverage_verified'])
        self.assertNotIn('CANARY',json.dumps(report))
        with self.assertRaises(inputs.InputError): inputs.require_coverage(report)
        records={row['path']:row for row in report['head']['files']}
        self.assertEqual(records['go.mod']['sha256'],hashlib.sha256(new['go.mod']).hexdigest())
    def test_reader_cannot_substitute_blob_bytes_even_when_path_and_size_match(self):
        reader=Reader({COMMIT_A:{'go.mod':b'original-bytes'}})
        with patch.object(reader,'blob',return_value=b'PRIVATE_CANARY'):
            with self.assertRaises(inputs.InputError) as error: inputs.revision(reader,COMMIT_A)
        self.assertNotIn('CANARY',str(error.exception))
    def fixture(self):
        payload=b'{"sample":true}\n'; notice=b'fixture notice\n'
        catalog={'schema':'evydence-fixture-provenance.v1',
                 'notices':[{'path':'LICENSE','sha256':hashlib.sha256(notice).hexdigest()}],
                 'fixtures':[{'files':[{'path':'testdata/example.json','sha256':hashlib.sha256(payload).hexdigest()}]}]}
        return {'testdata/fixture-provenance.v1.json':json.dumps(catalog).encode(),
                'testdata/example.json':payload,'LICENSE':notice}
    def test_fixture_payload_coverage_and_notice_hashes_cannot_be_omitted_or_forged(self):
        files=self.fixture(); revision,_=inputs.revision(Reader({COMMIT_A:files}),COMMIT_A)
        self.assertIn('fixture-file-coverage-and-hashes',revision['schemas_verified'])
        for change in ['new-payload','changed-notice','changed-payload']:
            bad=dict(files)
            if change=='new-payload': bad['testdata/unrecorded.json']=b'new data'
            if change=='changed-notice': bad['LICENSE']=b'changed notice'
            if change=='changed-payload': bad['testdata/example.json']=b'changed data'
            with self.subTest(change=change),self.assertRaises(inputs.InputError): inputs.revision(Reader({COMMIT_A:bad}),COMMIT_A)


if __name__=='__main__': unittest.main()
