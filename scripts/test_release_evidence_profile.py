#!/usr/bin/env python3
"""Prove release evidence rejects missing, substituted and ambiguous subjects."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_evidence_profile as profile
import release_sbom
import support_matrix


class EvidenceProfileTests(unittest.TestCase):
    def setUp(self):
        self.tag, self.commit = 'v0.0.0-rc.1403', 'a' * 40
        self.records = [{'name': 'evydence_v0.0.0-rc.1403_linux_amd64/evydence', 'kind': 'binary',
                         'sha256': hashlib.sha256(b'binary').hexdigest(), 'bytes': 6}]
        self.manifest = {'schema_version': 'evydence-release-build-manifest.v1',
                         'build_recipe_version': 'evydence-release-build.v1',
                         'commit': self.commit, 'tag': self.tag, 'go_version': 'go' + support_matrix.load_policy()['go']['current'],
                         'materials': [{'path': 'go.mod', 'digest': 'sha256:' + 'b' * 64}]}
        components = [{'type': 'library', 'name': 'example.com/module', 'version': 'v1.2.3',
                       'purl': 'pkg:golang/example.com/module@v1.2.3'}]
        self.boms = {item['name']: release_sbom.bound_bom(item, components) for item in self.records}
        self.manifest_sha = 'c' * 64

    def documents(self):
        return profile.documents(self.records, self.boms, self.manifest, self.manifest_sha,
                                 self.tag, self.commit, invocation='local')

    def verify(self, documents):
        return profile.verify_documents(documents, self.records, self.manifest,
                                        self.manifest_sha, self.tag, self.commit)

    def test_slsa_statement_binds_actual_subjects_source_inputs_and_parameters(self):
        documents = self.documents()
        statement = json.loads(documents[profile.PROVENANCE_NAME])
        self.assertEqual(statement['_type'], 'https://in-toto.io/Statement/v1')
        self.assertEqual(statement['predicateType'], 'https://slsa.dev/provenance/v1')
        self.assertEqual(statement['subject'], [{'name': self.records[0]['name'],
                                               'digest': {'sha256': self.records[0]['sha256']}}])
        definition = statement['predicate']['buildDefinition']
        self.assertEqual(definition['externalParameters']['tag'], self.tag)
        self.assertIn(self.commit, json.dumps(definition['resolvedDependencies']))
        self.assertIn('go.mod', json.dumps(definition['resolvedDependencies']))
        self.assertIn('release_candidate_package.sh', statement['predicate']['runDetails']['builder']['id'])
        self.verify(documents)

    def test_hosted_builder_workflow_identity_is_separate_from_checked_out_source(self):
        invocation = profile.SOURCE + '/actions/runs/123'
        documents = profile.documents(self.records, self.boms, self.manifest, self.manifest_sha,
                                      self.tag, self.commit, invocation=invocation, workflow_commit='d' * 40)
        self.verify(documents)
        statement = json.loads(documents[profile.PROVENANCE_NAME])
        self.assertTrue(statement['predicate']['runDetails']['builder']['id'].endswith('/release-artifacts.yml@' + 'd' * 40))
        self.assertEqual(statement['predicate']['buildDefinition']['externalParameters']['source_commit'], self.commit)
        with self.assertRaises(ValueError):
            profile.documents(self.records, self.boms, self.manifest, self.manifest_sha,
                              self.tag, self.commit, invocation=invocation)

    def test_wrong_or_missing_sbom_subject_fails(self):
        for mode in ['wrong_digest', 'wrong_name', 'missing_subject', 'missing_bom']:
            with self.subTest(mode=mode):
                documents = self.documents()
                name = next(name for name in documents if name.startswith('evydence-sbom-'))
                if mode == 'missing_bom':
                    del documents[name]
                else:
                    bom = json.loads(documents[name])
                    if mode == 'wrong_digest':
                        bom['metadata']['component']['hashes'][0]['content'] = '0' * 64
                    elif mode == 'wrong_name':
                        bom['metadata']['component']['name'] += '-different'
                    else:
                        del bom['metadata']['component']
                    documents[name] = profile.json_bytes(bom)
                with self.assertRaisesRegex(ValueError, '^invalid release evidence profile$'):
                    self.verify(documents)

    def test_wrong_missing_duplicate_and_legacy_provenance_subjects_fail(self):
        for mode in ['wrong', 'missing', 'duplicate', 'legacy', 'wrong_source']:
            with self.subTest(mode=mode):
                documents = self.documents()
                statement = json.loads(documents[profile.PROVENANCE_NAME])
                if mode == 'wrong':
                    statement['subject'][0]['digest']['sha256'] = '0' * 64
                elif mode == 'missing':
                    statement['subject'] = []
                elif mode == 'duplicate':
                    statement['subject'] *= 2
                elif mode == 'legacy':
                    statement['_type'] = 'https://in-toto.io/Statement/v0.1'
                else:
                    statement['predicate']['buildDefinition']['externalParameters']['source_commit'] = '0' * 40
                documents[profile.PROVENANCE_NAME] = profile.json_bytes(statement)
                with self.assertRaises(ValueError):
                    self.verify(documents)

    def test_index_cannot_omit_or_redirect_an_artifacts_evidence(self):
        for mode in ['missing_index', 'missing_artifact', 'redirect']:
            with self.subTest(mode=mode):
                documents = self.documents()
                if mode == 'missing_index':
                    del documents[profile.INDEX_NAME]
                else:
                    index = json.loads(documents[profile.INDEX_NAME])
                    if mode == 'missing_artifact':
                        index['artifacts'] = []
                    else:
                        index['artifacts'][0]['sbom']['path'] = '../PRIVATE_CANARY'
                    documents[profile.INDEX_NAME] = profile.json_bytes(index)
                with self.assertRaises(ValueError):
                    self.verify(documents)

    def test_consistently_rehashed_substituted_evidence_still_fails_actual_subject_bytes(self):
        substituted = copy.deepcopy(self.records)
        substituted[0]['sha256'] = '0' * 64
        forged_boms = {item['name']: release_sbom.bound_bom(item, self.boms[item['name']]['components'])
                       for item in substituted}
        forged = profile.documents(substituted, forged_boms, self.manifest, self.manifest_sha,
                                   self.tag, self.commit, invocation='local')
        with self.assertRaises(ValueError):
            self.verify(forged)

    def test_private_paths_and_unvalidated_provider_environment_are_rejected(self):
        self.manifest['materials'][0]['path'] = '/PRIVATE_CANARY/go.mod'
        with self.assertRaisesRegex(ValueError, '^invalid release evidence profile$') as raised:
            self.documents()
        self.assertNotIn('PRIVATE_CANARY', str(raised.exception))

    def test_duplicate_json_keys_and_nonstandard_numbers_fail(self):
        for raw in [b'{"x":1,"x":2}', b'{"x":NaN}', b'{}{}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                profile.parse_json(raw)

    def test_explicit_legacy_compatibility_is_limited_to_pinned_historical_identity(self):
        commit = '2f759100e723554e4e68e3ada712c923e391a17a'
        raw = profile.json_bytes({'schema': 'evydence-legacy-release-evidence.v1', 'releases': [
            {'repository': 'aatuh/evydence', 'tag': 'v0.1.0-rc.7', 'source_commit': commit,
             'provenance_profile': 'evydence-release-provenance.v1'}]})
        profile.verify_legacy_identity(raw, 'aatuh/evydence', 'v0.1.0-rc.7', commit)
        for repository, tag, source in [('someone/evydence', 'v0.1.0-rc.7', commit),
                                        ('aatuh/evydence', 'v0.1.0-rc.8', commit),
                                        ('aatuh/evydence', 'v0.1.0-rc.7', '0' * 40)]:
            with self.subTest(repository=repository, tag=tag, source=source), self.assertRaises(ValueError):
                profile.verify_legacy_identity(raw, repository, tag, source)


if __name__ == '__main__':
    unittest.main()
