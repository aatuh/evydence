#!/usr/bin/env python3
"""Neither authenticated provider findings nor bound source observations may vanish."""
import copy
from datetime import date
import json
import unittest

import dependency_review_join as join
import dependency_review_provider as provider
from test_dependency_admission import BASE,MERGE,HEAD,Reader,API,collection,component

TODAY=date(2026,10,22)


def row(**changes):
    return {'change_type':'added','manifest':'site/marketing/package-lock.json','ecosystem':'npm','name':'lodash',
            'version':'4.17.11','package_url':'pkg:npm/lodash@4.17.11','license':'MIT','vulnerabilities':[],**changes}


def snapshot(rows):
    return {'schema':provider.SCHEMA,'repository':'aatuh/evydence','base':BASE,'head':HEAD,'comparison_base':MERGE,
            'provider_authenticated':True,'file_listing_verified':True,'dependency_rows':rows,'receipts':[]}


def assess(rows,components=None,api=None,before=None):
    return join.assess(Reader(),BASE,MERGE,HEAD,collection(MERGE,before or []),
        collection(HEAD,[component()] if components is None else components),snapshot(rows),api or API(),TODAY)


class JoinTests(unittest.TestCase):
    def test_provider_high_and_unknown_findings_are_preserved_when_osv_has_no_match(self):
        for severity in ['critical','high','unknown']:
            result=assess([row(vulnerabilities=[{'advisory_ghsa_id':'GHSA-aaaa-bbbb-cccc','severity':severity,'summary':'PRIVATE_CANARY'}])])
            self.assertFalse(result['package_decision_passed']);self.assertEqual(result['changes'][0]['vulnerabilities'][0]['severity'],severity)
            self.assertNotIn('CANARY',json.dumps(result));self.assertFalse(result['dependency_coverage_verified'])

    def test_union_uses_worst_severity_and_does_not_lose_osv_only_findings(self):
        api=API(vulnerabilities=[{'id':'GHSA-aaaa-bbbb-cccc','severity':'critical'},{'id':'GO-2026-1234','severity':'high'}])
        result=assess([row(vulnerabilities=[{'advisory_ghsa_id':'GHSA-aaaa-bbbb-cccc','severity':'low'}])],api=api)
        findings=result['changes'][0]['vulnerabilities'];self.assertEqual(len(findings),2)
        self.assertEqual(findings[0]['severity'],'critical');self.assertFalse(result['package_decision_passed'])
        result=assess([row(vulnerabilities=[{'advisory_ghsa_id':'GHSA-aaaa-bbbb-cccc','severity':'high'}])],api=API('unavailable'))
        self.assertIsNone(result['changes'][0]['vulnerabilities'])
        self.assertEqual(result['changes'][0]['provider_findings'],[{'id':'GHSA-aaaa-bbbb-cccc','severity':'high'}])
        self.assertFalse(result['package_decision_passed'])

    def test_provider_addition_forces_assessment_even_when_source_identity_and_origin_already_exist(self):
        value=component()
        result=assess([row(vulnerabilities=[{'advisory_ghsa_id':'GHSA-aaaa-bbbb-cccc','severity':'high'}])],before=[value])
        self.assertEqual(len(result['changes']),1);self.assertFalse(result['package_decision_passed'])

    def test_missing_provider_license_does_not_replace_verified_artifact_but_conflicting_license_blocks(self):
        self.assertTrue(assess([row(license=None)])['package_decision_passed'])
        result=assess([row(license='GPL-3.0-only')])
        self.assertFalse(result['package_decision_passed']);self.assertIn('provider_license_conflict',result['changes'][0]['violations'])
        self.assertFalse(assess([row()],components=[component(license=None,license_status='unknown')])['package_decision_passed'])

    def test_source_go_versions_and_python_names_match_provider_coordinates(self):
        go=component(ecosystem='gomod',name='example.org/module',version='v1.2.3',origins=['qa'])
        dep=row(ecosystem='gomod',name='example.org/module',version='1.2.3',manifest='tools/go.mod',package_url='pkg:golang/example.org/module@1.2.3')
        self.assertTrue(assess([dep],components=[go])['provider_join_passed'])
        py=component(ecosystem='pypi',name='PyYAML',version='6.0.3',origins=['qa'])
        dep=row(ecosystem='pip',name='pyyaml',version='6.0.3',manifest='tools/requirements-qa.txt',package_url='pkg:pypi/pyyaml@6.0.3')
        self.assertTrue(assess([dep],components=[py])['provider_join_passed'])

    def test_explicit_github_action_coverage_cannot_fabricate_support_for_other_scopes_or_failed_osv(self):
        action=component(ecosystem='github-actions',name='actions/checkout',version='d'*40,origins=['ci'])
        dep=row(ecosystem='actions',name='actions/checkout',version='d'*40,manifest='.github/workflows/ci.yml',package_url='pkg:githubactions/actions/checkout@'+'d'*40)
        self.assertTrue(assess([dep],components=[action],api=API('unsupported'))['package_decision_passed'])
        self.assertFalse(assess([dep],components=[action],api=API('unavailable'))['package_decision_passed'])
        self.assertFalse(assess([row()],api=API('unsupported'))['package_decision_passed'])

    def test_unmatched_additions_remain_visible_and_block_but_removals_are_not_readmitted(self):
        result=assess([row(name='other',package_url='pkg:npm/other@4.17.11')])
        self.assertFalse(result['provider_join_passed']);self.assertFalse(result['package_decision_passed'])
        self.assertEqual(result['unmatched_provider_components'][0]['name'],'other')
        result=assess([row(change_type='removed',name='other',package_url='pkg:npm/other@4.17.11',license='GPL-3.0-only')])
        self.assertTrue(result['provider_join_passed']);self.assertEqual(result['unmatched_provider_components'],[])

    def test_untrusted_wrong_source_duplicate_or_conflicting_cross_manifest_rows_are_rejected_or_blocked(self):
        for change in [{'provider_authenticated':False},{'file_listing_verified':False},{'base':MERGE},{'head':BASE},
                       {'comparison_base':BASE},{'repository':'other/repo'}]:
            observed=snapshot([row()]);observed.update(change)
            with self.subTest(change=change),self.assertRaises(join.JoinError):
                join.assess(Reader(),BASE,MERGE,HEAD,collection(MERGE,[]),collection(HEAD,[component()]),observed,API(),TODAY)
        with self.assertRaises(join.JoinError):assess([row(),copy.deepcopy(row())])
        result=assess([row(),row(manifest='another/package-lock.json',license='GPL-3.0-only')])
        self.assertFalse(result['package_decision_passed'])


if __name__=='__main__':unittest.main()
