#!/usr/bin/env python3
"""Untrusted dependency-review metadata must preserve strict admission semantics."""
from datetime import date
import copy
import json
import unittest
import dependency_comparison as comparison

BASE='a'*40; HEAD='b'*40; TODAY=date(2026,10,22)
RULES={'schema':'evydence-dependency-policy.v1','allowed_licenses':['MIT'],'allowed_with':[],'exceptions':[]}


def row(**changes):
    return {'change_type':'added','manifest':'package-lock.json','ecosystem':'npm','name':'example',
            'version':'1.2.3','package_url':'pkg:npm/example@1.2.3','license':'MIT','vulnerabilities':[],**changes}


def assess(rows):
    return comparison.assess(json.dumps(rows).encode(),RULES,TODAY,repository='aatuh/evydence',base=BASE,head=HEAD)


class ComparisonTests(unittest.TestCase):
    def test_go_versions_match_inventory_coordinates_and_legacy_removal_purls(self):
        added=row(ecosystem='gomod',name='example.org/module',version='1.2.3',
                  manifest='go.mod',package_url='pkg:golang/example.org/module@1.2.3')
        result=assess([added]); self.assertEqual(result['components'][0]['version'],'v1.2.3')
        removed={**added,'change_type':'removed','package_url':'pkg:golang/example.org/module'}
        self.assertEqual(comparison.component(removed)['version'],'v1.2.3')
        self.assertEqual(assess([removed])['components'],[])
        with self.assertRaises(comparison.ComparisonError): assess([{**removed,'change_type':'added'}])

    def test_added_components_use_strict_policy_and_removed_components_do_not_block_admission(self):
        result=assess([row(),row(change_type='removed',version='1.0.0',package_url='pkg:npm/example@1.0.0',license='GPL-3.0-only')])
        self.assertTrue(result['passed']); self.assertEqual(len(result['components']),1)
        self.assertEqual(result['base'],BASE); self.assertEqual(result['head'],HEAD)
        self.assertEqual(assess([])['components'],[])

    def test_missing_unknown_and_disallowed_licenses_do_not_pass(self):
        for license in [None,'NOASSERTION','UNKNOWN','GPL-3.0-only']:
            with self.subTest(license=license): self.assertFalse(assess([row(license=license)])['passed'])
        value=row(); del value['license']
        with self.assertRaises(comparison.ComparisonError): assess([value])

    def test_high_critical_unknown_or_missing_severity_is_blocking(self):
        for severity in ['high','critical','unknown',None,'unexpected']:
            vulnerability={'advisory_ghsa_id':'GHSA-aaaa-bbbb-cccc','severity':severity,'advisory_summary':'PRIVATE_CANARY'}
            result=assess([row(vulnerabilities=[vulnerability])])
            self.assertFalse(result['passed']); self.assertNotIn('CANARY',json.dumps(result))
        for value in [row(vulnerabilities=None),row(vulnerabilities=[{}])]:
            with self.assertRaises(comparison.ComparisonError): assess([value])
        value=row(); del value['vulnerabilities']
        with self.assertRaises(comparison.ComparisonError): assess([value])

    def test_conflicting_metadata_cannot_hide_behind_another_manifest(self):
        a=row(); b=row(manifest='nested/package-lock.json',license='GPL-3.0-only')
        with self.assertRaises(comparison.ComparisonError): assess([a,b])
        b=row(manifest='nested/package-lock.json')
        result=assess([a,b]); self.assertEqual(len(result['components']),1)
        self.assertEqual(result['components'][0]['manifests'],['nested/package-lock.json','package-lock.json'])
        b['vulnerabilities']=[{'advisory_ghsa_id':'GHSA-aaaa-bbbb-cccc','severity':'high'}]
        self.assertFalse(assess([a,b])['passed'])

    def test_invalid_identity_purl_manifest_scope_and_provider_fields_fail_safely(self):
        for changes in [{'name':'../PRIVATE_CANARY'},{'manifest':'../escape/go.mod'},
                        {'manifest':'/absolute/go.mod'},{'version':'bad\nversion'},
                        {'package_url':'pkg:npm/different@1.2.3'},{'ecosystem':'unsupported'},
                        {'change_type':'unrecognized'}]:
            with self.subTest(changes=changes),self.assertRaises(comparison.ComparisonError) as error: assess([row(**changes)])
            self.assertNotIn('CANARY',str(error.exception))
        for repository,base,head in [('other/repo',BASE,HEAD),('aatuh/evydence','master',HEAD),('aatuh/evydence',BASE,BASE)]:
            with self.subTest(repository=repository,base=base),self.assertRaises(comparison.ComparisonError):
                comparison.assess(b'[]',RULES,TODAY,repository=repository,base=base,head=head)

    def test_bounds_duplicates_and_malformed_json_are_rejected(self):
        for raw in [b'{}',b'[{}]',b'[{"change_type":"added","change_type":"removed"}]',b'NaN',b'\xff']:
            with self.subTest(raw=raw),self.assertRaises(comparison.ComparisonError):
                comparison.assess(raw,RULES,TODAY,repository='aatuh/evydence',base=BASE,head=HEAD)
        with self.assertRaises(comparison.ComparisonError): assess([row(),copy.deepcopy(row())])


if __name__=='__main__': unittest.main()
