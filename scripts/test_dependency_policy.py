#!/usr/bin/env python3
"""Offline regressions for dependency admission, not a live dependency audit."""
from __future__ import annotations

import copy
from datetime import date
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'dependency_policy', Path(__file__).with_name('dependency_policy.py'))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
TODAY = date(2026, 10, 21)


def policy():
    return {'schema': 'evydence-dependency-policy.v1',
            'allowed_licenses': ['MIT', 'Apache-2.0', 'BSD-3-Clause'],
            'allowed_with': ['Apache-2.0 WITH LLVM-exception'],
            'exceptions': []}


def component():
    return {'ecosystem': 'npm', 'name': '@example/library', 'version': '1.2.3',
            'license': 'MIT', 'vulnerabilities': []}


def exception(kind='license', value='GPL-3.0-only'):
    return {'id': 'DEP-0001', 'ecosystem': 'npm', 'name': '@example/library',
            'version': '1.2.3', 'kind': kind, 'value': value,
            'owner': 'aatuh', 'reason': 'Synthetic fixture; no live exception approved.',
            'reviewed_on': '2026-10-20', 'expires_on': '2026-11-20',
            'review_url': 'https://github.com/aatuh/evydence/pull/123#issuecomment-456'}


class SPDXTests(unittest.TestCase):
    def allowed(self, expression):
        return POLICY.license_allowed(expression, policy())

    def test_spdx_boolean_operators_have_their_defined_precedence(self):
        for value in ['MIT', '(MIT)', 'MIT AND Apache-2.0',
                      'GPL-3.0-only OR MIT', 'MIT OR GPL-3.0-only AND BSD-3-Clause',
                      '(GPL-3.0-only OR MIT) AND BSD-3-Clause']:
            with self.subTest(expression=value):
                self.assertTrue(self.allowed(value))
        for value in ['GPL-3.0-only', 'MIT AND GPL-3.0-only',
                      '(MIT OR GPL-3.0-only) AND GPL-3.0-only']:
            with self.subTest(expression=value):
                self.assertFalse(self.allowed(value))

    def test_with_exceptions_are_bound_to_the_exact_license(self):
        self.assertTrue(self.allowed('Apache-2.0 WITH LLVM-exception'))
        self.assertFalse(self.allowed('MIT WITH LLVM-exception'))
        self.assertFalse(self.allowed('Apache-2.0 WITH Unknown-exception'))
        self.assertFalse(self.allowed('LLVM-exception'))

    def test_license_identifiers_ignore_case_but_operators_do_not(self):
        for value in ['mit', 'mIt AND apache-2.0',
                      'aPACHE-2.0 WITH llvm-EXCEPTION']:
            with self.subTest(expression=value):
                self.assertTrue(self.allowed(value))
        with self.assertRaises(POLICY.PolicyError):
            self.allowed('MIT and Apache-2.0')

    def test_missing_and_unresolved_licenses_do_not_pass(self):
        for value in [None, '', 'NOASSERTION', 'NONE', 'LicenseRef-Private']:
            with self.subTest(expression=value):
                self.assertFalse(self.allowed(value))

    def test_every_branch_is_parsed_even_if_an_alternative_is_allowed(self):
        for value in ['MIT OR', 'MIT OR (Apache-2.0', 'MIT OR MIT garbage',
                      'MIT WITH', 'MIT WITH LLVM-exception WITH Other',
                      '(MIT OR Apache-2.0) WITH LLVM-exception', 'MIT || Apache-2.0',
                      'MIT AND ()', 'MIT OR MIT\nPRIVATE_CANARY', 'MIT OR MIT\x00',
                      'MIT or Apache-2.0', 'MIT\u200b', 'MIT OR "Apache-2.0"']:
            with self.subTest(expression=value), self.assertRaises(POLICY.PolicyError):
                self.allowed(value)

    def test_plus_is_only_a_license_suffix_and_not_an_exception_operator(self):
        for value in ['M+IT', 'MIT++', 'MIT WITH LLVM-exception+', 'MIT WITH LLVM+exception']:
            with self.subTest(expression=value), self.assertRaises(POLICY.PolicyError):
                self.allowed(value)
        rules = policy(); rules['allowed_licenses'].append('GPL-2.0+')
        self.assertTrue(POLICY.license_allowed('GPL-2.0+', rules))

    def test_expression_work_is_bounded_before_recursion_or_token_expansion(self):
        for value in ['(' * 1000 + 'MIT' + ')' * 1000,
                      ' OR '.join(['MIT'] * 200), 'X' * 4096]:
            with self.subTest(length=len(value)), self.assertRaises(POLICY.PolicyError):
                self.allowed(value)


class AdmissionTests(unittest.TestCase):
    def assess(self, item=None, rules=None):
        return POLICY.assess_component(component() if item is None else item,
                                       policy() if rules is None else rules, TODAY)

    def test_permitted_dependency_passes_without_an_exception(self):
        self.assertEqual(self.assess(), {'passed': True, 'violations': [], 'exceptions': []})

    def test_unknown_and_disallowed_licenses_fail_admission(self):
        for value, code in [(None, 'unknown_license'), ('NOASSERTION', 'unknown_license'),
                            ('GPL-3.0-only', 'disallowed_license')]:
            item = component(); item['license'] = value
            self.assertEqual(self.assess(item)['violations'], [code])
            self.assertFalse(self.assess(item)['passed'])

    def test_high_critical_and_unknown_vulnerabilities_block_all_scopes(self):
        for severity in ['high', 'critical', 'unknown']:
            item = component()
            item['vulnerabilities'] = [{'id': 'GHSA-2345-6789-cfgh', 'severity': severity}]
            self.assertFalse(self.assess(item)['passed'])
            self.assertEqual(self.assess(item)['violations'], ['blocked_vulnerability'])
        for severity in ['low', 'moderate']:
            item = component()
            item['vulnerabilities'] = [{'id': 'GHSA-2345-6789-cfgh', 'severity': severity}]
            self.assertTrue(self.assess(item)['passed'])

    def test_live_exception_is_exactly_scoped_and_is_reported(self):
        rules = policy(); rules['exceptions'] = [exception()]
        item = component(); item['license'] = 'GPL-3.0-only'
        self.assertEqual(self.assess(item, rules),
                         {'passed': True, 'violations': [], 'exceptions': ['DEP-0001']})
        for key, other in [('ecosystem', 'gomod'), ('name', '@other/library'),
                           ('version', '1.2.4'), ('license', 'GPL-2.0-only')]:
            changed = dict(item); changed[key] = other
            with self.subTest(key=key):
                self.assertFalse(self.assess(changed, rules)['passed'])

    def test_license_exception_cannot_waive_an_advisory_or_another_advisory(self):
        rules = policy(); rules['exceptions'] = [exception()]
        item = component(); item['license'] = 'GPL-3.0-only'
        item['vulnerabilities'] = [{'id': 'GHSA-2345-6789-cfgh', 'severity': 'critical'}]
        self.assertFalse(self.assess(item, rules)['passed'])
        rules['exceptions'].append(exception('vulnerability', 'GHSA-2345-6789-cfgh'))
        rules['exceptions'][1]['id'] = 'DEP-0002'
        self.assertTrue(self.assess(item, rules)['passed'])
        item['vulnerabilities'].append({'id': 'GO-2026-1234', 'severity': 'high'})
        self.assertFalse(self.assess(item, rules)['passed'])

    def test_unknown_license_needs_an_explicit_unknown_license_exception(self):
        rules = policy(); rules['exceptions'] = [exception(value='NOASSERTION')]
        item = component(); item['license'] = None
        self.assertTrue(self.assess(item, rules)['passed'])
        item['license'] = 'MIT WITH Unknown-exception'
        self.assertFalse(self.assess(item, rules)['passed'])

    def test_exception_expires_at_start_of_expiration_date(self):
        rules = policy(); row = exception(); row['expires_on'] = TODAY.isoformat()
        rules['exceptions'] = [row]
        item = component(); item['license'] = 'GPL-3.0-only'
        with self.assertRaises(POLICY.PolicyError):
            self.assess(item, rules)

    def test_inputs_are_not_mutated(self):
        rules = policy(); item = component()
        before = copy.deepcopy((rules, item))
        self.assess(item, rules)
        self.assertEqual((rules, item), before)


class PolicyValidationTests(unittest.TestCase):
    def test_required_exception_fields_and_review_evidence_are_not_optional(self):
        for key in exception():
            rules = policy(); row = exception(); del row[key]; rules['exceptions'] = [row]
            with self.subTest(missing=key), self.assertRaises(POLICY.PolicyError):
                POLICY.validate_policy(rules, TODAY)

    def test_exception_cannot_be_global_expired_future_reviewed_or_indefinite(self):
        invalid = [('name', '*'), ('version', '*'), ('owner', ''), ('reason', ''),
                   ('review_url', ''), ('review_url', 'https://example.com/review'),
                   ('review_url', 'https://github.com.evil/aatuh/evydence/pull/123'),
                   ('review_url', 'https://github.com/other/repo/pull/123'),
                   ('review_url', 'https://github.com/aatuh/evydence/pull/123?token=CANARY'),
                   ('reviewed_on', '2026-10-22'), ('expires_on', '2027-10-20'),
                   ('expires_on', '2026-10-20'), ('expires_on', '2026-02-30'),
                   ('kind', 'all'), ('value', '*')]
        for key, value in invalid:
            rules = policy(); row = exception(); row[key] = value; rules['exceptions'] = [row]
            with self.subTest(key=key, value=value), self.assertRaises(POLICY.PolicyError):
                POLICY.validate_policy(rules, TODAY)

    def test_duplicate_identity_and_duplicate_exception_scope_are_rejected(self):
        for duplicate_id in [True, False]:
            rules = policy(); row = exception(); other = dict(row)
            if not duplicate_id:
                other['id'] = 'DEP-0002'
            rules['exceptions'] = [row, other]
            with self.assertRaises(POLICY.PolicyError):
                POLICY.validate_policy(rules, TODAY)

    def test_policy_cannot_allow_unknowns_or_silently_ignore_new_keys(self):
        for key, value in [('allowed_licenses', ['NOASSERTION']),
                           ('allowed_licenses', ['UNKNOWN']),
                           ('allowed_licenses', ['UNLICENSED']),
                           ('allowed_licenses', ['MIT', 'MIT']),
                           ('allowed_licenses', ['MIT', 'mit']),
                           ('allowed_licenses', ['MIT OR GPL-3.0-only']),
                           ('allowed_with', ['MIT']), ('warn_only', True),
                           ('schema', 'evydence-dependency-policy.v2')]:
            rules = policy(); rules[key] = value
            with self.subTest(key=key), self.assertRaises(POLICY.PolicyError):
                POLICY.validate_policy(rules, TODAY)

    def test_malformed_provider_components_cannot_be_treated_as_empty_or_safe(self):
        mutations = [('vulnerabilities', None), ('vulnerabilities', {}),
                     ('vulnerabilities', [{'id': 'GO-2026-1234', 'severity': None}]),
                     ('vulnerabilities', [{'id': 'GO-2026-1234', 'severity': 'safe'}]),
                     ('vulnerabilities', [{'id': 'GO-2026-1234', 'severity': 'high', 'ignored': True}]),
                     ('name', '../PRIVATE_CANARY'), ('name', 'PRIVATE_CANARY\n'),
                     ('version', '*'), ('license', True), ('ecosystem', 'unknown'),
                     ('vulnerabilities', [{'id': 'GO-2026-1234', 'severity': 'high'}] * 2)]
        for key, value in mutations:
            item = component(); item[key] = value
            with self.subTest(key=key), self.assertRaises(POLICY.PolicyError):
                POLICY.assess_component(item, policy(), TODAY)

    def test_public_errors_do_not_echo_input_or_json_parser_details(self):
        item = component(); item['name'] = 'PRIVATE_CANARY\n'
        with self.assertRaises(POLICY.PolicyError) as raised:
            POLICY.assess_component(item, policy(), TODAY)
        self.assertNotIn('PRIVATE_CANARY', str(raised.exception))
        for raw in [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":1e999}', b'{"x":-1e999}',
                    b'{"PRIVATE_CANARY":', b'\xff', b'[' * 2000]:
            with self.subTest(raw=raw[:20]), self.assertRaises(POLICY.PolicyError) as raised:
                POLICY.parse_document(raw)
            self.assertNotIn('PRIVATE_CANARY', str(raised.exception))
        with self.assertRaises(POLICY.PolicyError):
            POLICY.parse_document(b' ' * (4 * 1024 * 1024 + 1))
        self.assertEqual(POLICY.parse_document(b'{"ok":true}'), {'ok': True})

    def test_bad_field_types_and_surrogates_raise_only_safe_policy_errors(self):
        for key in policy():
            for value in [None, True, [], {}, 42]:
                if key in ('allowed_with', 'exceptions') and value == []:
                    continue
                rules = policy(); rules[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(POLICY.PolicyError):
                    POLICY.validate_policy(rules, TODAY)
        rules = policy(); row = exception(); row['reason'] = 'CANARY\ud800'
        rules['exceptions'] = [row]
        with self.assertRaises(POLICY.PolicyError) as raised:
            POLICY.validate_policy(rules, TODAY)
        self.assertNotIn('CANARY', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
