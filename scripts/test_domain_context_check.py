#!/usr/bin/env python3
"""Regression tests for the context-owned domain inventory checker."""

from __future__ import annotations

import unittest

import domain_context_check


class DomainContextCheckTests(unittest.TestCase):
    def test_adr_assigns_every_legacy_model_once(self) -> None:
        ownership = domain_context_check.parse_adr_ownership(
            domain_context_check.ADR.read_text(encoding="utf-8")
        )
        assigned = [name for names in ownership.values() for name in names]
        legacy = set()
        for path in domain_context_check.LEGACY_DOMAIN.glob("*.go"):
            if not path.name.endswith("_test.go"):
                legacy.update(
                    domain_context_check.declared_types(path.read_text(encoding="utf-8"))
                )
        supporting = {"VerificationState", "VerificationProfile", "VerificationProfileDefinition"}

        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertEqual(set(assigned), legacy - supporting)

    def test_source_boundary_rejects_tags_and_non_standard_imports(self) -> None:
        failures = domain_context_check.source_boundary_failures(
            "internal/release/domain/models.go",
            'package domain\nimport "example.test/server/internal/app"\n'
            'type Release struct { ID string `json:"id"` }\n',
        )

        self.assertTrue(any("tag" in failure for failure in failures))
        self.assertTrue(any("non-standard" in failure for failure in failures))

    def test_source_boundary_ignores_string_literals_outside_imports(self) -> None:
        source = (
            'package domain\nimport "time"\n'
            'func report() []string { return []string{\n'
            '    "This example.test/text is report copy, not an import.",\n'
            '} }\n'
        )
        self.assertEqual(domain_context_check.source_boundary_failures("internal/risk/domain/report.go", source), [])

    def test_source_boundary_checks_block_import_aliases(self) -> None:
        source = (
            'package domain\nimport (\n    "time"\n'
            '    adapter "example.test/project/internal/adapter"\n)\n'
        )
        failures = domain_context_check.source_boundary_failures("internal/risk/domain/report.go", source)
        self.assertEqual(len(failures), 1)
        self.assertIn("example.test/project/internal/adapter", failures[0])

    def test_field_compatibility_rejects_missing_and_changed_fields(self) -> None:
        failures = domain_context_check.context_field_compatibility_failures(
            "release",
            {"Release"},
            {
                "Release": {
                    "ID": "string",
                    "State": "string",
                    "CreatedAt": "time.Time",
                }
            },
            {"Release": {"ID": "string", "State": "string"}},
        )

        self.assertEqual(len(failures), 1)
        self.assertIn("missing fields CreatedAt", failures[0])
        self.assertIn("changed field types State (ReleaseState -> string)", failures[0])

    def test_repository_context_models_are_valid(self) -> None:
        self.assertEqual(domain_context_check.validate_repository(), [])


if __name__ == "__main__":
    unittest.main()
