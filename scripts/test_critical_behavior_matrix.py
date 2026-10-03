#!/usr/bin/env python3
"""Regression tests for the critical behavior evidence matrix."""

from __future__ import annotations

import dataclasses
import pathlib
import tempfile
import unittest

import critical_behavior_matrix


class CriticalBehaviorMatrixTests(unittest.TestCase):
    def test_repository_matrix_references_are_valid(self) -> None:
        failures = critical_behavior_matrix.validate_behaviors(
            critical_behavior_matrix.BEHAVIORS,
            critical_behavior_matrix.ROOT,
        )

        self.assertEqual(failures, [])

    def test_missing_negative_or_failure_evidence_is_rejected(self) -> None:
        behavior = critical_behavior_matrix.BEHAVIORS[0]
        missing_negative = dataclasses.replace(
            behavior,
            negative=critical_behavior_matrix.Evidence(),
        )
        missing_failure = dataclasses.replace(
            behavior,
            failure=critical_behavior_matrix.Evidence(),
        )

        negative_failures = critical_behavior_matrix.validate_behaviors(
            (missing_negative,),
            critical_behavior_matrix.ROOT,
            required_ids={behavior.identifier},
        )
        failure_failures = critical_behavior_matrix.validate_behaviors(
            (missing_failure,),
            critical_behavior_matrix.ROOT,
            required_ids={behavior.identifier},
        )

        self.assertTrue(any("negative" in failure for failure in negative_failures))
        self.assertTrue(any("failure" in failure for failure in failure_failures))

    def test_reference_validation_rejects_absolute_traversal_and_missing_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "sample_test.go"
            source.write_text("func TestPresent(t *testing.T) {}\n", encoding="utf-8")

            self.assertEqual(
                critical_behavior_matrix.validate_reference(
                    "sample_test.go::TestPresent", root
                ),
                [],
            )
            self.assertTrue(
                critical_behavior_matrix.validate_reference(
                    "/absolute/sample_test.go::TestPresent", root
                )
            )
            self.assertTrue(
                critical_behavior_matrix.validate_reference(
                    "../sample_test.go::TestPresent", root
                )
            )
            self.assertTrue(
                critical_behavior_matrix.validate_reference(
                    "sample_test.go::TestMissing", root
                )
            )

    def test_ci_coverage_artifact_is_tied_to_exact_commit(self) -> None:
        failures = critical_behavior_matrix.validate_ci_contract(
            critical_behavior_matrix.CI_WORKFLOW
        )

        self.assertEqual(failures, [])

    def test_rendered_matrix_contains_every_behavior_and_policy(self) -> None:
        rendered = critical_behavior_matrix.render(critical_behavior_matrix.BEHAVIORS)

        for identifier in critical_behavior_matrix.REQUIRED_BEHAVIOR_IDS:
            self.assertIn(f"`{identifier}`", rendered)
        self.assertIn("80.0%", rendered)
        self.assertIn("81.0%", rendered)
        self.assertIn("Flaky-Test Policy", rendered)
        self.assertIn("Deterministic Fixture Policy", rendered)


if __name__ == "__main__":
    unittest.main()
