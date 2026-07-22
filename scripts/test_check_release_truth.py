#!/usr/bin/env python3
"""Regression tests for release-truth changelog validation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_release_truth.py")
SPEC = importlib.util.spec_from_file_location("check_release_truth", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load release-truth checker")
RELEASE_TRUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_TRUTH)


class ReleaseTruthTests(unittest.TestCase):
    def test_no_unreleased_changes_is_not_an_entry(self) -> None:
        changelog = "# Changelog\n\n## Unreleased\n\n- No unreleased changes.\n\n## v0.1.0-rc.7 - 2026-06-01\n"

        self.assertFalse(RELEASE_TRUTH.unreleased_section_has_entries(changelog))

    def test_unreleased_change_is_an_entry(self) -> None:
        changelog = "# Changelog\n\n## Unreleased\n\n### Added\n\n- Customer package proof summary.\n\n## v0.1.0-rc.7 - 2026-06-01\n"

        self.assertTrue(RELEASE_TRUTH.unreleased_section_has_entries(changelog))

    def test_user_visible_commit_detection_ignores_only_maintenance_types(self) -> None:
        subjects = ["test: add smoke test", "ci: tighten workflow", "feat: add evidence export"]

        self.assertTrue(RELEASE_TRUTH.has_user_visible_commit(subjects))
        self.assertFalse(RELEASE_TRUTH.has_user_visible_commit(["test: add smoke test", "chore: refresh fixture"]))


if __name__ == "__main__":
    unittest.main()
