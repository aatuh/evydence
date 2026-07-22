#!/usr/bin/env python3
"""Regression tests for the repository-local quality scorecard checker."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("quality_scorecard.py")
SPEC = importlib.util.spec_from_file_location("quality_scorecard", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load quality scorecard checker")
QUALITY_SCORECARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY_SCORECARD)


DIMENSIONS = [
    "Dependency-worthiness",
    "Code and architecture",
    "Tests",
    "Documentation",
    "Open-source trust",
    "Ecosystem fit",
    "Feature completeness",
    "API design",
]


def scorecard(overall: str = "4.0", external_status: str = "Open") -> str:
    rows = [
        "| Dimension | Current score | Target score | Repository evidence | External evidence | Blockers |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for dimension in DIMENSIONS:
        rows.append(
            f"| {dimension} | 4.0/10 | 9.0/10 | [evidence](evidence.md) | "
            f"{external_status} | EVY-1604 |"
        )
    return "\n".join(
        [
            "# Quality Scorecard",
            "",
            "Last verified commit: `0123456789abcdef0123456789abcdef01234567`",
            f"Overall evidence score: `{overall}/10`",
            "",
            "## Dimensions",
            "",
            *rows,
            "",
            "## Required External Evidence",
            "",
            "- [ ] Independent security review",
            "- [ ] Two design-partner pilots",
            "",
        ]
    )


class QualityScorecardTests(unittest.TestCase):
    def write_scorecard(self, body: str) -> tuple[Path, Path]:
        root = Path(tempfile.mkdtemp())
        reference = root / "docs" / "reference"
        reference.mkdir(parents=True)
        (reference / "evidence.md").write_text("# Evidence\n", encoding="utf-8")
        card = reference / "quality-scorecard.md"
        card.write_text(body, encoding="utf-8")
        return root, card

    def test_accepts_conservative_score_with_open_external_evidence(self) -> None:
        root, card = self.write_scorecard(scorecard())

        self.assertEqual(QUALITY_SCORECARD.validate_scorecard(card, root, validate_commit=False), [])

    def test_rejects_nine_with_open_external_evidence(self) -> None:
        root, card = self.write_scorecard(scorecard(overall="9.0"))

        failures = QUALITY_SCORECARD.validate_scorecard(card, root, validate_commit=False)

        self.assertIn("overall score is 9.0/10 while external evidence remains open", failures)

    def test_rejects_missing_repository_evidence_link(self) -> None:
        root, card = self.write_scorecard(scorecard().replace("[evidence](evidence.md)", "no evidence", 1))

        failures = QUALITY_SCORECARD.validate_scorecard(card, root, validate_commit=False)

        self.assertIn("Dependency-worthiness has no repository evidence link", failures)


if __name__ == "__main__":
    unittest.main()
