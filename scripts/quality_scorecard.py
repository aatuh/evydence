#!/usr/bin/env python3
"""Validate evidence and external-blocker rules in the quality scorecard."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCORECARD = ROOT / "docs" / "reference" / "quality-scorecard.md"
DIMENSIONS = (
    "Dependency-worthiness",
    "Code and architecture",
    "Tests",
    "Documentation",
    "Open-source trust",
    "Ecosystem fit",
    "Feature completeness",
    "API design",
)
TABLE_HEADER = (
    "Dimension",
    "Current score",
    "Target score",
    "Repository evidence",
    "External evidence",
    "Blockers",
)
SCORE_RE = re.compile(r"^(?:0|[1-9](?:\.\d+)?|10(?:\.0+)?)/10$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def section(lines: list[str], heading: str) -> list[str]:
    try:
        start = lines.index(heading) + 1
    except ValueError:
        return []
    result: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        result.append(line)
    return result


def table_rows(lines: list[str]) -> tuple[list[str], list[list[str]]]:
    rows = [line for line in lines if line.startswith("|")]
    if len(rows) < 2:
        return [], []
    parsed = [[cell.strip() for cell in row.strip("|").split("|")] for row in rows]
    return parsed[0], parsed[2:]


def score(value: str) -> float:
    return float(value.removesuffix("/10"))


def local_links_exist(text: str, root: Path, source: Path) -> list[str]:
    failures: list[str] = []
    for target in LINK_RE.findall(text):
        destination = target.strip().split("#", 1)[0]
        if not destination or "://" in destination or destination.startswith("mailto:"):
            continue
        path = (source.parent / destination).resolve()
        if root not in path.parents and path != root:
            failures.append(f"scorecard link escapes repository: {target}")
        elif not path.exists():
            failures.append(f"scorecard link target does not exist: {target}")
    return failures


def commit_exists(commit: str, root: Path) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def validate_scorecard(card: Path, root: Path, validate_commit: bool = True) -> list[str]:
    if not card.is_file():
        return [f"missing scorecard: {card}"]
    text = card.read_text(encoding="utf-8")
    lines = text.splitlines()
    failures: list[str] = []
    if not lines or lines[0] != "# Quality Scorecard":
        failures.append("scorecard must start with '# Quality Scorecard'")

    commit_match = re.search(r"^Last verified commit: `([^`]+)`$", text, re.MULTILINE)
    if commit_match is None:
        failures.append("scorecard is missing Last verified commit")
    else:
        commit = commit_match.group(1)
        if not COMMIT_RE.fullmatch(commit):
            failures.append("Last verified commit must be a 40-character lowercase SHA")
        elif validate_commit and not commit_exists(commit, root):
            failures.append(f"Last verified commit is not available locally: {commit}")

    overall_match = re.search(r"^Overall evidence score: `([^`]+)/10`$", text, re.MULTILINE)
    if overall_match is None:
        failures.append("scorecard is missing Overall evidence score")
        overall = 0.0
    else:
        candidate = f"{overall_match.group(1)}/10"
        if not SCORE_RE.fullmatch(candidate):
            failures.append("Overall evidence score must be between 0 and 10")
            overall = 0.0
        else:
            overall = score(candidate)

    header, rows = table_rows(section(lines, "## Dimensions"))
    if header != list(TABLE_HEADER):
        failures.append("Dimensions table has an unexpected header")
    found: set[str] = set()
    for row in rows:
        if len(row) != len(TABLE_HEADER):
            failures.append("Dimensions table has a malformed row")
            continue
        dimension, current, target, repository, external, blockers = row
        found.add(dimension)
        if not SCORE_RE.fullmatch(current):
            failures.append(f"{dimension} has an invalid current score")
        if not SCORE_RE.fullmatch(target):
            failures.append(f"{dimension} has an invalid target score")
        if not LINK_RE.search(repository):
            failures.append(f"{dimension} has no repository evidence link")
        if not external.startswith("Open") and not LINK_RE.search(external):
            failures.append(f"{dimension} has no external evidence status or link")
        if not blockers:
            failures.append(f"{dimension} has no blocker disposition")
    missing = sorted(set(DIMENSIONS) - found)
    unexpected = sorted(found - set(DIMENSIONS))
    if missing:
        failures.append(f"Dimensions table is missing: {', '.join(missing)}")
    if unexpected:
        failures.append(f"Dimensions table has unexpected entries: {', '.join(unexpected)}")

    external_items = re.findall(r"^- \[([ x])\] .+$", "\n".join(section(lines, "## Required External Evidence")), re.MULTILINE)
    if not external_items:
        failures.append("Required External Evidence must contain a checklist")
    elif overall >= 9.0 and any(item != "x" for item in external_items):
        failures.append(f"overall score is {overall:.1f}/10 while external evidence remains open")

    failures.extend(local_links_exist(text, root, card))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the committed quality scorecard")
    args = parser.parse_args()
    if not args.check:
        parser.error("--check is required")
    failures = validate_scorecard(SCORECARD, ROOT)
    if failures:
        for failure in failures:
            print(f"quality-scorecard-check: {failure}", file=sys.stderr)
        return 1
    print("quality-scorecard-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
