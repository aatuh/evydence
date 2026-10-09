#!/usr/bin/env python3
"""Verify parser-fixture provenance and execute the versioned conformance corpus."""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "testdata" / "parser-corpus.v1.json"

def safe_file(relative: str) -> pathlib.Path:
    path = (ROOT / relative).resolve()
    if ROOT not in path.parents or not path.is_file():
        raise ValueError("invalid corpus path")
    return path

def main() -> int:
    try:
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if document.get("schema_version") != "evydence-parser-corpus.v1" or not isinstance(document.get("fixtures"), list):
            raise ValueError("invalid corpus manifest")
        for fixture in document["fixtures"]:
            required = {"id", "kind", "path", "sha256", "license", "source", "expected_status", "expected_summary", "max_bytes"}
            if not isinstance(fixture, dict) or required - fixture.keys() or fixture["expected_status"] != "accepted" or not isinstance(fixture["expected_summary"], dict) or not isinstance(fixture["max_bytes"], int) or fixture["max_bytes"] <= 0:
                raise ValueError("invalid corpus fixture")
            raw = safe_file(fixture["path"]).read_bytes()
            if len(raw) > fixture["max_bytes"] or hashlib.sha256(raw).hexdigest() != fixture["sha256"] or not safe_file(fixture["source"]):
                raise ValueError("corpus fixture integrity or provenance mismatch")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"parser-corpus-check: {exc}", file=sys.stderr)
        return 1
    result = subprocess.run(["go", "test", "./internal/app", "-run", "^TestParserConformanceCorpus$", "-count=1"], cwd=ROOT, check=False)
    if result.returncode:
        return result.returncode
    print(f"parser-corpus-check: validated {len(document['fixtures'])} versioned fixtures")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
