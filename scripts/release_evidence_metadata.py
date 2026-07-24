#!/usr/bin/env python3
"""Generate deterministic release-candidate SBOM and provenance metadata."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def run(args: list[str]) -> str:
    return subprocess.check_output(args, text=True).strip()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def go_modules() -> list[dict[str, str]]:
    raw = subprocess.check_output(["go", "list", "-m", "-json", "all"], text=True)
    decoder = json.JSONDecoder()
    modules: list[dict[str, str]] = []
    idx = 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
        if idx >= len(raw):
            break
        obj, idx = decoder.raw_decode(raw, idx)
        path = str(obj.get("Path", "")).strip()
        if not path:
            continue
        version = str(obj.get("Version", "")).strip()
        replacement = obj.get("Replace")
        if isinstance(replacement, dict):
            version = str(replacement.get("Version") or replacement.get("Path") or version).strip()
        modules.append({"path": path, "version": version})
    modules.sort(key=lambda item: (item["path"], item["version"]))
    return modules


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: scripts/release_evidence_metadata.py <tag> <distdir>", file=sys.stderr)
        return 2
    tag = sys.argv[1].strip()
    distdir = Path(sys.argv[2]).resolve()
    repo = Path.cwd().resolve()
    try:
        distdir.relative_to(repo)
    except ValueError:
        print("distdir must be inside the repository", file=sys.stderr)
        return 2
    if not distdir.is_dir():
        print(f"distdir missing: {distdir}", file=sys.stderr)
        return 2

    commit = run(["git", "rev-parse", "HEAD"])
    commit_date = run(["git", "show", "-s", "--format=%cI", "HEAD"])
    go_version = run(["go", "version"])
    modules = go_modules()

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "github.com/aatuh/evydence:" + tag)),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "evydence",
                "version": tag,
                "purl": "pkg:github/aatuh/evydence@" + tag,
            },
            "properties": [
                {"name": "evydence:commit", "value": commit},
                {"name": "evydence:commit_date", "value": commit_date},
                {"name": "evydence:go_version", "value": go_version},
                {"name": "evydence:limitations", "value": "Release SBOM is generated from Go module metadata and release packaging inputs; it is not a complete SBOM proof."},
            ],
        },
        "components": [
            {
                "type": "library",
                "name": module["path"],
                "version": module["version"],
                "purl": f"pkg:golang/{module['path']}@{module['version']}" if module["version"] else f"pkg:golang/{module['path']}",
            }
            for module in modules
            if module["path"] != "github.com/aatuh/evydence"
        ],
    }

    artifact_names = sorted(
        path.name
        for pattern in ("evydence_*.tar.gz", "evydence_*.zip", "openapi.yaml", "migrations.sha256", "release-notes.md", "release-build-manifest.json")
        for path in distdir.glob(pattern)
    )
    provenance = {
        "schema": "evydence-release-provenance.v1",
        "subject": {"name": "evydence", "version": tag, "commit": commit, "commit_date": commit_date},
        "builder": {
            "type": "local-or-github-actions-release-candidate-packager",
            "commands": ["make production-check", "scripts/release_candidate_package.sh"],
            "go_version": go_version,
        },
        "materials": [
            {"path": name, "sha256": sha256(distdir / name)}
            for name in artifact_names
            if (distdir / name).is_file()
        ],
        "limitations": [
            "This provenance records repository release-candidate packaging inputs and hashes.",
            "It is not a SLSA level claim, legal compliance proof, certification, complete SBOM proof, authoritative vulnerability result, or secure-release guarantee.",
            "Public release publication, registry image digest verification, branch protection, and provider account settings require operator verification outside repository files.",
        ],
        "environment": {
            "github_repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "github_ref": os.environ.get("GITHUB_REF", ""),
        },
    }
    intoto_statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {"name": material["path"], "digest": {"sha256": material["sha256"]}}
            for material in provenance["materials"]
        ],
        "predicateType": "https://evydence.dev/schemas/release-provenance/v1",
        "predicate": {
            "schema": "evydence-release-provenance.v1",
            "subject": provenance["subject"],
            "builder": provenance["builder"],
            "environment": provenance["environment"],
            "limitations": provenance["limitations"],
        },
    }

    write_json(distdir / "evydence-release-sbom.cdx.json", sbom)
    write_json(distdir / "evydence-release-provenance.json", provenance)
    write_jsonl(distdir / "evydence-release-provenance.intoto.jsonl", intoto_statement)
    print(f"wrote {distdir / 'evydence-release-sbom.cdx.json'}")
    print(f"wrote {distdir / 'evydence-release-provenance.json'}")
    print(f"wrote {distdir / 'evydence-release-provenance.intoto.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
