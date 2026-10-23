#!/usr/bin/env python3
"""Generate deterministic release-candidate SBOM and provenance metadata."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

import release_artifacts
import release_build
import release_evidence_profile as profile
import release_evidence_tools
import release_scanner
import release_subjects
import support_matrix


MAX_MODULE_METADATA_BYTES = 8 * 1024 * 1024
MAX_MODULE_RECORDS = 4096
PROJECT_MODULE = "github.com/aatuh/evydence"
MODULE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)*")
MODULE_VERSION = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+incompatible)?"
)


def module_metadata_error() -> ValueError:
    return ValueError("invalid release module metadata")


def module_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise module_metadata_error()
        value[key] = item
    return value


def module_path(value):
    if type(value) is not str or not 1 <= len(value) <= 1024 or MODULE_PATH.fullmatch(value) is None:
        raise module_metadata_error()
    return value


def module_version(value, *, main=False):
    if main and value == "":
        return value
    if type(value) is not str or not 1 <= len(value) <= 256 or MODULE_VERSION.fullmatch(value) is None:
        raise module_metadata_error()
    return value


def run(args: list[str]) -> str:
    environment = release_build.build_environment(os.environ, support_matrix.load_policy()['go']['current'])
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL,
                                   env=environment, timeout=30).strip()


def go_modules() -> list[dict[str, str]]:
    try:
        raw = subprocess.check_output(["go", "list", "-m", "-json", "all"], text=True,
                                      stderr=subprocess.DEVNULL, timeout=120,
                                      env=release_build.build_environment(os.environ, support_matrix.load_policy()['go']['current']))
        if type(raw) is not str or len(raw.encode("utf-8")) > MAX_MODULE_METADATA_BYTES:
            raise module_metadata_error()
        decoder = json.JSONDecoder(object_pairs_hook=module_object)
        modules = {}
        idx = 0
        records = 0
        while idx < len(raw):
            while idx < len(raw) and raw[idx].isspace():
                idx += 1
            if idx >= len(raw):
                break
            obj, idx = decoder.raw_decode(raw, idx)
            records += 1
            if type(obj) is not dict or records > MAX_MODULE_RECORDS:
                raise module_metadata_error()
            path = module_path(obj.get("Path"))
            if "Replace" in obj:
                replacement = obj["Replace"]
                if type(replacement) is not dict:
                    raise module_metadata_error()
                # Local replacements do not identify a locked public module and
                # must never turn a private filesystem path into a version.
                path = module_path(replacement.get("Path"))
                version = module_version(replacement.get("Version"))
            else:
                version = module_version(obj.get("Version", ""),
                                         main=path == PROJECT_MODULE and obj.get("Main") is True)
            if path in modules:
                raise module_metadata_error()
            modules[path] = version
        if not modules:
            raise module_metadata_error()
        return [{"path": path, "version": version} for path, version in sorted(modules.items())]
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError, RecursionError):
        raise module_metadata_error() from None


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def generate() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('distdir')
    parser.add_argument('--syft', default=os.environ.get('EVYDENCE_RELEASE_SYFT', ''))
    arguments = parser.parse_args()
    tag = arguments.tag
    distdir = Path(arguments.distdir).resolve()
    repo = Path.cwd().resolve()
    try:
        distdir.relative_to(repo)
    except ValueError:
        print("distdir must be inside the repository", file=sys.stderr)
        return 2
    if not distdir.is_dir():
        print("release evidence output directory is missing", file=sys.stderr)
        return 2

    commit = run(["git", "rev-parse", "HEAD"])
    commit_date = run(["git", "show", "-s", "--format=%cI", "HEAD"])
    go_version = run(["go", "version"])
    try:
        modules = go_modules()
    except ValueError:
        print("release evidence metadata: invalid module metadata", file=sys.stderr)
        return 2

    release_artifacts.validate_coordinates(tag, commit)
    current = support_matrix.load_policy()['go']['current']
    if (go_version != 'go version go' + current + ' linux/amd64'
            or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}', commit_date) is None):
        raise ValueError('invalid release source identity')

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

    if not arguments.syft:
        raise ValueError('pinned release scanner is required')
    executable = Path(arguments.syft).resolve()
    installed = release_evidence_tools.verify_installation(executable.parent, release_evidence_tools.recipe_digest())
    if installed != executable:
        raise ValueError('invalid pinned scanner installation')
    with tempfile.TemporaryDirectory(prefix='evydence-release-sbom-') as temporary:
        scratch = Path(temporary)
        release_scanner.verify_tool(executable, scratch)
        records = release_subjects.collect(distdir, tag, scratch / 'subjects')
        boms = {item['name']: release_scanner.scan(executable, item, scratch / ('scan-' + str(index)))
                for index, item in enumerate(records)}
        handle, size = release_artifacts.regular_file(distdir / 'release-build-manifest.json')
        with handle:
            if size > profile.MAX_JSON_BYTES:
                raise ValueError('invalid build manifest')
            manifest_bytes = handle.read(profile.MAX_JSON_BYTES + 1)
        manifest = profile.parse_json(manifest_bytes)
        invocation = 'local'
        workflow_commit = None
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            run_id = os.environ.get('GITHUB_RUN_ID', '')
            if (os.environ.get('GITHUB_REPOSITORY') != 'aatuh/evydence'
                    or re.fullmatch(r'[1-9][0-9]{0,19}', run_id) is None):
                raise ValueError('invalid builder invocation')
            invocation = profile.SOURCE + '/actions/runs/' + run_id
            workflow_commit = os.environ.get('GITHUB_WORKFLOW_SHA', '')
        documents = profile.documents(records, boms, manifest, profile.digest(manifest_bytes),
                                      tag, commit, invocation=invocation, workflow_commit=workflow_commit)
        documents['evydence-release-sbom.cdx.json'] = profile.json_bytes(sbom)
        for name in documents:
            if (distdir / name).exists() or (distdir / name).is_symlink():
                raise ValueError('release evidence output already exists')
        for name, raw in documents.items():
            with (distdir / name).open('xb') as output:
                output.write(raw)
    print('wrote artifact-bound release SBOMs, provenance and evidence index')
    return 0


def main() -> int:
    try:
        return generate()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, RecursionError):
        print('release evidence metadata generation failed', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
