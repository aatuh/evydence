#!/usr/bin/env python3
"""Enforce Evydence's public OpenAPI compatibility policy.

The baseline is a checked-in release artifact whose digest is verified before
comparison. oasdiff performs structural OpenAPI comparison; this script adds
Evydence-specific contract checks for operation IDs, scopes, idempotency, and
the generated Problem Details error-code catalog. Exceptions are exact,
baseline-bound snapshots so they cannot silently approve later breaks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_OASDIFF_VERSION = "1.29.1"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
MAX_OASDIFF_OUTPUT_BYTES = 20 * 1024 * 1024
MINIMUM_DEPRECATION_NOTICE_DAYS = 180


class CheckFailure(RuntimeError):
    """A deterministic compatibility-policy failure."""


@dataclass(frozen=True)
class ContractChange:
    source: str
    rule: str
    location: str
    detail: str
    fingerprint: str

    def as_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "rule": self.rule,
            "location": self.location,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class CheckResult:
    baseline_sha256: str
    changes: tuple[ContractChange, ...]
    changes_sha256: str
    exception_id: str | None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_file(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise CheckFailure(f"{label} must be an existing file beneath the repository root: {value}") from exc
    if not resolved.is_file():
        raise CheckFailure(f"{label} must be a regular file: {value}")
    return resolved


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise CheckFailure(f"{label} is not UTF-8 JSON: {path.relative_to(ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise CheckFailure(f"{label} is invalid JSON: {path.relative_to(ROOT)}: {exc.msg}") from exc


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CheckFailure(f"{label} must be a JSON object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CheckFailure(f"{label} must be a non-empty string")
    return value.strip()


def load_baseline(path: Path) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    baseline = require_object(read_json(path, "baseline manifest"), "baseline manifest")
    if baseline.get("schema_version") != 1:
        raise CheckFailure("baseline manifest schema_version must be 1")
    require_string(baseline.get("release_tag"), "baseline manifest release_tag")
    release_url = require_string(baseline.get("release_url"), "baseline manifest release_url")
    if not release_url.startswith("https://github.com/"):
        raise CheckFailure("baseline manifest release_url must be an HTTPS GitHub release URL")
    channel = require_string(baseline.get("channel"), "baseline manifest channel")
    if channel not in {"prerelease", "stable"}:
        raise CheckFailure("baseline manifest channel must be prerelease or stable")
    artifact = repository_file(require_string(baseline.get("artifact"), "baseline manifest artifact"), "baseline artifact")
    expected_sha = require_string(baseline.get("artifact_sha256"), "baseline manifest artifact_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise CheckFailure("baseline manifest artifact_sha256 must be a lowercase SHA-256 digest")
    actual_sha = file_sha256(artifact)
    if actual_sha != expected_sha:
        raise CheckFailure(
            "baseline artifact digest mismatch: expected " + expected_sha + ", got " + actual_sha
        )
    if baseline.get("published_asset_digest") != "sha256:" + expected_sha:
        raise CheckFailure("baseline manifest published_asset_digest must match artifact_sha256")
    spec = require_object(read_json(artifact, "baseline OpenAPI artifact"), "baseline OpenAPI artifact")
    return baseline, artifact, spec


def resolve_tool(value: str) -> Path:
    candidate = Path(value)
    if candidate.parent != Path(".") or candidate.is_absolute():
        path = candidate.expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise CheckFailure(f"OASDIFF_BIN is not an executable file: {value}")
    else:
        found = shutil.which(value)
        if not found:
            raise CheckFailure(
                "oasdiff is required; install the pinned release or set OASDIFF_BIN to its executable path"
            )
        path = Path(found).resolve()
    try:
        completed = subprocess.run(
            [str(path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckFailure(f"cannot execute oasdiff: {exc}") from exc
    version_output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0 or not re.search(rf"\b{re.escape(EXPECTED_OASDIFF_VERSION)}\b", version_output):
        raise CheckFailure(
            f"oasdiff {EXPECTED_OASDIFF_VERSION} is required; got {version_output or 'no version output'}"
        )
    return path


def run_oasdiff(tool: Path, baseline: Path, candidate: Path) -> list[dict[str, Any]]:
    command = [
        str(tool),
        "breaking",
        str(baseline),
        str(candidate),
        "--format",
        "json",
        "--allow-external-refs=false",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckFailure(f"oasdiff comparison failed to run: {exc}") from exc
    if len(completed.stdout.encode("utf-8")) > MAX_OASDIFF_OUTPUT_BYTES:
        raise CheckFailure("oasdiff output exceeded the 20 MiB safety limit")
    if completed.returncode not in {0, 1}:
        diagnostic = completed.stderr.strip().replace("\n", " ")[:1000]
        raise CheckFailure(f"oasdiff comparison failed (exit {completed.returncode}): {diagnostic}")
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CheckFailure("oasdiff did not return a JSON breaking-change report") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        raise CheckFailure("oasdiff breaking-change report must be an array of objects")
    return parsed


def operation_map(spec: dict[str, Any], label: str) -> dict[tuple[str, str], dict[str, Any]]:
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        raise CheckFailure(f"{label} paths must be an object")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise CheckFailure(f"{label} contains an invalid path item")
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise CheckFailure(f"{label} operation {method.upper()} {path} must be an object")
            result[(method.upper(), path)] = operation
    return result


def normalized_string_list(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise CheckFailure(f"{label} must be an array of non-empty strings")
    return tuple(sorted(set(item.strip() for item in value)))


def response_statuses(operation: dict[str, Any], label: str) -> tuple[str, ...]:
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        raise CheckFailure(f"{label} responses must be an object")
    return tuple(sorted(str(status) for status in responses))


def idempotency_contract(operation: dict[str, Any]) -> str:
    return canonical_json(operation.get("x-idempotency-key"))


def error_codes(spec: dict[str, Any], label: str) -> tuple[str, ...]:
    components = spec.get("components", {})
    if not isinstance(components, dict):
        raise CheckFailure(f"{label} components must be an object")
    schemas = components.get("schemas", {})
    if not isinstance(schemas, dict):
        raise CheckFailure(f"{label} components.schemas must be an object")
    schema = schemas.get("ErrorCode")
    if schema is None:
        return ()
    if not isinstance(schema, dict):
        raise CheckFailure(f"{label} ErrorCode schema must be an object")
    return normalized_string_list(schema.get("enum"), f"{label} ErrorCode enum")


def validate_deprecations(spec: dict[str, Any]) -> None:
    operations = operation_map(spec, "candidate OpenAPI")
    operation_ids = {
        operation_id
        for operation in operations.values()
        if isinstance(operation.get("operationId"), str) and operation["operationId"].strip()
        for operation_id in [operation["operationId"].strip()]
    }
    for (method, path), operation in operations.items():
        deprecated = operation.get("deprecated", False)
        if not isinstance(deprecated, bool):
            raise CheckFailure(f"{method} {path} deprecated must be a boolean")
        if not deprecated:
            continue
        location = f"{method} {path}"
        policy = require_object(operation.get("x-evydence-deprecation"), location + " x-evydence-deprecation")
        replacement = require_string(policy.get("replacement_operation_id"), location + " replacement_operation_id")
        if replacement not in operation_ids or replacement == operation.get("operationId"):
            raise CheckFailure(f"{location} must name a distinct existing replacement operation")
        removal_version = require_string(policy.get("removal_version"), location + " removal_version")
        if not re.fullmatch(r"v[0-9]+(?:\.[0-9]+){1,2}(?:-[0-9A-Za-z.-]+)?", removal_version):
            raise CheckFailure(f"{location} removal_version must be a version beginning with v")
        notice_days = policy.get("minimum_notice_days")
        if not isinstance(notice_days, int) or notice_days < MINIMUM_DEPRECATION_NOTICE_DAYS:
            raise CheckFailure(f"{location} minimum_notice_days must be at least {MINIMUM_DEPRECATION_NOTICE_DAYS}")
        deprecated_at = require_string(policy.get("deprecated_at"), location + " deprecated_at")
        try:
            deprecated_time = datetime.fromisoformat(deprecated_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CheckFailure(f"{location} deprecated_at must be RFC 3339") from exc
        if deprecated_time.tzinfo is None:
            raise CheckFailure(f"{location} deprecated_at must include a timezone")
        migration_guide = require_string(policy.get("migration_guide"), location + " migration_guide")
        validate_document_reference(migration_guide, location + " migration_guide")
        sunset = require_string(policy.get("sunset"), location + " sunset")
        if operation.get("x-sunset") != sunset:
            raise CheckFailure(f"{location} x-sunset must equal x-evydence-deprecation.sunset")
        try:
            sunset_time = parsedate_to_datetime(sunset)
        except (TypeError, ValueError, IndexError) as exc:
            raise CheckFailure(f"{location} sunset must be an HTTP-date") from exc
        if sunset_time.tzinfo is None:
            sunset_time = sunset_time.replace(tzinfo=timezone.utc)
        if sunset_time < deprecated_time.astimezone(timezone.utc) + timedelta(days=notice_days):
            raise CheckFailure(f"{location} sunset must honor minimum_notice_days")
        headers = normalized_string_list(policy.get("headers"), location + " deprecation headers")
        if not {"Deprecation", "Link", "Sunset"}.issubset(headers):
            raise CheckFailure(f"{location} must advertise Deprecation, Sunset, and Link headers")
        responses = operation.get("responses")
        if not isinstance(responses, dict) or not responses:
            raise CheckFailure(f"{location} must document response headers")
        for status, response in responses.items():
            if not isinstance(response, dict):
                raise CheckFailure(f"{location} response {status} must be an object")
            response_headers = response.get("headers")
            if not isinstance(response_headers, dict) or not {"Deprecation", "Link", "Sunset"}.issubset(response_headers):
                raise CheckFailure(f"{location} response {status} must document Deprecation, Sunset, and Link headers")


def policy_change(rule: str, location: str, detail: str) -> ContractChange:
    fingerprint = digest_text(canonical_json({"rule": rule, "location": location, "detail": detail}))[:16]
    return ContractChange("evydence-policy", rule, location, detail, fingerprint)


def collect_policy_changes(base: dict[str, Any], target: dict[str, Any]) -> list[ContractChange]:
    base_operations = operation_map(base, "baseline OpenAPI")
    target_operations = operation_map(target, "candidate OpenAPI")
    changes: list[ContractChange] = []
    for key in sorted(base_operations):
        method, path = key
        location = f"{method} {path}"
        target_operation = target_operations.get(key)
        if target_operation is None:
            changes.append(policy_change("operation-removed", location, "operation is absent from the candidate contract"))
            continue
        base_operation = base_operations[key]
        base_id = base_operation.get("operationId")
        target_id = target_operation.get("operationId")
        if isinstance(base_id, str) and base_id and base_id != target_id:
            changes.append(policy_change("operation-id-changed", location, f"{base_id} -> {target_id!r}"))
        base_scopes = normalized_string_list(base_operation.get("x-scopes"), location + " baseline x-scopes")
        target_scopes = normalized_string_list(target_operation.get("x-scopes"), location + " candidate x-scopes")
        if base_scopes != target_scopes:
            changes.append(policy_change("scope-contract-changed", location, f"{base_scopes} -> {target_scopes}"))
        base_idempotency = idempotency_contract(base_operation)
        target_idempotency = idempotency_contract(target_operation)
        if base_idempotency != target_idempotency:
            changes.append(policy_change("idempotency-contract-changed", location, "x-idempotency-key changed"))
        removed_statuses = sorted(set(response_statuses(base_operation, location + " baseline")) - set(response_statuses(target_operation, location + " candidate")))
        if removed_statuses:
            changes.append(policy_change("response-status-removed", location, ", ".join(removed_statuses)))
    base_codes = set(error_codes(base, "baseline OpenAPI"))
    target_codes = set(error_codes(target, "candidate OpenAPI"))
    for code in sorted(target_codes - base_codes):
        changes.append(policy_change("error-code-added", "components.schemas.ErrorCode", code))
    for code in sorted(base_codes - target_codes):
        changes.append(policy_change("error-code-removed", "components.schemas.ErrorCode", code))
    return changes


def collect_oasdiff_changes(report: list[dict[str, Any]]) -> list[ContractChange]:
    changes: list[ContractChange] = []
    for item in report:
        level = item.get("level")
        rule = item.get("id")
        fingerprint = item.get("fingerprint")
        text = item.get("text")
        if not isinstance(level, int) or not isinstance(rule, str) or not isinstance(fingerprint, str) or not isinstance(text, str):
            raise CheckFailure("oasdiff report contains an invalid breaking-change entry")
        # ErrorCode changes are evaluated once from the named component below;
        # oasdiff expands that shared component for every response and would
        # otherwise produce tens of thousands of duplicate records.
        is_shared_error_code_enum = rule == "response-property-enum-value-added" and "`code` response property" in text
        if is_shared_error_code_enum:
            continue
        # oasdiff treats only level 3 as an error. Enum warnings are still
        # client-visible response compatibility changes, so retain them.
        if level < 3 and "enum" not in rule:
            continue
        operation = item.get("operation") if isinstance(item.get("operation"), str) else ""
        path = item.get("path") if isinstance(item.get("path"), str) else ""
        operation_id = item.get("operationId") if isinstance(item.get("operationId"), str) else ""
        location = " ".join(part for part in (operation, path, operation_id) if part) or "OpenAPI document"
        changes.append(ContractChange("oasdiff", rule, location, text, fingerprint))
    return changes


def normalized_changes(changes: list[ContractChange]) -> tuple[ContractChange, ...]:
    by_identity: dict[tuple[str, str], ContractChange] = {}
    for change in changes:
        identity = (change.source, change.fingerprint)
        prior = by_identity.get(identity)
        if prior is not None and prior != change:
            raise CheckFailure("compatibility change fingerprint collision")
        by_identity[identity] = change
    return tuple(sorted(by_identity.values(), key=lambda item: (item.source, item.rule, item.location, item.fingerprint)))


def changes_digest(changes: tuple[ContractChange, ...]) -> str:
    return digest_text(canonical_json([change.as_dict() for change in changes]))


def change_summary(changes: tuple[ContractChange, ...]) -> dict[str, int]:
    return dict(sorted(Counter(change.rule for change in changes).items()))


def validate_document_reference(value: Any, label: str) -> None:
    reference = require_string(value, label)
    relative_path = reference.split("#", 1)[0]
    if not relative_path:
        raise CheckFailure(f"{label} must name a repository document")
    repository_file(relative_path, label)


def matching_exception(
    exceptions: dict[str, Any],
    baseline: dict[str, Any],
    baseline_sha256: str,
    changes: tuple[ContractChange, ...],
    digest: str,
) -> str | None:
    if exceptions.get("schema_version") != 1:
        raise CheckFailure("exception file schema_version must be 1")
    items = exceptions.get("exceptions")
    if not isinstance(items, list):
        raise CheckFailure("exception file exceptions must be an array")
    channel = baseline["channel"]
    for item in items:
        item = require_object(item, "exception entry")
        exception_id = require_string(item.get("id"), "exception id")
        if item.get("baseline_sha256") != baseline_sha256:
            continue
        if item.get("changes_sha256") != digest or item.get("change_count") != len(changes):
            continue
        if item.get("change_summary") != change_summary(changes):
            raise CheckFailure(f"exception {exception_id} change_summary does not describe the exact approved change set")
        if item.get("channel") != channel:
            continue
        validate_document_reference(item.get("migration_note"), f"exception {exception_id} migration_note")
        validate_document_reference(item.get("changelog_note"), f"exception {exception_id} changelog_note")
        if channel == "prerelease":
            if item.get("kind") != "prerelease" or not isinstance(item.get("approval_ref"), str) or not item["approval_ref"].strip():
                raise CheckFailure(f"prerelease exception {exception_id} lacks an explicit approval_ref")
        else:
            if item.get("kind") != "security-emergency":
                continue
            if not isinstance(item.get("security_advisory"), str) or not item["security_advisory"].strip():
                raise CheckFailure(f"stable exception {exception_id} lacks a documented security_advisory")
        return exception_id
    return None


def check_contracts(
    baseline_manifest: dict[str, Any],
    baseline_spec: dict[str, Any],
    candidate_spec: dict[str, Any],
    oasdiff_report: list[dict[str, Any]],
    exceptions: dict[str, Any],
) -> CheckResult:
    baseline_sha = require_string(baseline_manifest.get("artifact_sha256"), "baseline manifest artifact_sha256")
    validate_deprecations(candidate_spec)
    changes = normalized_changes(collect_oasdiff_changes(oasdiff_report) + collect_policy_changes(baseline_spec, candidate_spec))
    digest = changes_digest(changes)
    exception_id = matching_exception(exceptions, baseline_manifest, baseline_sha, changes, digest) if changes else None
    if changes and exception_id is None:
        raise CheckFailure(
            f"{len(changes)} unapproved breaking OpenAPI change(s) against {baseline_manifest.get('release_tag', 'the selected baseline')} "
            f"(changes_sha256={digest})"
        )
    return CheckResult(baseline_sha, changes, digest, exception_id)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-manifest", default="docs/reference/openapi-baseline.json")
    parser.add_argument("--candidate", default="openapi.yaml")
    parser.add_argument("--exceptions", default=".github/openapi-breaking-exceptions.json")
    parser.add_argument("--oasdiff", default=os.environ.get("OASDIFF_BIN", "oasdiff"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    baseline_manifest_path = repository_file(args.baseline_manifest, "baseline manifest")
    candidate_path = repository_file(args.candidate, "candidate OpenAPI contract")
    exception_path = repository_file(args.exceptions, "exception file")
    baseline_manifest, baseline_artifact, baseline_spec = load_baseline(baseline_manifest_path)
    candidate_spec = require_object(read_json(candidate_path, "candidate OpenAPI contract"), "candidate OpenAPI contract")
    exceptions = require_object(read_json(exception_path, "exception file"), "exception file")
    tool = resolve_tool(args.oasdiff)
    result = check_contracts(
        baseline_manifest,
        baseline_spec,
        candidate_spec,
        run_oasdiff(tool, baseline_artifact, candidate_path),
        exceptions,
    )
    tag = baseline_manifest.get("release_tag", "selected baseline")
    if result.changes:
        print(
            f"openapi-breaking-check: {len(result.changes)} approved {baseline_manifest['channel']} breaking change(s) "
            f"against {tag}; exception={result.exception_id}; changes_sha256={result.changes_sha256}; "
            f"summary={canonical_json(change_summary(result.changes))}"
        )
    else:
        print(f"openapi-breaking-check: no breaking changes against {tag}")


if __name__ == "__main__":
    try:
        main()
    except CheckFailure as exc:
        print(f"openapi-breaking-check: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
