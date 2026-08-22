#!/usr/bin/env python3
"""Unit tests for the deterministic OpenAPI compatibility policy."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import openapi_breaking_check as checker  # noqa: E402


BASELINE_SHA = "a" * 64


def spec(*, operation_id: str = "readWidget", scopes: list[str] | None = None, idempotency: object = None, responses: dict[str, object] | None = None, error_codes: list[str] | None = None) -> dict:
    operation: dict[str, object] = {
        "operationId": operation_id,
        "x-scopes": scopes if scopes is not None else ["widget:read"],
        "responses": responses if responses is not None else {"200": {"description": "ok"}},
    }
    if idempotency is not None:
        operation["x-idempotency-key"] = idempotency
    schemas: dict[str, object] = {}
    if error_codes is not None:
        schemas["ErrorCode"] = {"type": "string", "enum": error_codes}
    return {"openapi": "3.1.0", "paths": {"/v1/widgets": {"get": operation}}, "components": {"schemas": schemas}}


def manifest(channel: str = "prerelease") -> dict:
    return {"schema_version": 1, "release_tag": "v0.1.0-rc.7", "channel": channel, "artifact_sha256": BASELINE_SHA}


def external_change(*, fingerprint: str = "external-break", rule: str = "new-required-request-property", text: str = "added a required request field") -> list[dict]:
    return [{"level": 3, "id": rule, "fingerprint": fingerprint, "text": text, "operation": "POST", "path": "/v1/widgets", "operationId": "createWidget"}]


def exact_exception(base: dict, target: dict, report: list[dict], *, channel: str = "prerelease", kind: str = "prerelease") -> dict:
    changes = checker.normalized_changes(checker.collect_oasdiff_changes(report) + checker.collect_policy_changes(base, target))
    entry: dict[str, object] = {
        "id": "known-prerelease-break",
        "baseline_sha256": BASELINE_SHA,
        "changes_sha256": checker.changes_digest(changes),
        "change_count": len(changes),
        "change_summary": checker.change_summary(changes),
        "channel": channel,
        "kind": kind,
        "migration_note": "docs/reference/openapi.md#review-the-contract",
        "changelog_note": "CHANGELOG.md#unreleased",
    }
    if channel == "prerelease":
        entry["approval_ref"] = "EVY-705 test approval"
    else:
        entry["security_advisory"] = "SEC-TEST-1"
    return {"schema_version": 1, "exceptions": [entry]}


class CompatibilityPolicyTests(unittest.TestCase):
    def test_unapproved_required_field_break_fails(self) -> None:
        base = spec()
        target = spec()
        with self.assertRaisesRegex(checker.CheckFailure, "unapproved breaking"):
            checker.check_contracts(manifest(), base, target, external_change(), {"schema_version": 1, "exceptions": []})

    def test_exact_prerelease_exception_allows_only_current_break_set(self) -> None:
        base = spec(error_codes=["OLD"])
        target = spec(operation_id="readWidgetV2", error_codes=["OLD", "NEW"])
        report = external_change(fingerprint="required-name")
        exceptions = exact_exception(base, target, report)
        result = checker.check_contracts(manifest(), base, target, report, exceptions)
        self.assertEqual(result.exception_id, "known-prerelease-break")
        with self.assertRaisesRegex(checker.CheckFailure, "unapproved breaking"):
            checker.check_contracts(manifest(), base, target, external_change(fingerprint="different"), exceptions)

    def test_policy_detects_operation_scope_idempotency_response_and_error_code_changes(self) -> None:
        base = spec(
            scopes=["widget:read"],
            idempotency={"header": "Idempotency-Key", "required": False},
            responses={"200": {"description": "ok"}, "404": {"description": "missing"}},
            error_codes=["OLD"],
        )
        target = spec(
            operation_id="readWidgetV2",
            scopes=["widget:write"],
            idempotency={"header": "Idempotency-Key", "required": True},
            responses={"200": {"description": "ok"}},
            error_codes=["NEW"],
        )
        rules = {change.rule for change in checker.collect_policy_changes(base, target)}
        self.assertTrue({"operation-id-changed", "scope-contract-changed", "idempotency-contract-changed", "response-status-removed", "error-code-added", "error-code-removed"}.issubset(rules))

    def test_stable_line_rejects_non_emergency_exception(self) -> None:
        base = spec()
        target = spec()
        report = external_change()
        exceptions = exact_exception(base, target, report, channel="stable", kind="prerelease")
        with self.assertRaisesRegex(checker.CheckFailure, "unapproved breaking"):
            checker.check_contracts(manifest("stable"), base, target, report, exceptions)

    def test_stable_security_emergency_requires_advisory(self) -> None:
        base = spec()
        target = spec()
        report = external_change()
        exceptions = exact_exception(base, target, report, channel="stable", kind="security-emergency")
        result = checker.check_contracts(manifest("stable"), base, target, report, exceptions)
        self.assertEqual(result.exception_id, "known-prerelease-break")
        del exceptions["exceptions"][0]["security_advisory"]
        with self.assertRaisesRegex(checker.CheckFailure, "security_advisory"):
            checker.check_contracts(manifest("stable"), base, target, report, exceptions)

    def test_deprecated_operation_requires_replacement_headers_and_notice(self) -> None:
        target = spec()
        operation = target["paths"]["/v1/widgets"]["get"]
        operation["responses"] = {
            "200": {
                "description": "ok",
                "headers": {"Deprecation": {}, "Sunset": {}, "Link": {}},
            }
        }
        operation["deprecated"] = True
        operation["x-evydence-deprecation"] = {
            "replacement_operation_id": "readWidgetV2",
            "removal_version": "v1.2.0",
            "minimum_notice_days": 180,
            "deprecated_at": "2026-01-01T00:00:00Z",
            "migration_guide": "docs/reference/openapi.md#review-the-contract",
            "sunset": "Wed, 01 Jul 2026 00:00:00 GMT",
            "headers": ["Deprecation", "Sunset", "Link"],
        }
        operation["x-sunset"] = "Wed, 01 Jul 2026 00:00:00 GMT"
        target["paths"]["/v1/widgets-v2"] = {"get": {"operationId": "readWidgetV2", "x-scopes": ["widget:read"], "responses": {"200": {"description": "ok"}}}}
        checker.validate_deprecations(target)
        operation["x-evydence-deprecation"]["minimum_notice_days"] = 1
        with self.assertRaisesRegex(checker.CheckFailure, "minimum_notice_days"):
            checker.validate_deprecations(target)


if __name__ == "__main__":
    unittest.main()
