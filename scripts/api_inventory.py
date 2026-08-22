#!/usr/bin/env python3
"""Generate and validate the complete public API stability inventory."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "openapi.yaml"
OUTPUT = ROOT / "docs" / "reference" / "api-inventory.md"
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
STABILITY_CLASSES = {"core", "supported", "experimental", "deprecated"}

# The ordering is intentional: more-specific route families take precedence.
OWNER_PREFIXES = (
    ("/v1/admin/", "platform-operations"),
    ("/v1/customer-portal/", "customer-delivery"),
    ("/v1/customer-packages", "customer-delivery"),
    ("/v1/redaction-profiles", "customer-delivery"),
    ("/v1/reports/", "reporting"),
    ("/v1/control", "governance"),
    ("/v1/custom-policies", "governance"),
    ("/v1/questionnaire", "governance"),
    ("/v1/approvals", "governance"),
    ("/v1/exceptions", "governance"),
    ("/v1/waivers", "governance"),
    ("/v1/legal-holds", "governance"),
    ("/v1/retention", "governance"),
    ("/v1/object-retention", "governance"),
    ("/v1/api-keys", "identity-access"),
    ("/v1/organizations", "identity-access"),
    ("/v1/users", "identity-access"),
    ("/v1/role-bindings", "identity-access"),
    ("/v1/sso/", "identity-access"),
    ("/v1/collectors", "integration-ingestion"),
    ("/v1/commercial-collectors", "integration-ingestion"),
    ("/v1/marketplace-collectors", "integration-ingestion"),
    ("/v1/source/", "integration-ingestion"),
    ("/v1/incident-webhooks", "integration-ingestion"),
    ("/v1/signing", "integrity-verification"),
    ("/v1/dsse-trust-roots", "integrity-verification"),
    ("/v1/merkle", "integrity-verification"),
    ("/v1/transparency", "integrity-verification"),
    ("/v1/public-transparency", "integrity-verification"),
    ("/v1/artifact-signatures", "integrity-verification"),
    ("/v1/provider-verifications", "integrity-verification"),
    ("/v1/backup-manifests", "integrity-verification"),
    ("/v1/audit-", "integrity-verification"),
    ("/v1/verify", "integrity-verification"),
    ("/v1/health", "platform-operations"),
    ("/v1/ready", "platform-operations"),
    ("/v1/metrics", "platform-operations"),
    ("/v1/version", "platform-operations"),
    ("/v1/openapi.json", "platform-operations"),
    ("/v1/deployments", "operations-incidents"),
    ("/v1/environments", "operations-incidents"),
    ("/v1/incidents", "operations-incidents"),
    ("/v1/saas/", "operations-incidents"),
    ("/v1/products", "release-ledger"),
    ("/v1/projects", "release-ledger"),
    ("/v1/releases", "release-ledger"),
    ("/v1/release-candidates", "release-ledger"),
    ("/v1/release-bundles", "release-ledger"),
    ("/v1/artifacts", "release-ledger"),
    ("/v1/container-images", "release-ledger"),
    ("/v1/builds", "release-ledger"),
    ("/v1/build-attestations", "release-ledger"),
    ("/v1/evidence", "release-ledger"),
    ("/v1/sboms", "release-ledger"),
    ("/v1/sbom-", "release-ledger"),
    ("/v1/vex", "release-ledger"),
    ("/v1/vulnerability", "release-ledger"),
    ("/v1/openapi-contracts", "release-ledger"),
    ("/v1/openapi-diffs", "release-ledger"),
    ("/v1/security-", "release-ledger"),
    ("/v1/api-security-scans", "release-ledger"),
    ("/v1/remediation-tasks", "release-ledger"),
    ("/v1/policies/evaluate", "release-ledger"),
    ("/v1/report-templates", "reporting"),
)


def schema_label(schema: Any) -> str:
    if not isinstance(schema, dict) or not schema:
        return "unspecified"
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref:
        return ref.rsplit("/", 1)[-1]
    typ = schema.get("type")
    if isinstance(typ, str) and typ:
        return typ
    return "any"


def schema_is_broad(schema: Any) -> bool:
    if not isinstance(schema, dict) or not schema:
        return True
    if schema.get("$ref") == "#/components/schemas/DataEnvelope":
        return True
    if schema.get("type") == "object" and schema.get("additionalProperties") is True:
        return True
    if schema.get("type") == "object" and not schema.get("properties") and "additionalProperties" not in schema:
        return True
    return False


def owner_for_path(path: str) -> str:
    for prefix, owner in OWNER_PREFIXES:
        if path.startswith(prefix):
            return owner
    return ""


def auth_for_operation(path: str, operation: dict[str, Any]) -> str:
    if operation.get("security"):
        return "bearer"
    if path.startswith("/v1/customer-portal/"):
        return "customer-portal-token"
    if path.startswith("/v1/incident-webhooks/"):
        return "webhook-signature"
    if path == "/v1/sso/session-exchanges":
        return "sso-credential"
    if path in {"/v1/health", "/v1/ready", "/v1/version", "/v1/openapi.json", "/v1/metrics"}:
        return "public"
    return ""


def response_schemas(operation: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for status, response in sorted((operation.get("responses") or {}).items()):
        if not isinstance(response, dict):
            continue
        labels = sorted(
            {
                schema_label(media.get("schema"))
                for media in (response.get("content") or {}).values()
                if isinstance(media, dict)
            }
        )
        result[str(status)] = labels
    return result


def request_schema(operation: dict[str, Any]) -> str:
    content = (operation.get("requestBody") or {}).get("content") or {}
    schema = (content.get("application/json") or {}).get("schema")
    return schema_label(schema) if schema is not None else "-"


def operation_rows(spec: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, path_item in sorted((spec.get("paths") or {}).items()):
        if not isinstance(path_item, dict):
            continue
        for method, operation in sorted(path_item.items()):
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            responses = response_schemas(operation)
            success_statuses = [status for status in responses if status.isdigit() and 200 <= int(status) < 300]
            error_statuses = [status for status in responses if status.isdigit() and int(status) >= 400]
            problem_statuses = [status for status in error_statuses if "Problem" in responses[status]]
            rows.append(
                {
                    "operation_id": str(operation.get("operationId") or ""),
                    "method": method.upper(),
                    "path": path,
                    "stability": str(operation.get("x-evydence-stability") or ""),
                    "owner": owner_for_path(path),
                    "auth": auth_for_operation(path, operation),
                    "scopes": sorted(str(scope) for scope in operation.get("x-scopes") or []),
                    "idempotency": bool((operation.get("x-idempotency-key") or {}).get("required")),
                    "request_schema": request_schema(operation),
                    "response_schemas": responses,
                    "success_statuses": success_statuses,
                    "error_statuses": error_statuses,
                    "problem_statuses": problem_statuses,
                }
            )
    return rows


def inventory_from_spec(spec: dict[str, Any]) -> dict[str, Any]:
    operations = operation_rows(spec)
    return {
        "source": "openapi.yaml",
        "operation_count": len(operations),
        "stability_counts": dict(sorted(Counter(row["stability"] for row in operations).items())),
        "owner_counts": dict(sorted(Counter(row["owner"] for row in operations).items())),
        "operations": operations,
    }


def validate_spec(spec: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    seen_ids: set[str] = set()
    for row in operation_rows(spec):
        label = f"{row['method']} {row['path']}"
        operation_id = row["operation_id"]
        if not operation_id:
            failures.append(f"{label}: missing operationId")
        elif operation_id in seen_ids:
            failures.append(f"{label}: duplicate operationId {operation_id}")
        else:
            seen_ids.add(operation_id)
        if row["stability"] not in STABILITY_CLASSES:
            failures.append(f"{label}: missing stability classification")
        if not row["owner"]:
            failures.append(f"{label}: missing owner")
        if not row["auth"] or (row["auth"] == "bearer" and not row["scopes"] and row["path"] != "/v1/sso/logout"):
            failures.append(f"{label}: missing auth/scopes contract")
        if not row["success_statuses"]:
            failures.append(f"{label}: missing documented success response")
        if any(not row["response_schemas"][status] or "unspecified" in row["response_schemas"][status] for status in row["success_statuses"]):
            failures.append(f"{label}: missing success response schema")
        if not row["error_statuses"] or not row["problem_statuses"]:
            failures.append(f"{label}: missing stable error response contract")
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            content = (operation.get("requestBody") or {}).get("content") or {}
            schema = (content.get("application/json") or {}).get("schema")
            if schema is not None and schema_is_broad(schema):
                failures.append(f"{method.upper()} {path}: broad request schema")
            for status, response in (operation.get("responses") or {}).items():
                if not isinstance(response, dict):
                    continue
                for media in (response.get("content") or {}).values():
                    if isinstance(media, dict) and schema_is_broad(media.get("schema")):
                        failures.append(f"{method.upper()} {path}: broad response schema for {status}")
    return failures


def candidate_action(operation: dict[str, Any]) -> str:
    if operation["owner"] == "platform-operations":
        return "review internal/admin exposure"
    if operation["owner"] == "reporting":
        return "review merge with report family"
    return "review experimental scope"


def markdown(inventory: dict[str, Any]) -> str:
    operations = inventory["operations"]
    stable_count = sum(1 for operation in operations if operation["stability"] == "core")
    experimental = [operation for operation in operations if operation["stability"] == "experimental"]
    lines = [
        "# Public API Inventory",
        "",
        "This generated reference is the complete operation-level inventory for the committed `openapi.yaml` contract. It is a compatibility-review aid, not a claim that every experimental operation is stable, production-ready, or covered by an SDK.",
        "",
        "## Review Summary",
        "",
        f"- Operations: `{inventory['operation_count']}`; every public operation is represented once.",
        f"- Candidate stable core: `{stable_count}` operations; review this count before any stable API promise.",
        "- Owners, auth modes, scopes, idempotency requirements, schemas, success statuses, and error status contracts are derived from OpenAPI route metadata.",
        "",
        "| Stability | Operations |",
        "| --- | ---: |",
    ]
    for stability, count in inventory["stability_counts"].items():
        lines.append(f"| `{stability}` | {count} |")
    lines.extend(
        [
            "",
            "## Complete Operation Inventory",
            "",
            "| Operation | Method | Path | Stability | Owner | Auth | Scopes | Idempotency | Request | Success | Error statuses |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for operation in operations:
        request = operation["request_schema"]
        success = ", ".join(
            f"{status}:{'/'.join(operation['response_schemas'][status])}" for status in operation["success_statuses"]
        )
        errors = ", ".join(operation["error_statuses"])
        lines.append(
            "| {operation_id} | {method} | `{path}` | `{stability}` | `{owner}` | `{auth}` | {scopes} | {idempotency} | {request} | {success} | {errors} |".format(
                operation_id=operation["operation_id"],
                method=operation["method"],
                path=operation["path"],
                stability=operation["stability"],
                owner=operation["owner"],
                auth=operation["auth"],
                scopes=", ".join(operation["scopes"]) or "-",
                idempotency="required" if operation["idempotency"] else "not required",
                request=request,
                success=success,
                errors=errors,
            )
        )
    lines.extend(
        [
            "",
            "## Candidate Review Queue",
            "",
            "Every `experimental` operation is an explicit candidate for a maintainer decision before a stable API promise: keep isolated as experimental, merge with an adjacent operation, deprecate with a replacement, or remove through the API evolution process. Platform/admin candidates are specifically flagged for internal-exposure review. This is a review queue, not a removal decision.",
            "",
            "| Operation | Owner | Candidate action |",
            "| --- | --- | --- |",
        ]
    )
    for operation in experimental:
        lines.append(f"| {operation['operation_id']} | `{operation['owner']}` | {candidate_action(operation)} |")
    lines.extend(
        [
            "",
            "## Generation And Validation",
            "",
            "Run `python3 scripts/api_inventory.py --write` after OpenAPI route metadata changes. Run `make api-inventory-check` in CI; it fails on duplicate operation IDs, missing stability or ownership, broad schemas, and incomplete success, error, or auth contracts.",
        ]
    )
    return "\n".join(lines) + "\n"


def load_spec() -> dict[str, Any]:
    try:
        value = json.loads(OPENAPI.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit("api-inventory: missing openapi.yaml")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"api-inventory: openapi.yaml is not valid JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("paths"), dict):
        raise SystemExit("api-inventory: openapi.yaml is missing paths")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write docs/reference/api-inventory.md")
    parser.add_argument("--check", action="store_true", help="validate OpenAPI and generated inventory drift")
    args = parser.parse_args(argv)
    if args.write and args.check:
        parser.error("--write and --check cannot be used together")
    spec = load_spec()
    failures = validate_spec(spec)
    if failures:
        print("api-inventory: contract validation failed:", file=sys.stderr)
        for failure in sorted(failures):
            print(f"- {failure}", file=sys.stderr)
        return 1
    rendered = markdown(inventory_from_spec(spec))
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        return 0
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print("api-inventory: docs/reference/api-inventory.md is out of date; run scripts/api_inventory.py --write", file=sys.stderr)
            return 1
        print(f"api-inventory-check: {len(inventory_from_spec(spec)['operations'])} operations validated")
        return 0
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
