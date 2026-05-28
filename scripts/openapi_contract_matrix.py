#!/usr/bin/env python3
"""Generate a deterministic public API contract precision matrix."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "openapi.yaml"


def schema_label(media: dict) -> str:
    schema = media.get("schema") or {}
    ref = schema.get("$ref")
    if ref:
        return ref.rsplit("/", 1)[-1]
    typ = schema.get("type")
    fmt = schema.get("format")
    if typ and fmt:
        return f"{typ}/{fmt}"
    if typ:
        return str(typ)
    return "generic"


def request_schema(operation: dict) -> str:
    body = operation.get("requestBody")
    if not body:
        return "-"
    content = body.get("content") or {}
    if not content:
        return "unspecified"
    return ", ".join(f"{kind}:{schema_label(media)}" for kind, media in sorted(content.items()))


def response_schemas(operation: dict) -> str:
    labels: list[str] = []
    for status, response in sorted((operation.get("responses") or {}).items()):
        if not status.startswith("2"):
            continue
        content = response.get("content") or {}
        if not content:
            labels.append(f"{status}:unspecified")
            continue
        labels.append(f"{status}:" + ",".join(f"{kind}:{schema_label(media)}" for kind, media in sorted(content.items())))
    return "<br>".join(labels) if labels else "-"


def parameter_names(operation: dict) -> str:
    params = operation.get("parameters") or []
    if not params:
        return "-"
    grouped = [f"{p.get('in', '?')}:{p.get('name', '?')}" for p in params]
    return ", ".join(grouped)


def auth_label(operation: dict) -> str:
    if "security" in operation and not operation.get("security"):
        return "public"
    if operation.get("security"):
        return "Bearer"
    return "public"


def idempotency_label(method: str, operation: dict) -> str:
    if method.lower() != "post":
        return "-"
    if auth_label(operation) == "public":
        return "not required"
    return "required"


def scopes_label(operation: dict) -> str:
    scopes = operation.get("x-scopes") or []
    return ", ".join(scopes) if scopes else "-"


def precision_label(operation: dict) -> str:
    request = request_schema(operation)
    response = response_schemas(operation)
    broad_tokens = ("DataEnvelope", "generic", "unspecified")
    if any(token in request or token in response for token in broad_tokens):
        return "broad"
    return "precise"


def esc(value: str) -> str:
    return value.replace("|", "\\|")


def main() -> int:
    spec = json.loads(OPENAPI.read_text())
    rows: list[tuple[str, str, str, str, str, str, str, str, str]] = []
    for path, path_item in sorted(spec["paths"].items()):
        for method, operation in sorted(path_item.items()):
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            rows.append(
                (
                    method.upper(),
                    path,
                    operation.get("operationId", "-"),
                    auth_label(operation),
                    scopes_label(operation),
                    idempotency_label(method, operation),
                    parameter_names(operation),
                    request_schema(operation),
                    response_schemas(operation),
                    precision_label(operation),
                )
            )

    precise = sum(1 for row in rows if row[-1] == "precise")
    broad = len(rows) - precise
    lines = [
        "# API Contract Matrix",
        "",
        "This generated reference inventories Evydence `/v1` route contract precision from `openapi.yaml`.",
        "It is a planning aid for production contract hardening; `broad` means the route still uses a shared envelope, unspecified body, or generic schema where an endpoint-specific contract should be considered.",
        "",
        f"Generated from {len(rows)} operations: {precise} precise, {broad} broad.",
        "",
        "| Method | Path | Operation | Auth | Scopes | Idempotency | Params | Request | 2xx Response | Precision |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(esc(value) for value in row) + " |")
    print("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
