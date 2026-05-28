#!/usr/bin/env python3
"""Generate a deterministic SDK route catalog from committed OpenAPI."""

from __future__ import annotations

import json
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def success_statuses(operation: dict) -> list[str]:
    statuses: list[str] = []
    for status in sorted(operation.get("responses", {})):
        if status.isdigit() and 200 <= int(status) < 300:
            statuses.append(status)
    return statuses


def main() -> None:
    spec = json.loads((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
    routes: list[dict] = []
    for path, methods in sorted(spec.get("paths", {}).items()):
        for method, operation in sorted(methods.items()):
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            routes.append(
                {
                    "operation_id": operation.get("operationId", ""),
                    "method": method.upper(),
                    "path": path,
                    "scopes": operation.get("x-scopes", []),
                    "idempotency_key_required": bool(operation.get("x-idempotency-key", {}).get("required")),
                    "request_schema": operation.get("requestBody", {})
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                    .get("$ref", ""),
                    "success_statuses": success_statuses(operation),
                    "response_schemas": sorted(
                        {
                            media.get("schema", {}).get("$ref", "")
                            for response in operation.get("responses", {}).values()
                            for media in response.get("content", {}).values()
                            if media.get("schema", {}).get("$ref")
                        }
                    ),
                }
            )
    output = {
        "source": "openapi.yaml",
        "route_count": len(routes),
        "routes": routes,
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
