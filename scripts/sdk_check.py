#!/usr/bin/env python3
"""Validate SDK helper and route-catalog coverage against committed OpenAPI."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class RequiredHelper:
    operation_id: str
    method: str
    path: str
    go_name: str
    typescript_name: str
    python_name: str
    idempotent: bool


REQUIRED_HELPERS = (
    RequiredHelper("createProduct", "post", "/v1/products", "CreateProduct", "createProduct", "create_product", True),
    RequiredHelper("createRelease", "post", "/v1/releases", "CreateRelease", "createRelease", "create_release", True),
    RequiredHelper(
        "registerArtifact",
        "post",
        "/v1/artifacts",
        "RegisterArtifact",
        "registerArtifact",
        "register_artifact",
        True,
    ),
    RequiredHelper("createBuild", "post", "/v1/builds", "CreateBuild", "createBuild", "create_build", True),
    RequiredHelper("ready", "get", "/v1/ready", "Readiness", "readiness", "readiness", False),
    RequiredHelper(
        "releaseReadinessReport",
        "get",
        "/v1/reports/release-readiness",
        "ReleaseReadiness",
        "releaseReadiness",
        "release_readiness",
        False,
    ),
    RequiredHelper(
        "createSSOProvider",
        "post",
        "/v1/sso/providers",
        "CreateSSOProvider",
        "createSSOProvider",
        "create_sso_provider",
        True,
    ),
    RequiredHelper(
        "verifyProviderIdentity",
        "post",
        "/v1/provider-verifications",
        "VerifyProviderIdentity",
        "verifyProviderIdentity",
        "verify_provider_identity",
        True,
    ),
)


def fail(message: str) -> None:
    print(f"sdk-check: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_openapi() -> dict:
    try:
        return json.loads((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail("missing openapi.yaml")
    except json.JSONDecodeError as exc:
        fail(f"openapi.yaml is not parseable JSON: {exc}")


def operation(spec: dict, helper: RequiredHelper) -> dict:
    try:
        op = spec["paths"][helper.path][helper.method]
    except KeyError as exc:
        fail(f"missing OpenAPI operation for {helper.method.upper()} {helper.path}: {exc}")
    if op.get("operationId") != helper.operation_id:
        fail(
            f"{helper.method.upper()} {helper.path} operationId is {op.get('operationId')!r}, "
            f"expected {helper.operation_id!r}"
        )
    if helper.idempotent and not op.get("x-idempotency-key", {}).get("required"):
        fail(f"{helper.operation_id} must require Idempotency-Key in OpenAPI")
    if helper.idempotent and not op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema"):
        fail(f"{helper.operation_id} must declare an application/json request schema")
    if "200" not in op.get("responses", {}) and "201" not in op.get("responses", {}):
        fail(f"{helper.operation_id} must declare a success response")
    return op


def require_text(source: str, token: str, label: str) -> None:
    if token not in source:
        fail(f"{label} missing {token!r}")


def main() -> None:
    spec = load_openapi()
    catalog_path = ROOT / "sdk" / "openapi-route-catalog.json"
    if not catalog_path.exists():
        fail("missing sdk/openapi-route-catalog.json")
    generated_catalog = subprocess.check_output(
        [sys.executable, str(ROOT / "scripts" / "generate_sdk_route_catalog.py")],
        text=True,
    )
    committed_catalog = catalog_path.read_text(encoding="utf-8")
    if json.loads(generated_catalog) != json.loads(committed_catalog):
        fail("sdk/openapi-route-catalog.json is out of date; run scripts/generate_sdk_route_catalog.py")
    catalog = json.loads(committed_catalog)
    if catalog.get("route_count") != len(
        [
            None
            for path_item in spec.get("paths", {}).values()
            for method in path_item
            if method.lower() in {"get", "post", "put", "patch", "delete"}
        ]
    ):
        fail("SDK route catalog route_count does not match openapi.yaml")
    for helper in REQUIRED_HELPERS:
        operation(spec, helper)

    go_client = (ROOT / "sdk/go/evydence/client.go").read_text(encoding="utf-8")
    typescript_client = (ROOT / "sdk/typescript/client.ts").read_text(encoding="utf-8")
    python_client = (ROOT / "sdk/python/evydence_client.py").read_text(encoding="utf-8")

    for helper in REQUIRED_HELPERS:
        require_text(go_client, f"func (c Client) {helper.go_name}", "Go SDK")
        require_text(typescript_client, f"async {helper.typescript_name}", "TypeScript SDK")
        require_text(python_client, f"def {helper.python_name}", "Python SDK")

    require_text(go_client, "strings.HasPrefix(path, \"/v1/\")", "Go SDK path validation")
    require_text(typescript_client, "path.startsWith(\"/v1/\")", "TypeScript SDK path validation")
    require_text(python_client, "path.startswith(\"/v1/\")", "Python SDK path validation")

    print(
        f"sdk-check: validated {len(REQUIRED_HELPERS)} SDK helpers and "
        f"{catalog.get('route_count')} generated route catalog entries against openapi.yaml"
    )


if __name__ == "__main__":
    main()
