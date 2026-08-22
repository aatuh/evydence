#!/usr/bin/env python3
"""Validate SDK helper and route-catalog coverage against committed OpenAPI."""

from __future__ import annotations

import json
import pathlib
import re
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


@dataclass(frozen=True)
class RequestFieldContract:
    operation_id: str
    schema_name: str
    go_type: str
    typescript_type: str
    handler_file: pathlib.Path
    handler_name: str


REQUEST_FIELD_CONTRACTS = (
    RequestFieldContract(
        "createRelease",
        "CreateReleaseRequest",
        "CreateReleaseRequest",
        "CreateReleaseRequest",
        ROOT / "internal/adapters/httpapi/router.go",
        "createRelease",
    ),
    RequestFieldContract(
        "registerArtifact",
        "RegisterArtifactRequest",
        "RegisterArtifactRequest",
        "RegisterArtifactRequest",
        ROOT / "internal/adapters/httpapi/router.go",
        "registerArtifact",
    ),
    RequestFieldContract(
        "createBuild",
        "CreateBuildRequest",
        "CreateBuildRequest",
        "CreateBuildRequest",
        ROOT / "internal/adapters/httpapi/router.go",
        "createBuild",
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


def properties_and_required(spec: dict, schema_name: str) -> tuple[set[str], set[str]]:
    try:
        schema = spec["components"]["schemas"][schema_name]
        properties = set(schema["properties"])
    except KeyError as exc:
        fail(f"missing schema contract for {schema_name}: {exc}")
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(field, str) for field in required):
        fail(f"schema {schema_name} has invalid required fields")
    return properties, set(required)


def go_request_fields(source: str, type_name: str) -> tuple[set[str], set[str]]:
    match = re.search(rf"(?ms)^type {re.escape(type_name)} struct \{{(?P<body>.*?)^\}}", source)
    if not match:
        fail(f"Go SDK missing request type {type_name}")
    fields: set[str] = set()
    required: set[str] = set()
    for json_name, options in re.findall(r'`json:"([^,"]+)([^\"]*)"`', match.group("body")):
        fields.add(json_name)
        if ",omitempty" not in options:
            required.add(json_name)
    return fields, required


def typescript_request_fields(source: str, type_name: str) -> tuple[set[str], set[str]]:
    match = re.search(rf"(?ms)^export type {re.escape(type_name)} = \{{(?P<body>.*?)^\}};", source)
    if not match:
        fail(f"TypeScript SDK missing request type {type_name}")
    fields: set[str] = set()
    required: set[str] = set()
    for name, optional in re.findall(r"(?m)^\s{2}([a-z][a-z0-9_]*)\s*(\?)?:", match.group("body")):
        fields.add(name)
        if optional != "?":
            required.add(name)
    return fields, required


def handler_request_fields(source: str, handler_name: str) -> set[str]:
    marker = f"func (s *Server) {handler_name}("
    start = source.find(marker)
    if start == -1:
        fail(f"handler missing {handler_name}")
    end = source.find("\nfunc ", start + len(marker))
    handler = source[start:] if end == -1 else source[start:end]
    match = re.search(r"(?ms)var req struct \{(?P<body>.*?)^\t\}", handler)
    if not match:
        fail(f"handler {handler_name} missing tagged request struct")
    return set(re.findall(r'`json:"([^,"]+)', match.group("body")))


def validate_request_field_contracts(spec: dict, go_client: str, typescript_client: str) -> list[str]:
    failures: list[str] = []
    for contract in REQUEST_FIELD_CONTRACTS:
        schema_fields, schema_required = properties_and_required(spec, contract.schema_name)
        go_fields, go_required = go_request_fields(go_client, contract.go_type)
        typescript_fields, typescript_required = typescript_request_fields(typescript_client, contract.typescript_type)
        handler_fields = handler_request_fields(contract.handler_file.read_text(encoding="utf-8"), contract.handler_name)
        for label, fields in (("Go SDK", go_fields), ("TypeScript SDK", typescript_fields), ("handler", handler_fields)):
            if fields != schema_fields:
                failures.append(
                    f"{contract.operation_id} {label} fields {sorted(fields)} do not match "
                    f"{contract.schema_name} fields {sorted(schema_fields)}"
                )
        for label, required in (("Go SDK", go_required), ("TypeScript SDK", typescript_required)):
            if required != schema_required:
                failures.append(
                    f"{contract.operation_id} {label} required fields {sorted(required)} do not match "
                    f"{contract.schema_name} required fields {sorted(schema_required)}"
                )
    return failures


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
    allowed_stability = {"core", "supported", "experimental", "deprecated"}
    for route in catalog.get("routes", []):
        if route.get("stability") not in allowed_stability:
            fail(f"SDK route catalog has invalid stability for {route.get('operation_id')!r}")
    for helper in REQUIRED_HELPERS:
        operation(spec, helper)

    go_client = (ROOT / "sdk/go/evydence/client.go").read_text(encoding="utf-8")
    typescript_client = (ROOT / "sdk/typescript/client.ts").read_text(encoding="utf-8")
    python_client = (ROOT / "sdk/python/evydence_client.py").read_text(encoding="utf-8")
    quickstarts = (ROOT / "docs/sdk/quickstarts.md").read_text(encoding="utf-8")

    for failure in validate_request_field_contracts(spec, go_client, typescript_client):
        fail(failure)

    for helper in REQUIRED_HELPERS:
        require_text(go_client, f"func (c Client) {helper.go_name}", "Go SDK")
        require_text(typescript_client, f"async {helper.typescript_name}", "TypeScript SDK")
        require_text(python_client, f"def {helper.python_name}", "Python SDK")

    require_text(go_client, "strings.HasPrefix(path, \"/v1/\")", "Go SDK path validation")
    require_text(typescript_client, "path.startsWith(\"/v1/\")", "TypeScript SDK path validation")
    require_text(python_client, "path.startswith(\"/v1/\")", "Python SDK path validation")

    for token in (
        "evydence.Client",
        "EvydenceClient",
        "create_product",
        "Idempotency-Key",
        "Problem Details",
        "IDEMPOTENCY_KEY_REUSED",
        "dist/evydence package verify",
        "not an SDK helper",
    ):
        require_text(quickstarts, token, "SDK quickstarts")

    print(
        f"sdk-check: validated {len(REQUIRED_HELPERS)} SDK helpers, {len(REQUEST_FIELD_CONTRACTS)} "
        f"field-level request contracts, and {catalog.get('route_count')} generated route catalog entries against openapi.yaml"
    )


if __name__ == "__main__":
    main()
