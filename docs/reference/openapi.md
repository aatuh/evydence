# OpenAPI Contract

The committed API contract is `openapi.yaml`. It is generated from the HTTP adapter route registry and route-contract metadata.

## Generate And Check

Generate the contract:

```sh
go run ./cmd/openapi > openapi.yaml
```

Check drift:

```sh
make openapi-check
```

`make openapi-check` regenerates the contract, compares it with the committed file, and runs route contract tests for the HTTP adapter.

Check precision regression:

```sh
make openapi-precision-check
```

`make openapi-precision-check` enforces endpoint-specific contracts for all
registered public routes and fails if any operation falls back to a broad
request or response shape.

`make docs-check` compares the paths in `openapi.yaml` with the endpoint catalog in [API reference](../api.md). Add every generated path to that catalog, or the docs check fails.

## Review The Contract

The committed file is compact. For human review, pretty-print it without editing the generated source:

```sh
jq . openapi.yaml > /tmp/evydence-openapi.pretty.json
jq '.paths | keys[]' openapi.yaml
jq '.components.schemas | keys[]' openapi.yaml
```

Inspect one operation:

```sh
jq '.paths["/v1/evidence"].post' openapi.yaml
```

The API also serves the generated contract at:

```http
GET /v1/openapi.json
```

## Current Limitations

- `openapi.yaml` is generated in a compact JSON-compatible representation.
- Registered public routes have endpoint-specific request and response schemas.
- New routes must update operation metadata, component schemas, `openapi.yaml`, and the generated [API contract matrix](api-contract-matrix.md).
- Do not hand-edit `openapi.yaml`; update route metadata or the generator, then run `make openapi-check`.

Route registration and OpenAPI generation use the same HTTP adapter registry so tests can catch missing routes or stale operation metadata.
