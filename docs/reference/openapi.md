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
- Critical routes such as evidence creation, evidence search, release bundle verification, SSO session creation, customer portal token exchange, and instance diagnostics have more precise request/response schemas.
- Many routes still use generic response envelopes while the human examples live in [API reference](../api.md) and HTTP tests.
- Do not hand-edit `openapi.yaml`; update route metadata or the generator, then run `make openapi-check`.

Route registration and OpenAPI generation use the same HTTP adapter registry so tests can catch missing routes or stale operation metadata.
