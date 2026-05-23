# API Reference

The public API base path is `/v1`.

Common headers:

```http
Authorization: Bearer <api_key>
Idempotency-Key: <stable-create-key>
Content-Type: application/json
Accept: application/json
```

Create and action endpoints require `Idempotency-Key`. Reusing the same key with the same request returns the original response. Reusing it with different request content returns `409` with `IDEMPOTENCY_KEY_REUSED`.

Errors use RFC 9457 Problem Details and include a stable `code` field.

The generated OpenAPI document is committed at `openapi.yaml` and served at `/v1/openapi.json`.

## CI Provenance

Collectors are tenant-scoped automated ingesters. `POST /v1/collectors` creates a `github_actions` collector and returns a one-time API key secret scoped for build/evidence upload. `GET /v1/collectors` lists collectors without key hashes or secrets. The server binds collector identity from the API key; clients must not submit `collector_id` for build attribution.

`POST /v1/builds` records an immutable build run. For `provider=github_actions`, the request must include `project_id`, `release_id`, `commit_sha`, `status`, `started_at`, `repository`, `workflow_ref`, `run_id`, and `run_attempt`. Supported statuses are `queued`, `running`, `passed`, `failed`, and `cancelled`. `GET /v1/builds/{id}` requires `build:read`.

`POST /v1/builds/{id}/attestations` accepts raw DSSE JSON containing `payloadType`, base64 `payload`, and `signatures`. Evydence decodes the in-toto Statement, records subjects, predicate type, SLSA builder/build metadata when present, stores raw bytes as tenant-prefixed evidence, and marks the record structurally valid. This slice does not perform cryptographic trust-root verification.

## Release Risk Decisions

OpenVEX ingestion is available at `POST /v1/vex` with a request body containing `release_id`, optional `artifact_id`, and `payload`. The payload must be OpenVEX JSON with author, timestamp, and one or more statements. Raw VEX bytes are stored as tenant-prefixed object payloads and represented as immutable `vex` evidence.

Vulnerability findings from `POST /v1/vulnerability-scans` can be resolved with `POST /v1/vulnerability-findings/{id}/decisions`. Supported statuses are `affected`, `not_affected`, `fixed`, and `under_investigation`. New decisions supersede earlier decisions for the same finding.

Scoped exceptions are created with `POST /v1/exceptions` and approved separately with `POST /v1/exceptions/{id}/approve`. Only approved, unexpired exceptions can affect release readiness.

`GET /v1/reports/release-readiness?release_id=...` returns deterministic readiness JSON with checks, blocking findings, accepted exceptions, gaps, assumptions, and limitations. Readiness requires SBOM, vulnerability scan, artifact digest evidence, signed bundle, passed build provenance, build attestation subject matching a release artifact digest, and no unhandled open critical finding. It supports compliance readiness only and is not a legal compliance or secure-release conclusion.
