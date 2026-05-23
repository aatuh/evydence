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

## Release Risk Decisions

OpenVEX ingestion is available at `POST /v1/vex` with a request body containing `release_id`, optional `artifact_id`, and `payload`. The payload must be OpenVEX JSON with author, timestamp, and one or more statements. Raw VEX bytes are stored as tenant-prefixed object payloads and represented as immutable `vex` evidence.

Vulnerability findings from `POST /v1/vulnerability-scans` can be resolved with `POST /v1/vulnerability-findings/{id}/decisions`. Supported statuses are `affected`, `not_affected`, `fixed`, and `under_investigation`. New decisions supersede earlier decisions for the same finding.

Scoped exceptions are created with `POST /v1/exceptions` and approved separately with `POST /v1/exceptions/{id}/approve`. Only approved, unexpired exceptions can affect release readiness.

`GET /v1/reports/release-readiness?release_id=...` returns deterministic readiness JSON with checks, blocking findings, accepted exceptions, gaps, assumptions, and limitations. It supports compliance readiness only and is not a legal compliance or secure-release conclusion.
