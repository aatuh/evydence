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
