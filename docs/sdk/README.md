# SDK Workflow

This is a reference for the lightweight SDK layout.

The committed SDK examples are curated wrappers around the OpenAPI-backed HTTP API:

- `sdk/go/evydence`
- `sdk/typescript/client.ts`
- `sdk/python/evydence_client.py`

They intentionally keep a small surface: authenticated JSON `POST` requests with explicit idempotency keys. Broader generated clients should be regenerated from the committed `openapi.yaml` and reviewed before release.

SDK drift checks currently rely on `make openapi-check`, `go test ./...`, and documentation review. Generated SDK publishing is a release process, not an API runtime dependency.
