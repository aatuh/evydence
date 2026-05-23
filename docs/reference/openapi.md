# OpenAPI Contract

The committed API contract is `openapi.yaml`.

Generate it with:

```sh
go run ./cmd/openapi > openapi.yaml
```

Check drift with:

```sh
make openapi-check
```

The API also serves the generated contract at `/v1/openapi.json`. Route registration and OpenAPI generation use the same HTTP adapter registry so tests can catch missing routes or stale operation metadata.
