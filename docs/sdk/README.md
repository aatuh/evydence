# SDK Workflow

This is a reference for the lightweight SDK wrappers committed in this repository.

## Current Scope

The wrappers provide authenticated JSON `POST` helpers with explicit idempotency keys:

- Go: `sdk/go/evydence`
- TypeScript: `sdk/typescript/client.ts`
- Python: `sdk/python/evydence_client.py`

They do not expose typed methods for every route. Broader generated clients should be regenerated from the committed `openapi.yaml`, reviewed, and released through a separate SDK publishing process.

## Go

```go
client := evydence.Client{
	BaseURL: "http://localhost:8080",
	APIKey:  os.Getenv("EVYDENCE_API_KEY"),
}

var out map[string]any
err := client.Post(
	context.Background(),
	"/v1/products",
	"product-payments-api",
	map[string]any{"name": "Payments API", "slug": "payments-api"},
	&out,
)
if err != nil {
	return err
}
```

The helper rejects paths that do not start with `/v1/` and blank idempotency keys. Non-2xx responses return an error containing the HTTP status code; callers that need Problem Details bodies should use a generated or custom client.

## TypeScript

```ts
const client = new EvydenceClient({
  baseUrl: "http://localhost:8080",
  apiKey: process.env.EVYDENCE_API_KEY!,
});

const response = await client.post<{ data: { id: string } }>(
  "/v1/products",
  "product-payments-api",
  { name: "Payments API", slug: "payments-api" },
);
```

The helper validates `/v1/` paths and idempotency keys. Non-2xx responses throw an error with the HTTP status code.

## Python

```python
from evydence_client import EvydenceClient

client = EvydenceClient(
    base_url="http://localhost:8080",
    api_key=os.environ["EVYDENCE_API_KEY"],
)

response = client.post(
    "/v1/products",
    "product-payments-api",
    {"name": "Payments API", "slug": "payments-api"},
)
```

The helper validates `/v1/` paths and idempotency keys. HTTP errors raise `RuntimeError` with the status code.

## Idempotency Guidance

Use stable, operation-specific idempotency keys for create and action requests:

```text
product-payments-api
release-payments-api-1.0.0
build-github-123456-1
```

Reusing the same key with the same request returns the original response. Reusing the key with different request content returns `409`.

## Drift Checks

SDK drift checks currently rely on:

```sh
make openapi-check
make test
make sdk-check
```

Generated SDK publishing is not an API runtime dependency. Keep generated clients tied to the committed `openapi.yaml` and document any route coverage gaps at release time.
