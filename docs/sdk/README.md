# SDK Workflow

This is a reference for the lightweight SDK wrappers committed in this repository.

## Current Scope

The wrappers provide authenticated JSON `POST` helpers with explicit idempotency keys and small typed convenience helpers for the SSO/OIDC identity-provider routes:

- Go: `sdk/go/evydence`
- TypeScript: `sdk/typescript/client.ts`
- Python: `sdk/python/evydence_client.py`

They do not expose typed methods for every route. Broader generated clients should be regenerated from the committed `openapi.yaml`, reviewed, and released through a separate SDK publishing process.

No package publishing manifests are committed for these wrappers yet. Use them as in-repository examples or copy them into an application-owned SDK package until a release process publishes versioned SDK artifacts.

## Go

Import the wrapper from this module path when your code is in this repository or uses a local `replace` to this checkout:

```go
package main

import (
	"context"
	"os"

	"github.com/aatuh/evydence/sdk/go/evydence"
)

func createProduct() error {
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
return nil
}
```

The helper rejects paths that do not start with `/v1/` and blank idempotency keys. Non-2xx responses return an error containing the HTTP status code; callers that need Problem Details bodies should use a generated or custom client.

The Go wrapper also exposes `CreateSSOProvider` and `VerifyProviderIdentity` helpers. `VerifyProviderIdentity` can carry an OIDC `id_token`; SDK errors intentionally include only the HTTP status code and not the response body.

## TypeScript

Import the source wrapper directly from the checkout or from your application-owned package copy. The wrapper uses `fetch`; Node.js 18+ provides it globally, and older runtimes should pass `fetchImpl`.

```ts
import { EvydenceClient } from "./sdk/typescript/client";

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

The TypeScript wrapper also exposes `createSSOProvider` and `verifyProviderIdentity` helpers over the same routes.

## Python

Put `sdk/python` on `PYTHONPATH`, install the copied module in your application package, or run the example from that directory:

```python
import os

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

The Python wrapper also exposes `create_sso_provider` and `verify_provider_identity` helpers over the same routes.

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
