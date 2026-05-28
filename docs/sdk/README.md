# SDK Workflow

This is a reference for the lightweight SDK wrappers committed in this repository.

## Current Scope

The wrappers provide authenticated JSON helpers with explicit idempotency keys and small typed convenience helpers for the release-ledger and SSO/OIDC identity-provider routes:

- Go: `sdk/go/evydence`
- TypeScript: `sdk/typescript/client.ts`
- Python: `sdk/python/evydence_client.py`

They do not expose typed methods for every route. The current typed coverage is intentionally narrow: products, releases, artifacts, build runs, process readiness, release-readiness reports, SSO provider creation, and provider identity verification. Broader generated clients should be regenerated from the committed `openapi.yaml`, reviewed, and released through a separate SDK publishing process.

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
	err := client.CreateProduct(
		context.Background(),
		"product-payments-api",
		evydence.CreateProductRequest{Name: "Payments API", Slug: "payments-api"},
		&out,
	)
	if err != nil {
		return err
	}
	return nil
}
```

The helper rejects paths that do not start with `/v1/` and blank idempotency keys. Non-2xx responses return an error containing the HTTP status code; callers that need Problem Details bodies should use a generated or custom client.

The Go wrapper also exposes typed helpers for `CreateRelease`, `RegisterArtifact`, `CreateBuild`, `Readiness`, `ReleaseReadiness`, `CreateSSOProvider`, and `VerifyProviderIdentity`. `VerifyProviderIdentity` can carry an OIDC `id_token` or SAML `saml_assertion`; SDK errors intentionally include only the HTTP status code and not the response body.

## TypeScript

Import the source wrapper directly from the checkout or from your application-owned package copy. The wrapper uses `fetch`; Node.js 18+ provides it globally, and older runtimes should pass `fetchImpl`.

```ts
import { EvydenceClient } from "./sdk/typescript/client";

const client = new EvydenceClient({
  baseUrl: "http://localhost:8080",
  apiKey: process.env.EVYDENCE_API_KEY!,
});

const response = await client.createProduct<{ data: { id: string } }>(
  "product-payments-api",
  { name: "Payments API", slug: "payments-api" },
);
```

The helper validates `/v1/` paths and idempotency keys. Non-2xx responses throw an error with the HTTP status code.

The TypeScript wrapper also exposes `createRelease`, `registerArtifact`, `createBuild`, `readiness`, `releaseReadiness`, `createSSOProvider`, and `verifyProviderIdentity` helpers over the same routes.

## Python

Put `sdk/python` on `PYTHONPATH`, install the copied module in your application package, or run the example from that directory:

```python
import os

from evydence_client import EvydenceClient

client = EvydenceClient(
    base_url="http://localhost:8080",
    api_key=os.environ["EVYDENCE_API_KEY"],
)

response = client.create_product(
    "product-payments-api",
    {"name": "Payments API", "slug": "payments-api"},
)
```

The helper validates `/v1/` paths and idempotency keys. HTTP errors raise `RuntimeError` with the status code.

The Python wrapper also exposes `create_release`, `register_artifact`, `create_build`, `readiness`, `release_readiness`, `create_sso_provider`, and `verify_provider_identity` helpers over the same routes.

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

`make sdk-check` runs `scripts/sdk_check.py`, which verifies that the curated helper methods still map to committed OpenAPI operations, idempotent routes still require `Idempotency-Key`, and SDKs keep basic `/v1/` path validation. Generated SDK publishing is not an API runtime dependency. Keep generated clients tied to the committed `openapi.yaml` and document any route coverage gaps at release time.
