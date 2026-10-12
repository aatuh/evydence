# SDK Quickstarts

These quickstarts show the current in-repository SDK wrappers for a small
create/read flow. They are intentionally narrow: the wrappers help with
authenticated JSON requests, `/v1/` path checks, and explicit idempotency keys.
They are not published language packages yet and do not verify ZIP package
archives or signatures.

Use placeholders for credentials:

```sh
export EVYDENCE_URL=http://localhost:8080
export EVYDENCE_API_KEY=evy_test_or_live_key_from_your_tenant
```

Do not paste real API keys, bearer tokens, private keys, raw evidence payloads,
customer package contents, database URLs, or provider credentials into source
files, screenshots, public issues, or support requests.

## Go

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aatuh/evydence/sdk/go/evydence"
)

func main() {
	ctx := context.Background()
	client := evydence.Client{
		BaseURL: os.Getenv("EVYDENCE_URL"),
		APIKey:  os.Getenv("EVYDENCE_API_KEY"),
	}

	var product map[string]any
	if err := client.CreateProduct(ctx, "quickstart-go-product-v1", evydence.CreateProductRequest{
		Name: "Quickstart API",
		Slug: "quickstart-api",
	}, &product); err != nil {
		panic(err)
	}

	productID := product["data"].(map[string]any)["id"].(string)
	var release map[string]any
	if err := client.CreateRelease(ctx, "quickstart-go-release-v1", evydence.CreateReleaseRequest{
		ProductID: productID,
		Version:   "1.0.0",
	}, &release); err != nil {
		panic(err)
	}

	releaseID := release["data"].(map[string]any)["id"].(string)
	var readiness map[string]any
	if err := client.ReleaseReadiness(ctx, releaseID, &readiness); err != nil {
		panic(err)
	}
	fmt.Println(readiness["data"])
}
```

The Go wrapper returns a typed `*evydence.ProblemError` for non-2xx API
responses. Switch on the generated `Problem.Code` instead of parsing an error
message:

```go
var problem *evydence.ProblemError
if errors.As(err, &problem) {
	switch problem.Problem.Code {
	case evydence.ErrorCodeRateLimited:
		// respect problem.Problem.RetryAfterSeconds
	case evydence.ErrorCodeValidationFailed:
		// inspect safe problem.Problem.Violations
	}
}
```

## TypeScript

```ts
import { EvydenceClient, EvydenceProblemError } from "../../sdk/typescript/client";

const client = new EvydenceClient({
  baseUrl: process.env.EVYDENCE_URL ?? "http://localhost:8080",
  apiKey: process.env.EVYDENCE_API_KEY ?? "",
});

const product = await client.createProduct<{ data: { id: string } }>(
  "quickstart-typescript-product-v1",
  { name: "Quickstart API", slug: "quickstart-api" },
);

const release = await client.createRelease<{ data: { id: string } }>(
  "quickstart-typescript-release-v1",
  { product_id: product.data.id, version: "1.0.0" },
);

const readiness = await client.releaseReadiness<{ data: unknown }>(release.data.id);
console.log(readiness.data);
```

The TypeScript wrapper rejects with `EvydenceProblemError`, whose `problem`
field has generated error-code and retry-class unions:

```ts
try {
  await client.createProduct("quickstart-typescript-product-v1", { name: "Quickstart API", slug: "quickstart-api" });
} catch (error) {
  if (error instanceof EvydenceProblemError && error.problem.code === "RATE_LIMITED") {
    // respect error.problem.retry_after_seconds
  }
}
```

## Python

```python
import os

from error_codes import ErrorCode
from evydence_client import EvydenceClient, EvydenceProblemError


client = EvydenceClient(
    base_url=os.environ.get("EVYDENCE_URL", "http://localhost:8080"),
    api_key=os.environ["EVYDENCE_API_KEY"],
)

product = client.create_product(
    "quickstart-python-product-v1",
    {"name": "Quickstart API", "slug": "quickstart-api"},
)
release = client.create_release(
    "quickstart-python-release-v1",
    {"product_id": product["data"]["id"], "version": "1.0.0"},
)
print(client.release_readiness(release["data"]["id"])["data"])
```

The Python wrapper raises `EvydenceProblemError` with a generated `ErrorCode`
enum and safe Problem Details fields:

```python
try:
    client.create_product("quickstart-python-product-v1", {"name": "Quickstart API", "slug": "quickstart-api"})
except EvydenceProblemError as error:
    if error.problem.code is ErrorCode.RATE_LIMITED:
        # respect error.problem.retry_after_seconds
        pass
```

## Idempotency

Every create/action request in these examples uses an `Idempotency-Key`.
Choose a stable key per operation and tenant, for example:

```text
quickstart-go-product-v1
quickstart-typescript-release-v1
quickstart-python-package-v1
```

Reusing the same key with the same request replays the original response.
Reusing the same key with changed content returns `409` with the
`IDEMPOTENCY_KEY_REUSED` Problem Details code.

## Package Verification

Customer package ZIP verification is currently an offline CLI verifier task,
not an SDK helper. Use SDK or generated-client calls to create and download a
package, then verify the archive with the CLI:

```sh
dist/evydence package verify \
  --archive customer-package.zip \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example
```

The verifier checks the package manifest shape, manifest hash, package identity,
expected product/release IDs when supplied, prohibited sensitive fields, archive
metadata, and evidence-bundle coverage when a bundle is included. It does not
make legal compliance conclusions, certify the release, prove SBOM completeness,
or treat scanner results as authoritative.

## Limitations

- Current wrappers are source files in this repository, not published package
  artifacts.
- Typed helper coverage is intentionally narrow. Use
  [`sdk/openapi-route-catalog.json`](../../sdk/openapi-route-catalog.json) and
  [`openapi.yaml`](../../openapi.yaml) for generated clients that need all
  routes.
- Wrapper error values expose only typed, documented Problem Details fields;
  they never include arbitrary response bodies.
- Binary downloads, package archive verification, evidence bundle verification,
  and release manifest verification remain CLI/offline-verifier workflows.
