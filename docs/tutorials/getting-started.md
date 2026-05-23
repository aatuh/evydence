# Getting Started

This tutorial runs Evydence with in-process state and records a small release evidence flow. It is for local development only; data is lost when the process exits.

## Prerequisites

- Go with the version declared by `go.mod`.
- `curl` and `jq`.
- A free local port matching `EVYDENCE_ADDR` from `.api.env.example`, default `:8080`.

## Start The API

In terminal 1:

```sh
cp .api.env.example .api.env
unset EVYDENCE_DATABASE_URL
set -a; . ./.api.env; set +a
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true go run ./cmd/evydence-api
```

Expected result:

- The process prints a one-time JSON object containing `tenant_id`, `api_key`, and `secret`.
- The API listens on `http://localhost:8080` unless `EVYDENCE_ADDR` says otherwise.
- Because `EVYDENCE_DATABASE_URL` is unset, the tutorial uses in-process state.

In terminal 2, store the printed secret:

```sh
export EVYDENCE_URL=http://localhost:8080
export EVYDENCE_API_KEY='evy_replace_with_printed_secret'
```

Verify the process is reachable:

```sh
curl -sS "$EVYDENCE_URL/v1/ready" | jq .
```

Expected status is `200` with `data.status` set to `ok`.

## Create Core Release Records

Create a product:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/products" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-product" \
  -H "Content-Type: application/json" \
  --data '{"name":"Payments API","slug":"payments-api"}' \
  | tee /tmp/evydence-product.json | jq .

export PRODUCT_ID=$(jq -r '.data.id' /tmp/evydence-product.json)
```

Expected status is `201`. Reusing `tutorial-product` with the same body returns the original response; reusing it with different JSON returns `409`.

Create a project and release:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/projects" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-project" \
  -H "Content-Type: application/json" \
  --data "{\"product_id\":\"$PRODUCT_ID\",\"name\":\"api\"}" \
  | tee /tmp/evydence-project.json | jq .

export PROJECT_ID=$(jq -r '.data.id' /tmp/evydence-project.json)

curl -sS -X POST "$EVYDENCE_URL/v1/releases" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-release" \
  -H "Content-Type: application/json" \
  --data "{\"product_id\":\"$PRODUCT_ID\",\"version\":\"1.0.0\"}" \
  | tee /tmp/evydence-release.json | jq .

export RELEASE_ID=$(jq -r '.data.id' /tmp/evydence-release.json)
```

Both creates should return `201`.

## Upload Representative Evidence

Register an artifact:

```sh
export ARTIFACT_DIGEST=sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb

curl -sS -X POST "$EVYDENCE_URL/v1/artifacts" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-artifact" \
  -H "Content-Type: application/json" \
  --data "{\"name\":\"api.tar.gz\",\"media_type\":\"application/gzip\",\"digest\":\"$ARTIFACT_DIGEST\",\"size\":42}" \
  | tee /tmp/evydence-artifact.json | jq .

export ARTIFACT_ID=$(jq -r '.data.id' /tmp/evydence-artifact.json)
```

Upload a CycloneDX SBOM:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/sboms" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-sbom" \
  -H "Content-Type: application/json" \
  --data "{
    \"release_id\":\"$RELEASE_ID\",
    \"artifact_id\":\"$ARTIFACT_ID\",
    \"payload\":{
      \"bomFormat\":\"CycloneDX\",
      \"specVersion\":\"1.6\",
      \"components\":[{\"name\":\"openssl\",\"purl\":\"pkg:apk/openssl@3.1.0\"}]
    }
  }" | jq .
```

Upload a vulnerability scan with one open critical finding:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/vulnerability-scans" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-vuln-scan" \
  -H "Content-Type: application/json" \
  --data "{
    \"scanner\":\"grype\",
    \"target_ref\":\"pkg:oci/payments-api\",
    \"release_id\":\"$RELEASE_ID\",
    \"findings\":[{
      \"vulnerability\":\"CVE-2026-0099\",
      \"component\":\"pkg:apk/openssl@3.1.0\",
      \"severity\":\"critical\",
      \"state\":\"open\"
    }]
  }" | tee /tmp/evydence-scan.json | jq .

export FINDING_ID=$(jq -r '.data.findings[0].id' /tmp/evydence-scan.json)
```

Expected status is `201`. The scan organizes scanner evidence; it does not make the scanner authoritative.

Record a generic build evidence item:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/evidence" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-build-evidence" \
  -H "Content-Type: application/json" \
  --data "{
    \"product_id\":\"$PRODUCT_ID\",
    \"project_id\":\"$PROJECT_ID\",
    \"release_id\":\"$RELEASE_ID\",
    \"type\":\"build\",
    \"subtype\":\"log\",
    \"title\":\"Local tutorial build evidence\",
    \"payload_hash\":\"$ARTIFACT_DIGEST\",
    \"tags\":[\"tutorial\"],
    \"limitations\":[\"Local tutorial evidence is representative only.\"]
  }" | jq .
```

Expected status is `201`.

## Readiness And Review Output

Create a release bundle:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/release-bundles" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-release-bundle" \
  -H "Content-Type: application/json" \
  --data "{\"release_id\":\"$RELEASE_ID\"}" \
  | tee /tmp/evydence-bundle.json | jq .
```

Read release readiness:

```sh
curl -sS "$EVYDENCE_URL/v1/reports/release-readiness?release_id=$RELEASE_ID" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  | jq .
```

Expected status is `200`. In this minimal flow, `data.result` is expected to be `failed` because the release is missing some readiness inputs and has an unhandled open critical finding. The report should include checks, gaps, assumptions, limitations, and blocking findings.

Record a decision for the tutorial finding:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/vulnerability-findings/$FINDING_ID/decisions" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: tutorial-vuln-decision" \
  -H "Content-Type: application/json" \
  --data '{"status":"not_affected","justification":"tutorial example; vulnerable code path is not present"}' \
  | jq .
```

Expected status is `201`. Readiness may still report gaps until build provenance, attestation, signed bundle, and other required evidence are present.

Search the tutorial evidence:

```sh
curl -sS "$EVYDENCE_URL/v1/evidence/search?release_id=$RELEASE_ID&type=build&tag=tutorial&limit=10" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  | jq .
```

Expected status is `200` with the build evidence item under `data.items`.

## Cleanup

Stop the API process with `Ctrl-C`. For a durable local run, use PostgreSQL and object storage through [Install and operate](../how-to/install-and-operate.md) and [Configuration](../reference/configuration.md).

This tutorial demonstrates evidence capture and review output. It does not make legal compliance conclusions, grant certification, prove SBOM completeness, treat scanner output as authoritative, or guarantee release security.
