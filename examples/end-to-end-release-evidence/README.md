# End-To-End Release Evidence Example

This example shows the product path Evydence should make easy to evaluate:

1. CI builds an artifact and computes a digest.
2. CI uploads build provenance, SBOM, and vulnerability scan evidence.
3. Security records a VEX decision or approved exception for a blocking
   finding.
4. Evydence creates a release bundle and readiness report.
5. Evydence exports customer-safe review evidence.

The files in this directory are non-sensitive fixtures. They are not legal
compliance proof, certification, complete SBOM proof, authoritative
vulnerability results, or a secure-release guarantee.

## Start With Release Verification

Before running a local API flow, verify the current public release-candidate
assets from a clean temporary directory:

```sh
make public-release-verify TAG=v0.1.0-rc.4
```

This proves the downloaded public archives, OpenAPI checksum, migration
checksum, in-toto provenance statement shape, and signed release manifest before
you use source-checkout commands for local development.

## Files

- `release-evidence-manifest.json`: example CLI bulk-upload manifest.
- `sample-readiness-report.json`: representative readiness output with gaps and
  limitations.
- `sample-customer-package-manifest.json`: representative customer package
  manifest without raw tenant payload bytes.
- `sample-audit-chain-verification.json`: representative audit-chain
  verification result.

## Run Against A Local API

Start Evydence with the getting-started tutorial or the production-like Compose
stack, then set:

```sh
export EVYDENCE_URL=http://localhost:8080
export EVYDENCE_API_KEY='evy_replace_with_scoped_secret'
```

Upload the manifest with the local CLI:

```sh
go run ./cmd/evydence upload manifest \
  --api-url "$EVYDENCE_URL" \
  --api-key "$EVYDENCE_API_KEY" \
  --manifest examples/end-to-end-release-evidence/release-evidence-manifest.json
```

The manifest uses placeholder IDs. Replace `prod_example`, `proj_example`,
`rel_example`, and `art_example` with IDs created in your local tenant before
running it.

For a complete local API flow that creates the IDs for you and writes example
outputs under `tmp/end-to-end-release-evidence/`, run:

```sh
EVYDENCE_URL=http://localhost:8080 \
EVYDENCE_API_KEY='evy_replace_with_scoped_secret' \
examples/end-to-end-release-evidence/run-local-demo.sh
```

The script creates a product, release, artifact, SBOM, vulnerability scan,
vulnerability decision, release bundle, redaction profile, customer package,
readiness report, and audit-chain verification output. It expects a local API
that already has a tenant and scoped API key.
