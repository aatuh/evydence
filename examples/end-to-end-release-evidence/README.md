# End-To-End Release Evidence Example

This example shows the VEX-first product path Evydence should make easy to
evaluate:

1. Create a product, release, and artifact.
2. Upload SBOM evidence for the artifact.
3. Upload vulnerability scan evidence for the release.
4. Record a VEX-style decision or approved exception for a blocking finding.
5. Generate a release-readiness report.
6. Create a signed release bundle and customer-safe package or evidence bundle.
7. View the package locally and verify the bundle, package manifest, and audit
   chain.

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
- `sample-customer-package.zip`: downloadable fixture with `manifest.json`,
  `package.json`, `verification.json`, and `README.txt`.
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

## Inspect The Result

The generated files under `tmp/end-to-end-release-evidence/` map the buyer
question to concrete Evydence records:

- `sbom.json`: which SBOM was used for the release answer.
- `vulnerability-scan.json`: which scanner result raised the finding.
- `vulnerability-decision.json`: why the finding is treated as not affected in
  this demo.
- `release-readiness.json`: the readiness result, gaps, assumptions, and
  limitations.
- `release-bundle.json`: the signed release bundle metadata.
- `customer-package.json`: the customer-safe package manifest.
- `audit-chain-verification.json`: audit-chain continuity verification.

To visually inspect the customer-safe output, open
`site/package-viewer/index.html` and load `customer-package.json` from the demo
output directory. To verify the package manifest offline, run:

```sh
go run ./cmd/evydence package verify \
  --manifest tmp/end-to-end-release-evidence/customer-package.json
```

To inspect the checked sample without running the API, open
`sample-customer-package-manifest.json` in the viewer or verify the downloadable
fixture:

```sh
go run ./cmd/evydence package verify \
  --archive examples/end-to-end-release-evidence/sample-customer-package.zip \
  --expected-package-id csp_example
```

To verify the release bundle through the API, read the bundle id from
`release-bundle.json` and call:

```sh
bundle_id="$(jq -r '.data.id' tmp/end-to-end-release-evidence/release-bundle.json)"
curl -fsS \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  "$EVYDENCE_URL/v1/release-bundles/${bundle_id}/verify"
```

Expected result: the API returns verification checks for the tenant-scoped
bundle. The demo output remains review evidence with explicit limitations; it
is not legal compliance proof, certification, complete SBOM proof, an
authoritative scanner result, or a secure-release guarantee.
