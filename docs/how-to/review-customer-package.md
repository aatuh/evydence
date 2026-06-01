# Review A Customer Package

This how-to is for a customer reviewer or internal product-security reviewer
who received a scoped Evydence customer package. It uses the checked sample
fixture so the workflow can be tested without a running API or maintainer
access.

Evydence packages support technical evidence review and compliance readiness.
They are not legal compliance proof, certification, complete SBOM proof,
authoritative vulnerability results, regulator acceptance, or secure-release
guarantees.

## Inputs

Use the checked sample files:

```sh
examples/end-to-end-release-evidence/sample-customer-package-manifest.json
examples/end-to-end-release-evidence/sample-customer-package.zip
```

For a real review, use only package files received through an approved sharing
path. Portal package tokens are bearer secrets. Do not paste them into URLs,
public issues, logs, chat transcripts, or screenshots.

## Verify The Manifest Or Archive

Verify the manifest directly:

```sh
go run ./cmd/evydence package verify \
  --manifest examples/end-to-end-release-evidence/sample-customer-package-manifest.json \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example
```

Verify the ZIP archive and its embedded manifest/report metadata:

```sh
go run ./cmd/evydence package verify \
  --archive examples/end-to-end-release-evidence/sample-customer-package.zip \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example
```

Expected result: `customer package verified` with package, product, release,
manifest hash, and evidence-bundle status.

## Inspect The Package

Open the local viewer at `site/package-viewer/index.html`, then load
`examples/end-to-end-release-evidence/sample-customer-package-manifest.json`.
The viewer runs locally in the browser and does not upload files.

For ZIP packages, unpack the archive and open `report.html`. The static report
is generated from the redacted package manifest and local inline styles. It
does not require a running Evydence API.

When an Evydence API is running and the package owner issued a portal token,
open `/v1/customer-portal/package/view`. The portal page accepts tokens only in
form bodies, uses no-store cache headers, and reuses the same server-side
package scope, expiry, NDA, watermark, and audit controls as the JSON and ZIP
portal endpoints.

## Review Checklist

Confirm these sections before relying on the package for a customer or internal
review:

- package scope: package ID, product ID, release ID, expiry, and redaction
  profile;
- included evidence: artifact digests, SBOM metadata, vulnerability scan
  metadata, VEX or manual vulnerability decisions, release bundle, approvals,
  exceptions, and waivers when present;
- excluded evidence: anything omitted by the redaction profile or outside the
  package scope;
- verification material: manifest hash, release bundle hash, audit-chain
  summary, and verifier output;
- vulnerability answer: whether the relevant CVE is affected, fixed,
  not affected, or under investigation, plus customer-visible impact/action
  statements;
- gaps and limitations: missing evidence, stale evidence, assumptions, and
  explicit non-claims.

Escalate to the package owner when the package is expired, verification fails,
the relevant vulnerability or artifact is absent, the VEX/decision explanation
is incomplete, or the requested evidence is outside the redaction scope.

## Checked Workflow

Run the deterministic reviewer workflow check:

```sh
make reviewer-package-workflow-check
```

The check verifies the sample manifest checksum, runs the package verifier on
the manifest and archive, safely extracts the ZIP under `tmp/`, confirms
`report.html` contains verification and limitations sections, and fails if the
fixture exposes raw payload references, object-store keys, private-key markers,
portal-token hashes, internal notes, or script tags.
