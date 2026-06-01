# Evaluate Evydence In 10 Minutes

This walkthrough is for a product-security, AppSec, platform, or customer
reviewer who wants to understand the VEX-first release-evidence path without
running a full production deployment.

The question to answer is:

> This CVE appears in your SBOM. Are you affected, why, who approved it, and
> what can I verify?

Evydence answers that question by linking release, artifact, SBOM,
vulnerability scan, VEX or manual decision, approval or exception, readiness,
bundle, package, and audit-chain evidence. The checked fixtures are
non-sensitive examples. They are not legal compliance proof, certification,
complete SBOM proof, authoritative vulnerability results, or a secure-release
guarantee.

## 1. Verify The Public Release Candidate

Start by verifying the release artifacts you would install or evaluate:

```sh
make public-release-verify TAG=v0.1.0-rc.5
```

This downloads the public release-candidate evidence and checks the release
archives, OpenAPI checksum, migration checksum, in-toto provenance statement
shape, and signed release manifest. The release evidence index explains every
artifact in the set:

- [Release evidence index](../reference/release-evidence-index.md)
- [Release candidate checklist](../reference/release-candidate.md)

## 2. Open The Sample Customer Package

Open the local package viewer:

```sh
xdg-open site/package-viewer/index.html
```

If `xdg-open` is not available, open `site/package-viewer/index.html` directly
from your browser.

In the viewer, press **Load bundled demo** or load this checked fixture:

```text
examples/end-to-end-release-evidence/sample-customer-package-manifest.json
```

The sample package is also available as a ZIP archive:

```text
examples/end-to-end-release-evidence/sample-customer-package.zip
```

Use the viewer to inspect:

- release scope, package scope, and limitations;
- included artifact, SBOM, scan, VEX, decision, approval, and bundle metadata;
- the vulnerability decision that explains why the sample finding is not
  treated as an unresolved blocker;
- verification status and audit-chain evidence;
- explicitly excluded raw payload bytes, secrets, hashes, and internal notes.

The package viewer guide has the same path with screenshots and offline
verification commands:

- [View packages locally](../how-to/view-packages.md)

## 3. Verify The Sample Package

Verify the checked package fixture without running the API:

```sh
go run ./cmd/evydence package verify \
  --archive examples/end-to-end-release-evidence/sample-customer-package.zip \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example
```

Expected result: the command exits successfully and validates the package
manifest, archive metadata, and expected scope identifiers. It verifies the
example package bytes; it does not verify facts outside the sample data.

## 4. Read The Evidence Path

Use the end-to-end example as the shortest map from the reviewer question to
concrete API outputs:

- [End-to-end release evidence example](../../examples/end-to-end-release-evidence/README.md)
- [Sample readiness report](../../examples/end-to-end-release-evidence/sample-readiness-report.json)
- [Sample security summary](../../examples/end-to-end-release-evidence/sample-security-summary.json)
- [Sample audit-chain verification](../../examples/end-to-end-release-evidence/sample-audit-chain-verification.json)

The key files are:

| Reviewer question | Example file |
| --- | --- |
| Which SBOM did you use? | `sample-customer-package-manifest.json` and `sample-readiness-report.json` |
| Which scanner raised the finding? | `sample-security-summary.json` |
| Are you affected and why? | `sample-customer-package-manifest.json` vulnerability decision section |
| Who recorded or approved the answer? | package approvals and audit-chain fixture |
| What can I verify offline? | package archive, package manifest, bundle metadata, and audit-chain fixture |
| What is missing or limited? | readiness report gaps, assumptions, limitations, and non-claims |

## 5. Run The Local API Demo When Ready

After the static review path makes sense, run the API-backed demo:

```sh
EVYDENCE_URL=http://localhost:8080 \
EVYDENCE_API_KEY='evy_replace_with_scoped_secret' \
examples/end-to-end-release-evidence/run-local-demo.sh
```

The demo creates a product, release, artifact, SBOM, vulnerability scan,
vulnerability decision, release bundle, redaction profile, customer package,
readiness report, security summary, and audit-chain verification output under
`tmp/end-to-end-release-evidence/`.

For a step-by-step local API setup, use:

- [Getting started](getting-started.md)
- [Install and operate](../how-to/install-and-operate.md)

## What This Evaluation Should Show

After these steps, a reviewer should be able to trace one vulnerability answer
from SBOM and scanner evidence through a VEX or manual decision into a
customer-safe package and verification commands.

This supports compliance readiness and technical evidence organization. It
does not replace human review, legal analysis, scanner validation, provider
controls, or customer-specific disclosure decisions.
