# End-To-End GitHub Actions Release Evidence Guide

This guide shows the checked GitHub Actions path for recording one release's
build, SBOM, scanner, bundle, optional customer package, and readiness evidence.
It is a how-to for wiring CI to Evydence; it is not a claim that GitHub metadata,
scanner output, SBOM content, or the resulting release is complete or secure.

Use the workflow template at
[`docs/github-actions/release-evidence-workflow.yml`](release-evidence-workflow.yml)
after reviewing the assumptions below.

## Supported Flow

The workflow performs these phases:

1. Check out source and build the artifact.
2. Compute the artifact digest with `dist/evydence hash`.
3. Upload GitHub Actions build metadata with `dist/evydence github-actions upload-build`.
4. Generate CycloneDX SBOM and scanner JSON with Syft, Grype, and Trivy.
5. Build an Evydence upload manifest with `scripts/github_release_evidence_manifest.py`.
6. Run `dist/evydence ci preflight` to validate URL, key scopes, tenant-scoped IDs, and manifest shape.
7. Upload SBOM, scanner, release bundle, and optional customer package requests with `dist/evydence upload manifest`.
8. Read `/v1/reports/release-readiness` into `.evydence/release-readiness.json`.
9. Upload `.evydence/` as a GitHub Actions artifact for operator review.

The workflow does not call the live GitHub API. It records GitHub Actions
environment metadata submitted by the runner, such as repository, workflow ref,
run ID, run attempt, ref, and commit SHA. Treat those fields as CI-submitted
evidence unless your deployment also records separate provider verification
receipts.

## Required Evydence Scopes

Create a least-privilege collector API key when possible. Store the secret once
in GitHub Actions as `EVYDENCE_API_KEY`; do not print it in logs.

Minimum scopes for the end-to-end workflow:

| Scope | Why it is needed |
| --- | --- |
| `build:write` | Upload GitHub Actions build provenance. |
| `evidence:write` | Upload SBOM, vulnerability scan, VEX, and related evidence. |
| `bundle:write` | Create the release bundle from the upload manifest. |
| `verify:read` | Read release-readiness output. |
| `product:read` | Preflight the configured product ID. |
| `project:read` | Preflight the configured project ID. |
| `release:read` | Preflight the configured release ID and read readiness. |
| `evidence:read` | Support readiness and evidence lookups during preflight and upload flows. |

Add these only when the workflow creates a customer package:

| Scope | Why it is needed |
| --- | --- |
| `package:write` | Create a scoped customer package. |
| `package:read` | Download or inspect package metadata in follow-up jobs. |

Use an admin key only to create the collector key. Do not run routine CI uploads
with broad tenant-admin credentials.

## GitHub Secrets And Variables

Secrets:

| Name | Value |
| --- | --- |
| `EVYDENCE_API_URL` | Base URL such as `https://evydence.example.test`. |
| `EVYDENCE_API_KEY` | Collector or tenant API key with the scopes above. |

Variables:

| Name | Value |
| --- | --- |
| `EVYDENCE_PRODUCT_ID` | Existing Evydence product ID. |
| `EVYDENCE_PROJECT_ID` | Existing Evydence project ID. |
| `EVYDENCE_RELEASE_ID` | Existing Evydence release ID. |
| `EVYDENCE_ARTIFACT_ID` | Existing artifact ID linked to the release. |
| `EVYDENCE_REDACTION_PROFILE_ID` | Optional redaction profile ID for package creation. |

Secret handling rules:

- Never echo `EVYDENCE_API_KEY`, bearer tokens, private keys, database URLs, raw
  evidence payloads, customer data, or unreleased package contents.
- Store IDs as variables only when revealing those IDs is acceptable for your
  repository visibility model.
- Rotate the collector key if it appears in logs, screenshots, issue comments,
  or artifact uploads.
- Keep downloaded customer packages in short-lived artifacts with explicit
  retention and access review.

## Workflow Template

Copy the checked workflow into the repository that builds your release:

```sh
mkdir -p .github/workflows
cp docs/github-actions/release-evidence-workflow.yml .github/workflows/evydence-release-evidence.yml
```

Review and pin the scanner versions used by your runner image or workflow. The
checked template uses `syft`, `grype`, and `trivy` commands as integration
points; production runners should install reviewed versions before the evidence
job runs.

Customer package creation is optional. To enable it, set both
`EVYDENCE_PRODUCT_ID` and `EVYDENCE_REDACTION_PROFILE_ID`; the manifest
generator requires all package fields together and rejects partial package
configuration.

## Expected Outputs

The workflow writes these files under `.evydence/`:

| File | Meaning |
| --- | --- |
| `artifact.digest` | SHA-256 digest of the built artifact. |
| `upload-manifest.json` | Batched Evydence create/action requests. |
| `sbom-cyclonedx-upload.json` | SBOM upload payload generated from Syft/CycloneDX output. |
| `scan-grype-upload.json` | Generic vulnerability-scan upload payload from Grype output. |
| `scan-trivy-upload.json` | Generic vulnerability-scan upload payload from Trivy output. |
| `release-bundle-upload.json` | Release bundle creation payload. |
| `customer-package-upload.json` | Optional customer package creation payload. |
| `upload-output.txt` | IDs returned by `dist/evydence upload manifest`. |
| `release-readiness.json` | Readiness report with result, gaps, assumptions, and limitations. |

Expected successful log markers:

```text
upload manifest valid
uploaded /v1/sboms:
uploaded /v1/vulnerability-scans:
uploaded /v1/release-bundles:
```

If package creation is enabled, also expect:

```text
uploaded /v1/customer-packages:
```

Readiness may still fail when evidence is missing or a policy gate blocks the
release. Treat that as a review signal, not as a compliance, certification,
scanner-authority, or release-security conclusion.

## Local Test Assumption

Default repository tests do not make live GitHub API calls and do not require
real GitHub repositories, GitHub OIDC tokens, scanners, S3, KMS, or customer
systems. Use the local simulation before copying the workflow:

```sh
make local-ci-simulation-check
```

That check exercises the same Evydence CLI path with local fixtures and a
loopback API. Live provider validation remains a separate deployment or release
readiness task because it needs real provider accounts, secrets, and repository
settings.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `401 Unauthorized` | Missing, revoked, or malformed `EVYDENCE_API_KEY`. | Rotate or re-store the key. Do not print it. |
| `403 Forbidden` | Key lacks a required scope. | Compare scopes with the table above. |
| `404 Not Found` | Product, project, release, or artifact ID belongs to another tenant or does not exist. | Re-copy IDs from the Evydence API using the same tenant. |
| `409 IDEMPOTENCY_KEY_REUSED` | A workflow run idempotency key was reused with different content. | Review the earlier upload and use the run attempt as part of the key. |
| Scanner command missing | Runner image does not include Syft, Grype, or Trivy. | Install pinned versions before the evidence job or use a reviewed runner image. |
| Readiness failed | Evidence gap, unhandled critical finding, missing passed build/attestation, missing bundle, or missing decision/exception. | Read `.evydence/release-readiness.json` and remediate the specific gap. |
