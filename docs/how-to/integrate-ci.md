# Integrate CI Collectors

Use this guide to connect CI systems to Evydence. The examples submit CI metadata and artifacts as tenant-scoped evidence; they do not make Evydence the source of truth for provider-side policy, identity, or workflow state.

## Prerequisites

- An Evydence API URL.
- A tenant admin API key for creating collectors, or an existing collector key with the required write scopes.
- Product, project, release, and artifact IDs for the release being recorded.
- Provider secrets stored in the CI secret store, not committed to the repository.

## Create A Collector

Create a collector with an admin key:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/collectors" \
  -H "Authorization: Bearer $EVYDENCE_ADMIN_API_KEY" \
  -H "Idempotency-Key: collector-github-actions-main" \
  -H "Content-Type: application/json" \
  --data '{"name":"github-actions-main","type":"github_actions","version":"1.0.0"}' \
  | jq .
```

Expected status is `201`. The response returns the collector API key secret once. Store it as a CI secret such as `EVYDENCE_API_KEY`.

## GitHub Actions

Start with the quickstart workflow
[docs/github-actions/quickstart-release-evidence.yml](../github-actions/quickstart-release-evidence.yml).
It builds one artifact, computes its digest, writes a minimal CycloneDX SBOM,
writes an empty generic vulnerability scan payload, uploads GitHub Actions build
metadata with the scoped API key, creates an upload manifest, creates a release
bundle, and reads the release-readiness report.

The fuller scanner-oriented workflow is
[docs/github-actions/release-evidence-workflow.yml](../github-actions/release-evidence-workflow.yml).
The composite upload action is
[docs/github-actions/upload-build/action.yml](../github-actions/upload-build/action.yml).

Required quickstart inputs:

- `EVYDENCE_API_URL` as a GitHub secret, for example `https://evydence.example.test`
- `EVYDENCE_API_KEY` as a GitHub secret with `build:write`, `evidence:write`,
  `bundle:write`, `verify:read`, `product:read`, `project:read`,
  `release:read`, and `evidence:read`
- `EVYDENCE_PRODUCT_ID` as a GitHub variable
- `EVYDENCE_PROJECT_ID` as a GitHub variable
- `EVYDENCE_RELEASE_ID` as a GitHub variable
- `EVYDENCE_ARTIFACT_ID` as a GitHub variable
- optionally `EVYDENCE_OPENVEX_PATH` as a GitHub variable when the repository includes a reviewed
  OpenVEX JSON document to upload

The CLI command used by the workflow reads GitHub-provided environment variables such as `GITHUB_REPOSITORY`, `GITHUB_WORKFLOW_REF`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_REF`, and `GITHUB_SHA`.

The API key used by the quickstart must be scoped for the operations it runs:
`build:write`, `evidence:write`, `bundle:write`, `verify:read`,
`product:read`, `project:read`, `release:read`, and `evidence:read`. Add
`package:write` only when the workflow is extended to generate a customer
package.

The quickstart grants only `contents: read`. If a deployment chooses to request
and record GitHub OIDC metadata, grant `id-token: write` in the workflow and pass
`EVYDENCE_GITHUB_OIDC_SUBJECT` or `--oidc-subject`. This implementation records
the value as evidence metadata; it does not request or verify a GitHub OIDC
token.

### Minimal GitHub Actions Setup

1. Create or locate the Evydence product, project, release, and artifact
   records for the release candidate. Copy the product, project, release, and
   artifact IDs into GitHub Actions variables named exactly
   `EVYDENCE_PRODUCT_ID`, `EVYDENCE_PROJECT_ID`, `EVYDENCE_RELEASE_ID`, and
   `EVYDENCE_ARTIFACT_ID`.
2. Create a collector API key or tenant API key with the scopes listed above.
   Store the API URL and API key as GitHub Actions secrets named exactly
   `EVYDENCE_API_URL` and `EVYDENCE_API_KEY`.
3. Copy
   [`docs/github-actions/quickstart-release-evidence.yml`](../github-actions/quickstart-release-evidence.yml)
   into `.github/workflows/evydence-release-evidence.yml` in the repository
   that builds the artifact.
4. Run the workflow manually with `workflow_dispatch`.

Expected output:

- `.evydence/artifact.digest` contains the SHA-256 digest of the built CLI
  artifact.
- `.evydence/sbom.cdx.json` and `.evydence/grype.json` are uploaded as release
  evidence through an upload manifest.
- `evydence ci preflight` validates the API URL, API key scopes, product,
  project, release, artifact, and manifest before the upload step.
- GitHub Actions build provenance is recorded for the configured project and
  release.
- The manifest upload creates a release bundle when the required release
  evidence is present.
- `.evydence/release-readiness.json` contains the current readiness result,
  gaps, assumptions, and limitations for review.

Troubleshooting:

- `401 Unauthorized` usually means `EVYDENCE_API_KEY` is missing, revoked, or
  pasted with extra whitespace. Rotate the key if it may have been exposed; do
  not print it in logs.
- `403 Forbidden` means the key authenticated but lacks a required scope. The
  quickstart requires `build:write`, `evidence:write`, `bundle:write`,
  `verify:read`, `product:read`, `project:read`, `release:read`, and
  `evidence:read`.
- `404 Not Found` usually means the product, project, release, or artifact ID
  is wrong for the tenant bound to the API key. Check the GitHub variable values
  against Evydence API responses.
- `evydence ci preflight` uses stable exit codes for CI routing: `2` for
  missing configuration, `3` for authentication failure, `4` for missing scope,
  `5` for wrong-tenant or missing resource, and `6` for invalid manifests. It
  does not print the API key.
- `409 IDEMPOTENCY_KEY_REUSED` means the same workflow run idempotency prefix
  was reused with different payload content. Re-run with a new
  `GITHUB_RUN_ATTEMPT` or change the manifest idempotency prefix only after
  reviewing whether the earlier upload should remain authoritative.
- Readiness failures should be treated as evidence gaps or policy findings to
  review, not as legal compliance, certification, or release-security
  conclusions.

## One-Shot CLI Upload

For a local or CI path that already has files on disk, use the one-shot release
evidence uploader:

```sh
go run ./cmd/evydence release upload-evidence \
  --url "$EVYDENCE_API_URL" \
  --api-key "$EVYDENCE_API_KEY" \
  --product-id "$EVYDENCE_PRODUCT_ID" \
  --release-id "$EVYDENCE_RELEASE_ID" \
  --artifact-id "$EVYDENCE_ARTIFACT_ID" \
  --artifact dist/api.tar.gz \
  --sbom .evydence/sbom.cdx.json \
  --scan .evydence/scan.evydence.json \
  --target-ref "pkg:github/${GITHUB_REPOSITORY}@${GITHUB_SHA}" \
  --vex .evydence/review.openvex.json
```

The command computes the artifact digest locally, validates JSON inputs, uploads
the SBOM, generic vulnerability scan, optional OpenVEX document, and release
bundle through existing `/v1` endpoints, then prints the release-readiness API
reference to check next. It never prints the API key.

Use explicit create flags when the product, release, or artifact should be
created by the command:

```sh
go run ./cmd/evydence release upload-evidence \
  --url "$EVYDENCE_API_URL" \
  --api-key "$EVYDENCE_API_KEY" \
  --create-product \
  --product-name "Payments API" \
  --product-slug payments-api \
  --create-release \
  --release-version 1.0.0 \
  --create-artifact \
  --artifact dist/api.tar.gz \
  --sbom .evydence/sbom.cdx.json \
  --scan .evydence/scan.evydence.json \
  --target-ref "pkg:github/acme/payments-api@${GITHUB_SHA}" \
  --idempotency-prefix "release-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
```

Without the matching `--create-*` flag, missing product, release, or artifact
IDs fail before side effects. Add `--dry-run` to validate paths and JSON and
print planned requests without requiring an API URL or key. The `--scan` file is
Evydence generic vulnerability scan JSON with `findings`; use the full
scanner-oriented workflow when you need Grype or Trivy normalization.

For bulk uploads, validate the manifest before upload:

```sh
go run ./cmd/evydence upload validate-manifest \
  --manifest .evydence/upload-manifest.json
```

The manifest schema and supported request kinds are documented in
[Upload manifest](../reference/upload-manifest.md).

The full workflow also shows a scanner handoff path:

- produce CycloneDX JSON with `syft`;
- produce Grype and Trivy JSON scanner outputs;
- run `scripts/github_release_evidence_manifest.py` to normalize those files into Evydence upload payloads;
- upload the manifest with `evydence upload manifest`;
- optionally create a customer package when `EVYDENCE_PRODUCT_ID` and `EVYDENCE_REDACTION_PROFILE_ID` are configured.

Pin scanner versions in your runner image or workflow before using the example for production evidence. Scanner output is evidence for review; it is not treated as complete or authoritative vulnerability coverage.

## GitLab CI

The GitLab template is [docs/gitlab/evydence-release-evidence.gitlab-ci.yml](../gitlab/evydence-release-evidence.gitlab-ci.yml).

Required CI variables mirror the GitHub flow:

- `EVYDENCE_API_URL`
- `EVYDENCE_API_KEY`
- `EVYDENCE_PROJECT_ID`
- `EVYDENCE_RELEASE_ID`
- `EVYDENCE_ARTIFACT_ID`

The template builds `dist/evydence`, writes `artifact.digest`, creates `evydence-upload-manifest.json` in the evidence job, and uploads that manifest with `go run ./cmd/evydence upload manifest`. GitLab-provided variables such as `CI_PROJECT_PATH`, `CI_COMMIT_SHA`, `CI_PIPELINE_ID`, and `CI_JOB_ID` are recorded as submitted CI metadata; Evydence does not verify GitLab identity or pipeline policy from those fields alone.

## Source Snapshots

Use [Source snapshot collectors](../collectors/source-snapshots.md) to upload repository, commit, branch-protection, and pull-request metadata from GitHub or GitLab:

- `POST /v1/collectors/github/source-snapshots`
- `POST /v1/collectors/gitlab/source-snapshots`

Do not include bearer tokens, private repository credentials, or raw provider secret dumps in snapshot payloads. Commit messages are stored as hashes by the API service.

## Collector Supply Chain

Use [Collector supply chain](../collectors/supply-chain.md) to record collector release evidence and health checks:

- `POST /v1/collectors/{id}/releases`
- `GET /v1/collectors/{id}/health`

Collector health reports show whether release evidence exists and whether a collector version is pinned. They do not prove that a collector is free of vulnerabilities or safe to run.
