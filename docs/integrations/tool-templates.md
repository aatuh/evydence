# Tool-Specific Integration Templates

These templates show practical handoff points for common tools. They are copy-starting points, not live provider tests. Default repository checks do not call Syft, Grype, Trivy, Dependency-Track, Jira, GitHub, GitLab, S3, or MinIO.

Evydence records submitted evidence and limitations. Scanner output is not
treated as complete or authoritative vulnerability coverage, Jira links are
metadata, and object-store configuration still needs operator review.

## Syft CycloneDX SBOM

Use Syft to write CycloneDX JSON:

```sh
mkdir -p .evydence
syft dir:. -o cyclonedx-json=.evydence/sbom.cdx.json
```

Add it to an Evydence upload manifest:

```sh
python3 scripts/github_release_evidence_manifest.py \
  --out .evydence/upload-manifest.json \
  --release-id "$EVYDENCE_RELEASE_ID" \
  --artifact-id "$EVYDENCE_ARTIFACT_ID" \
  --target-ref "pkg:github/${GITHUB_REPOSITORY}@${GITHUB_SHA}" \
  --idempotency-prefix "ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" \
  --cyclonedx-sbom .evydence/sbom.cdx.json \
  --include-release-bundle
```

Expected Evydence endpoint: `POST /v1/sboms`.

## Grype Vulnerability Scan

Use Grype JSON as scanner input:

```sh
mkdir -p .evydence
grype dir:. -o json > .evydence/grype.json
```

Normalize and upload through the same manifest generator:

```sh
python3 scripts/github_release_evidence_manifest.py \
  --out .evydence/upload-manifest.json \
  --release-id "$EVYDENCE_RELEASE_ID" \
  --artifact-id "$EVYDENCE_ARTIFACT_ID" \
  --target-ref "pkg:github/${GITHUB_REPOSITORY}@${GITHUB_SHA}" \
  --idempotency-prefix "ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" \
  --grype-json .evydence/grype.json
```

Expected Evydence endpoint: `POST /v1/vulnerability-scans`.

## Trivy Vulnerability Scan

Use Trivy filesystem JSON:

```sh
mkdir -p .evydence
trivy fs --format json --output .evydence/trivy.json .
```

Normalize and upload:

```sh
python3 scripts/github_release_evidence_manifest.py \
  --out .evydence/upload-manifest.json \
  --release-id "$EVYDENCE_RELEASE_ID" \
  --artifact-id "$EVYDENCE_ARTIFACT_ID" \
  --target-ref "pkg:github/${GITHUB_REPOSITORY}@${GITHUB_SHA}" \
  --idempotency-prefix "ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" \
  --trivy-json .evydence/trivy.json
```

Expected Evydence endpoint: `POST /v1/vulnerability-scans`.

## GitHub Actions

Use the end-to-end guide when your repository builds in GitHub Actions:

- [End-to-end GitHub Actions release evidence guide](../github-actions/end-to-end-release-evidence.md)
- [Scanner workflow template](../github-actions/release-evidence-workflow.yml)
- [Quickstart workflow template](../github-actions/quickstart-release-evidence.yml)

Use `contents: read` by default. Add `id-token: write` only when your deployment
intentionally records OIDC subject metadata. The current workflow does not call
the live GitHub API.

## GitLab CI

Use the checked GitLab CI template:

```sh
cp docs/gitlab/evydence-release-evidence.gitlab-ci.yml .gitlab-ci.yml
```

Required variables:

- `EVYDENCE_API_URL`
- `EVYDENCE_API_KEY`
- `EVYDENCE_PROJECT_ID`
- `EVYDENCE_RELEASE_ID`
- `EVYDENCE_ARTIFACT_ID`

GitLab-provided variables such as `CI_PROJECT_PATH`, `CI_COMMIT_SHA`,
`CI_PIPELINE_ID`, and `CI_JOB_ID` are recorded as submitted CI metadata. They do
not prove GitLab-side branch protection, approval policy, runner integrity, or
pipeline identity by themselves.

## Dependency-Track

Dependency-Track is adjacent inventory and analysis, not replaced by Evydence.
Use its exports as evidence inputs when they are part of your review process.

SBOM export handoff example:

```sh
curl -fsS \
  -H "X-Api-Key: $DEPENDENCY_TRACK_API_KEY" \
  "$DEPENDENCY_TRACK_URL/api/v1/bom/cyclonedx/project/$DEPENDENCY_TRACK_PROJECT_UUID" \
  > .evydence/dependency-track-sbom.cdx.json
```

Then upload the exported CycloneDX document through the Syft/CycloneDX manifest
path above. Keep the Dependency-Track API key in CI secrets and do not store
the key or raw exported customer data in logs.

If you export Dependency-Track findings, normalize them to Evydence generic
vulnerability scan JSON before upload:

```json
{
  "release_id": "rel_example",
  "scanner": "dependency-track",
  "target_ref": "pkg:github/acme/service@sha",
  "findings": [
    {
      "vulnerability": "CVE-2026-0099",
      "component": "pkg:maven/example/component@1.0.0",
      "severity": "high",
      "state": "open"
    }
  ]
}
```

Expected Evydence endpoint: `POST /v1/vulnerability-scans`.

## Jira Metadata Links

Jira links are metadata, not evidence trust by themselves. Use them to connect a
decision, exception, remediation task, or security review to the work item where
people coordinated the change.

Generic evidence metadata example:

```json
{
  "product_id": "prod_example",
  "release_id": "rel_example",
  "type": "issue_tracker",
  "subtype": "jira_metadata",
  "title": "Jira review metadata for CVE-2026-0099",
  "payload_hash": "sha256:<hash-of-redacted-json>",
  "metadata": {
    "provider": "jira",
    "issue_key": "SEC-1234",
    "issue_url": "https://jira.example.test/browse/SEC-1234",
    "linked_subject": "CVE-2026-0099"
  },
  "limitations": [
    "Jira metadata links the review context but does not prove the ticket state or approval policy by itself."
  ]
}
```

Expected Evydence endpoint: `POST /v1/evidence`. Use a redacted local JSON file
for `payload_hash` input and avoid uploading comments, attachments, credentials,
or customer data unless the package scope and redaction profile explicitly allow
it.

## S3-Compatible Object Storage

For shared or production-like deployments, use S3/MinIO-compatible object
storage rather than filesystem storage:

```sh
EVYDENCE_OBJECT_STORE=s3
EVYDENCE_S3_ENDPOINT=s3.example.test
EVYDENCE_S3_BUCKET=evydence
EVYDENCE_S3_REGION=eu-north-1
EVYDENCE_S3_USE_SSL=true
EVYDENCE_S3_ACCESS_KEY_ID=<from-secret-manager>
EVYDENCE_S3_SECRET_ACCESS_KEY=<from-secret-manager>
```

Operator checklist:

- create the bucket outside Evydence before startup;
- use TLS for remote object storage;
- store object credentials in deployment secrets, not source control;
- back up PostgreSQL and object storage from the same recovery point;
- enable provider-side versioning, retention, or object lock when required;
- rehearse restore with [Backup and restore runbook](../runbooks/backup-restore.md);
- review [Object store recovery runbook](../runbooks/object-store-recovery.md).

Evydence tenant-prefixes object keys and verifies stored payload digests during
worker replay and verification flows. Bucket policy, IAM, encryption, lifecycle
rules, WORM/object-lock enforcement, and provider availability remain operator
responsibilities.

## Local Validation

Validate generated manifests without network access:

```sh
go run ./cmd/evydence upload validate-manifest \
  --manifest .evydence/upload-manifest.json
```

Run the checked local CI path:

```sh
make local-ci-simulation-check
```

Those checks validate Evydence-side manifest handling and local evidence flow.
They intentionally do not validate live provider credentials, scanner
installations, SaaS project permissions, or object-store service policies.
