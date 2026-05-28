# API Reference

The public API base path is `/v1`. The generated contract is committed at [`../openapi.yaml`](../openapi.yaml) and served by the API at `/v1/openapi.json`.

Use this page for common integration workflows and route lookup. The endpoint catalog is expected to list every path in `openapi.yaml`; the generated contract remains the source of truth for operation details, schemas, status codes, security metadata, and route drift checks.

## Request Contract

Common headers:

```http
Authorization: Bearer <api_key>
Idempotency-Key: <stable-create-key>
Content-Type: application/json
Accept: application/json
```

Create and action endpoints require `Idempotency-Key`. Reusing the same key with the same request returns the original response. Reusing the same key with different request content returns `409` with `IDEMPOTENCY_KEY_REUSED`.

Successful JSON responses use a `data` envelope. Errors use RFC 9457 Problem Details with stable `code` and `request_id` fields. Clients may send `X-Request-ID`; otherwise the API generates one and returns it in the response header and Problem Details body.

Example validation problem:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "code": "VALIDATION_FAILED",
  "request_id": "req-test-validation"
}
```

## Minimal Release Evidence Workflow

The getting-started tutorial has a runnable curl flow. This section is the compact API shape for client implementers.

### 1. Create Product, Project, And Release

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/products" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: product-payments-api" \
  -H "Content-Type: application/json" \
  --data '{"name":"Payments API","slug":"payments-api"}'
```

Expected status: `201`.

Representative response shape:

```json
{
  "data": {
    "id": "prod_...",
    "name": "Payments API",
    "slug": "payments-api",
    "tenant_id": "ten_..."
  }
}
```

Then create:

```http
POST /v1/projects
POST /v1/releases
```

Representative request bodies:

```json
{"product_id":"prod_...","name":"api"}
```

```json
{"product_id":"prod_...","version":"1.0.0"}
```

### 2. Register Artifact And Upload Evidence

Register an artifact:

```json
{
  "name": "api.tar.gz",
  "media_type": "application/gzip",
  "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  "size": 42
}
```

Upload generic evidence:

```json
{
  "product_id": "prod_...",
  "project_id": "proj_...",
  "release_id": "rel_...",
  "type": "build",
  "subtype": "log",
  "title": "Build evidence",
  "payload_hash": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  "tags": ["ci"],
  "limitations": ["Captured from CI metadata submitted by the collector."]
}
```

`POST /v1/evidence` creates immutable evidence metadata. Later changes are represented by supersession, lifecycle events, links, or new evidence records.

### 3. Upload SBOM And Vulnerability Evidence

CycloneDX SBOM:

```http
POST /v1/sboms
```

```json
{
  "release_id": "rel_...",
  "artifact_id": "art_...",
  "payload": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
      {"name": "openssl", "purl": "pkg:apk/openssl@3.1.0"}
    ]
  }
}
```

Vulnerability scan:

```http
POST /v1/vulnerability-scans
```

```json
{
  "scanner": "grype",
  "target_ref": "pkg:oci/payments-api",
  "release_id": "rel_...",
  "findings": [
    {
      "vulnerability": "CVE-2026-0099",
      "component": "pkg:apk/openssl@3.1.0",
      "severity": "critical",
      "state": "open"
    }
  ]
}
```

Scanner evidence is recorded for review and workflow decisions. It is not treated as authoritative by itself.

Decision on a finding:

```http
POST /v1/vulnerability-findings/{id}/decisions
```

```json
{
  "status": "not_affected",
  "justification": "vulnerable code path is not present"
}
```

Supported decision statuses are `affected`, `not_affected`, `fixed`, and `under_investigation`.

### 4. Readiness And Bundle Retrieval

Create a release bundle:

```http
POST /v1/release-bundles
```

```json
{"release_id":"rel_..."}
```

Read readiness:

```http
GET /v1/reports/release-readiness?release_id=rel_...
```

Representative response shape:

```json
{
  "data": {
    "release_id": "rel_...",
    "result": "failed",
    "checks": [],
    "blocking_findings": [],
    "gaps": [],
    "assumptions": [],
    "limitations": []
  }
}
```

Readiness is deterministic and evidence-scoped. It reports checks, blockers, gaps, assumptions, and limitations; it is not a legal compliance or release-security conclusion.

## Authentication And Scopes

API keys and collector keys are tenant-scoped bearer secrets. Human SSO session actors derive scopes from role bindings and enforce resource constraints where those resources are part of the request.

Important scope boundaries:

| Boundary | Behavior |
|----------|----------|
| Tenant data | Cross-tenant reads return `404` where applicable. |
| Collector identity | Build attribution is derived from the authenticated collector key; clients must not submit `collector_id` for build attribution. |
| Instance admin | `GET /v1/admin/instance` requires explicit `instance:admin`; tenant admin and ordinary wildcard tenant keys are insufficient. |
| Customer portal | `POST /v1/customer-portal/package` is a public token exchange endpoint and intentionally does not use bearer authentication. |

## Endpoint Catalog

### System

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/v1/health` | Process health. |
| `GET` | `/v1/ready` | Low-detail readiness. |
| `GET` | `/v1/version` | Version metadata. |
| `GET` | `/v1/metrics` | Tenant-safe counts; admin scope required. |
| `GET` | `/v1/openapi.json` | Generated OpenAPI. |
| `GET` | `/v1/admin/instance` | Low-detail instance counts; `instance:admin` required. |

### Identity And Administration

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/organizations` | Create tenant-scoped organization. |
| `POST` | `/v1/users` | Create normalized human user. |
| `POST` | `/v1/users/{id}/deactivate` | Record deactivation transition. |
| `POST` | `/v1/role-bindings` | Assign role to user or collector. |
| `GET` | `/v1/role-bindings` | List tenant-scoped bindings. |
| `POST` | `/v1/sso/providers` | Record OIDC or SAML provider metadata. |
| `POST` | `/v1/sso/identity-links` | Link verified provider subject to user. |
| `POST` | `/v1/sso/sessions` | Issue one-time session secret. |
| `POST` | `/v1/sso/sessions/{id}/revoke` | Revoke session. |
| `POST` | `/v1/api-keys` | Create one-time API key secret. |
| `GET` | `/v1/api-keys` | List keys without secret hashes. |

Current SSO endpoints model admin-managed provider, identity-link, and session records. Live OIDC discovery, JWKS validation, SAML assertion verification, browser redirects, provider login callbacks, and group synchronization are not implemented in this slice.

### Products, Releases, Evidence, And Risk

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/products` | Create product. |
| `GET` | `/v1/products` | List products. |
| `POST` | `/v1/projects` | Create project under product. |
| `POST` | `/v1/releases` | Create release. |
| `GET` | `/v1/releases/{id}` | Read release. |
| `POST` | `/v1/releases/{id}/freeze` | Append freeze transition. |
| `POST` | `/v1/releases/{id}/approve` | Append approval transition. |
| `POST` | `/v1/artifacts` | Register artifact digest metadata. |
| `POST` | `/v1/evidence` | Create immutable evidence metadata. |
| `GET` | `/v1/evidence` | List evidence by release/type. |
| `GET` | `/v1/evidence/search` | Search by product, project, release, build, deployment, type, subtype, source, collector, verification status, subject, tag, created time, and limit. |
| `POST` | `/v1/evidence-summaries` | Create evidence-cited technical summary with assumptions and limitations. |
| `POST` | `/v1/evidence-graph-snapshots` | Persist product/release evidence adjacency snapshot. |
| `GET` | `/v1/evidence/{id}` | Read evidence. |
| `POST` | `/v1/evidence/{id}/supersede` | Supersede without mutating original. |
| `POST` | `/v1/evidence/{id}/link` | Link evidence to another subject. |
| `POST` | `/v1/evidence/{id}/lifecycle-events` | Append amendment/redaction/tombstone/retention marker. |
| `GET` | `/v1/evidence/{id}/lifecycle-events` | Read lifecycle timeline. |
| `POST` | `/v1/sboms` | Upload CycloneDX SBOM. |
| `POST` | `/v1/sboms/spdx` | Upload SPDX SBOM. |
| `GET` | `/v1/sboms/{id}` | Read SBOM metadata. |
| `POST` | `/v1/sbom-diffs` | Compare stored SBOMs. |
| `POST` | `/v1/vulnerability-scans` | Upload normalized vulnerability scan. |
| `GET` | `/v1/vulnerability-scans/{id}` | Read vulnerability scan metadata. |
| `POST` | `/v1/vulnerability-findings/{id}/decisions` | Superseding decision record. |
| `POST` | `/v1/vulnerability-findings/{id}/workflow` | Append workflow event. |
| `GET` | `/v1/reports/vulnerability-posture` | Summarize findings for a release. |
| `GET` | `/v1/reports/release-readiness` | Deterministic readiness report. |
| `GET` | `/v1/reports/missing-evidence` | Missing evidence report for review. |
| `POST` | `/v1/reports/anomaly` | Generate deterministic evidence anomaly signals. |
| `POST` | `/v1/release-candidates` | Create release candidate. |
| `GET` | `/v1/release-candidates` | List release candidates. |
| `GET` | `/v1/release-candidates/{id}` | Read release candidate. |
| `POST` | `/v1/release-candidates/{id}/promote` | Promote release candidate. |
| `POST` | `/v1/release-candidates/{id}/reject` | Reject release candidate. |
| `POST` | `/v1/remediation-tasks` | Create remediation task. |

### CI, Source, Deployment, And Collectors

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/collectors` | Create collector and one-time key. |
| `GET` | `/v1/collectors` | List collectors without secrets. |
| `POST` | `/v1/collectors/{id}/releases` | Record collector release evidence. |
| `GET` | `/v1/collectors/{id}/health` | Collector health report. |
| `POST` | `/v1/commercial-collectors` | Create commercial collector definition. |
| `GET` | `/v1/commercial-collectors` | List commercial collector definitions. |
| `POST` | `/v1/marketplace-collectors` | Register marketplace collector package metadata. |
| `GET` | `/v1/marketplace-collectors` | List marketplace collector package records. |
| `POST` | `/v1/builds` | Record immutable build run. |
| `GET` | `/v1/builds/{id}` | Read build run. |
| `POST` | `/v1/builds/{id}/attestations` | Upload DSSE in-toto attestation JSON. |
| `POST` | `/v1/build-attestations/{id}/verify-signature` | Verify against configured DSSE trust roots. |
| `POST` | `/v1/dsse-trust-roots` | Create DSSE trust root. |
| `POST` | `/v1/source/repositories` | Record source repository. |
| `GET` | `/v1/source/repositories` | List repositories. |
| `POST` | `/v1/source/commits` | Record source commit. |
| `POST` | `/v1/source/branches` | Record branch state. |
| `POST` | `/v1/source/pull-requests` | Record pull request metadata. |
| `POST` | `/v1/collectors/github/source-snapshots` | Upload strict GitHub source snapshot. |
| `POST` | `/v1/collectors/gitlab/source-snapshots` | Upload strict GitLab source snapshot. |
| `POST` | `/v1/environments` | Create deployment environment. |
| `GET` | `/v1/environments` | List environments. |
| `POST` | `/v1/deployments` | Record deployment event. |
| `GET` | `/v1/deployments` | List deployments. |
| `GET` | `/v1/deployments/{id}` | Read deployment event. |
| `POST` | `/v1/container-images` | Register container image metadata. |

Source snapshots capture submitted provider metadata. They do not call provider APIs or verify OIDC tokens.

### Controls, Reports, Packages, And Governance

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/control-frameworks` | Create framework version. |
| `GET` | `/v1/control-frameworks` | List frameworks. |
| `GET` | `/v1/control-framework-template-packs` | List built-in starter packs. |
| `POST` | `/v1/control-framework-template-packs/{slug}/install` | Copy starter pack to tenant records. |
| `POST` | `/v1/controls` | Create control. |
| `GET` | `/v1/controls/{id}` | Read control. |
| `POST` | `/v1/controls/{id}/evidence` | Append control evidence link. |
| `GET` | `/v1/control-evidence` | List links. |
| `GET` | `/v1/reports/control-coverage` | Deterministic control coverage. |
| `GET` | `/v1/reports/cra-readiness` | Technical evidence readiness report with limitations. |
| `POST` | `/v1/exceptions` | Create exception. |
| `POST` | `/v1/exceptions/{id}/approve` | Approve exception. |
| `GET` | `/v1/exceptions` | List exceptions. |
| `POST` | `/v1/waivers` | Create waiver. |
| `POST` | `/v1/waivers/{id}/approve` | Approve waiver. |
| `POST` | `/v1/approvals` | Create immutable approval record. |
| `POST` | `/v1/redaction-profiles` | Create package redaction profile. |
| `POST` | `/v1/customer-packages` | Create scoped customer package manifest. |
| `GET` | `/v1/customer-packages/{id}` | Read package manifest and record access. |
| `GET` | `/v1/customer-packages/{id}/download` | Download scoped ZIP package with manifest metadata and verification guidance. |
| `POST` | `/v1/customer-portal/access` | Create one-time package access token. |
| `POST` | `/v1/customer-portal/package` | Exchange package token for scoped manifest. |
| `POST` | `/v1/customer-portal/package/download` | Exchange package token for scoped ZIP package download. |
| `POST` | `/v1/questionnaire-templates` | Create questionnaire template. |
| `POST` | `/v1/questionnaire-packages` | Generate evidence-backed responses. |
| `POST` | `/v1/questionnaire-drafts` | Create evidence-backed draft answers for review. |
| `GET` | `/v1/reports/security-review-package` | Redaction-aware package report. |
| `GET` | `/v1/reports/cra-readiness-html` | HTML CRA-readiness review content. |
| `POST` | `/v1/reports/pdf` | Create reproducible PDF report package metadata and payload hash. |
| `GET` | `/v1/reports/incident-package` | Incident package report. |
| `POST` | `/v1/report-templates` | Create allowed-field template. |
| `POST` | `/v1/report-templates/{id}/render` | Render deterministic JSON report. |
| `POST` | `/v1/incidents` | Create incident. |
| `POST` | `/v1/incidents/{id}/timeline` | Append incident timeline event. |

### Integrity, Verification, And Operations

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/release-bundles` | Create signed release bundle. |
| `GET` | `/v1/release-bundles/{id}` | Read bundle metadata. |
| `GET` | `/v1/release-bundles/{id}/manifest` | Read bundle manifest. |
| `GET` | `/v1/release-bundles/{id}/verify` | Verify bundle. |
| `POST` | `/v1/evidence-bundles` | Export evidence bundle. |
| `POST` | `/v1/evidence-bundles/import` | Import evidence bundle. |
| `POST` | `/v1/verify` | Verify supported subject types. |
| `GET` | `/v1/audit-chain/verify` | Verify tenant audit chain. |
| `GET` | `/v1/audit-log` | List tenant audit entries; admin scope required. |
| `GET` | `/v1/signing-keys` | List keys. |
| `POST` | `/v1/signing-keys/rotate` | Rotate signing key. |
| `POST` | `/v1/signing-keys/{id}/revoke` | Revoke key for new signatures. |
| `POST` | `/v1/signing-providers` | Record external signing-provider metadata. |
| `POST` | `/v1/signing-operations` | Record external signing-provider operation receipt and signature ref. |
| `POST` | `/v1/provider-verifications` | Verify stored provider identity metadata; no live provider assertion is implied. |
| `POST` | `/v1/saas/profiles` | Create explicit-instance-admin SaaS edition profile record. |
| `POST` | `/v1/artifact-signatures` | Create artifact signature metadata. |
| `GET` | `/v1/artifact-signatures/{id}` | Read artifact signature. |
| `POST` | `/v1/artifact-signatures/{id}/verify-cosign` | Verify cosign-style artifact signature. |
| `POST` | `/v1/merkle-batches` | Create signed checkpoint batch. |
| `GET` | `/v1/merkle-batches/{id}/verify` | Verify batch. |
| `POST` | `/v1/transparency-checkpoints` | Record external anchoring metadata. |
| `POST` | `/v1/public-transparency-logs` | Record optional public transparency log configuration. |
| `POST` | `/v1/public-transparency-log-entries` | Record published public transparency log entry metadata. |
| `POST` | `/v1/object-retention-policies` | Record retention policy intent. |
| `POST` | `/v1/object-retention-policies/{id}/verify` | Record verification transition. |
| `POST` | `/v1/legal-holds` | Record legal hold. |
| `POST` | `/v1/retention-overrides` | Record retention override. |
| `GET` | `/v1/reports/retention` | List retention records. |
| `POST` | `/v1/backup-manifests` | Generate backup manifest. |
| `GET` | `/v1/backup-manifests/{id}/verify` | Verify backup manifest. |

### Security Evidence And Contracts

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/security-scans` | Upload SAST, DAST, secret scan, license scan, or API-security scan JSON. |
| `POST` | `/v1/api-security-scans` | Convenience API-security scan route. |
| `POST` | `/v1/security-documents` | Upload sensitive manual security document metadata/payload. |
| `POST` | `/v1/vex` | Upload OpenVEX. |
| `POST` | `/v1/vex/cyclonedx` | Upload CycloneDX VEX. |
| `GET` | `/v1/vex/{id}` | Read VEX metadata. |
| `POST` | `/v1/openapi-contracts` | Upload OpenAPI contract. |
| `GET` | `/v1/openapi-contracts/{id}` | Read contract metadata. |
| `POST` | `/v1/openapi-diffs` | Compare stored contracts. |
| `POST` | `/v1/policies/evaluate` | Evaluate built-in release policy. |
| `POST` | `/v1/custom-policies` | Create deterministic custom policy. |
| `POST` | `/v1/custom-policies/{id}/evaluate` | Store replayable policy evaluation. |

## Current Contract Limitations

- `openapi.yaml` is generated as compact JSON-style YAML and is optimized for drift checks and tooling, not prose review.
- A subset of high-value operations has precise named schemas and response envelopes. Many route responses remain generic envelopes.
- Operation-level examples are maintained here and in tests until the generator emits richer examples.
- OpenAPI diffing currently classifies broad path-count changes; rich operation-level compatibility analysis remains future work.

These limitations should be called out in release evidence when API contract review is part of the release process.
