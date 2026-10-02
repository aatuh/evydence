# API Reference

The public API base path is `/v1`. The generated contract is committed at [`../openapi.yaml`](../openapi.yaml) and served by the API at `/v1/openapi.json`.
The static rendered companion is committed at [`openapi/index.html`](openapi/index.html) for browser-based review of operations and schemas.

Use this page for common integration workflows and route lookup. The endpoint catalog is expected to list every path in `openapi.yaml`; the generated contract remains the source of truth for operation details, schemas, status codes, security metadata, and route drift checks.
The OpenAPI contract also includes non-sensitive examples for the main release evidence flow: create release, upload SBOM, upload vulnerability scan, record a vulnerability decision, read release readiness, and create a customer package.

## Stability

Every operation is classified as `core`, `supported`, `experimental`, or
`deprecated` in the generated OpenAPI extension
`x-evydence-stability`. See [Product boundary and API stability](reference/product-boundary.md)
for the classification policy and the generated [API contract matrix](reference/api-contract-matrix.md)
for every operation. [API Versioning And Deprecation](reference/api-versioning.md)
defines the formal compatibility, prerelease-exception, and deprecation
lifecycle.

## Request Contract

Common headers:

```http
Authorization: Bearer <api_key>
Idempotency-Key: <stable-create-key>
Content-Type: application/json
Accept: application/json
```

Create and action endpoints require `Idempotency-Key`. A key is scoped to the
authenticated tenant, actor, HTTP method, and path. The service stores a
request digest, not the raw request body, and uses an internal hashed lease
owner while a command is pending.

Native document uploads also bind their media type and relationship/version
headers into the request digest. During the bounded retention window, a retry
of a record created before those headers were included can fall back to the
legacy body-only digest only after the current fingerprint conflicts. Newly
created records always retain the stronger fingerprint, so changing a semantic
header while reusing their key still returns a conflict.

For 24 hours after reservation:

- Reusing a completed key with the same request returns the original safe
  response.
- Reusing a key with a different request returns `409` with
  `IDEMPOTENCY_KEY_REUSED`; the original body is not disclosed.
- Reusing an actively leased key returns `409` with
  `IDEMPOTENCY_IN_PROGRESS`; clients should retry the same key after a short
  delay rather than issue the command again.
- A pending lease that expires without completion may be recovered by one
  later request using the same key and request digest. The transition is
  conditional, so only one recovery owner is recorded.
- A failed key returns `409` with `IDEMPOTENCY_REQUEST_FAILED`. Its original
  error and any partial response are not stored or replayed.

For create endpoints that issue a one-time credential, such as an API key or
collector key, the initial response includes the raw credential once. The
durable replay envelope deliberately omits that field. A retry after a
transport failure returns the created public resource but cannot recover the
credential; create a replacement credential through the normal rotation flow.

After retention expires, the key is eligible for cleanup and is no longer a
replay guarantee. Clients that require a retry must keep the same key and
request bytes within that window.

Successful JSON responses use a `data` envelope. Errors use RFC 9457 Problem Details with stable `code`, `request_id`, `retryable`, and `retry_class` fields. Clients may send `X-Request-ID`; otherwise the API generates one and returns it in the response header and Problem Details body. When a retry interval is applicable, the body contains `retry_after_seconds` and the response mirrors it in `Retry-After`.

The complete generated catalog is [API Error Codes](reference/error-codes.md). Switch on `code` and `retry_class`, never the human-readable `title` or `detail`. Validation failures can include safe JSON Pointer `violations`; no response includes raw database, object-store, provider, or parser errors.

Example validation problem:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "validation failed",
  "code": "VALIDATION_FAILED",
  "request_id": "req-test-validation",
  "retryable": false,
  "retry_class": "none",
  "violations": [
    {"field": "/name", "code": "required"}
  ]
}
```

## Collection Pagination And Conditional Reads

Collection `GET` endpoints return the existing `data` array together with a
typed `meta` object. This preserves the v1 envelope while bounding every page:

```json
{
  "data": [{"id": "..."}],
  "meta": {
    "api_version": "v1",
    "page_size": 50,
    "sort": "created_at",
    "direction": "asc",
    "next_cursor": "opaque-token-when-another-page-exists"
  }
}
```

`page_size` defaults to `50` and must be from `1` through `500`. Most lists
allow `sort=created_at` (the default) or `sort=id`, with `direction=asc` (the
default) or `direction=desc`; evidence search and audit log retain their
reverse-chronological default (`direction=desc`). Template packs and SBOM components are sorted by
their stable `id` only. Send the returned opaque `cursor` unchanged with the
same filters, sort, and direction to fetch the next page. Cursors are bound to
the authenticated tenant and query shape; malformed, tampered, mismatched, or
stale cursors return `400 VALIDATION_FAILED` without disclosing list state.

`limit` remains a transitional alias for the existing evidence-search, SBOM
component, and audit-log routes. Do not combine it with `page_size`; new
clients should use `page_size`. Unsupported, repeated, or blank query
parameters are rejected rather than silently ignored.

In the PostgreSQL profile, admin audit-log pages query the tenant's committed
chain with bounded keyset pagination, including entries beyond the newest 500.
The local-memory profile retains its legacy in-process 500-entry preselection.
SBOM component pages in the PostgreSQL profile likewise apply current tenant
ownership and resource grants before the SQL keyset limit, so pagination can
reach components beyond the former 500-result preselection cap. Components
remain JSONB arrays inside each SBOM; the database expands matching rows for
the query, so this is bounded transfer to the API, not a component-level index.
The source evidence must be an SBOM with matching release and artifact subject;
its optional build and deployment parents must resolve consistently in the
same tenant. Inconsistently linked rows are excluded from unfiltered pages.
The local-memory profile retains the legacy 500-component preselection cap.
When `sbom_id` is supplied in PostgreSQL mode, a nonexistent, inaccessible, or
inconsistently linked SBOM returns `404`; a visible SBOM with no matching
components returns an empty page. This avoids exposing other product scopes
through filtered-list existence checks.

Evidence lifecycle-event pages in PostgreSQL mode read ordinary evidence
parentage and a bounded event page from one tenant-scoped snapshot. The API
checks current `evidence:read` grants and removes sensitive detail fields and
internal canonical-origin metadata before returning events. Worker-owned
evidence retains its legacy projection path until its provenance checks move.

Finite resource `GET` responses expose private ETags. For immutable resources
the tag is a representation digest; resources with a positive `revision` use
that revision as a strong decimal ETag. Send `If-None-Match` from a previous
read to receive `304 Not Modified` with no response body when it still matches.
Responses include `Cache-Control: private, max-age=0, must-revalidate` and
`Vary: Authorization`; ETags never grant access or replace authorization.

## Conditional Release Transitions

Releases and release candidates include a positive integer `revision` in their
read and create responses. Their state transitions require the exact current
revision in a strong `If-Match` ETag so a stale client cannot silently replace
another actor's transition.

```http
POST /v1/releases/rel_.../freeze
If-Match: "1"
Idempotency-Key: release-freeze-rel_...-r1
```

Use the returned `revision` for the next transition. The same requirement
applies to release-candidate promotion and rejection. Missing, weak, combined,
or non-positive tags return `400 VALIDATION_FAILED`. A stale tag returns `409`
with `VERSION_CONFLICT` and a safe `current_revision` value in Problem Details;
read the resource again before deciding whether to retry. These transitions
append audit history and do not alter immutable evidence records.

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
POST /v1/releases/{id}/evidence-flow/start
GET /v1/releases/{id}/security-summary
```

Representative request bodies:

```json
{"product_id":"prod_...","name":"api"}
```

```json
{"product_id":"prod_...","version":"1.0.0"}
```

`POST /v1/releases/{id}/evidence-flow/start` returns a read-only workflow plan
with current evidence counts, required endpoints, scopes, idempotency guidance,
assumptions, and limitations. It does not create evidence or replace the
resource-specific endpoints.

`GET /v1/releases/{id}/security-summary` returns a tenant-scoped quick-check
summary for review surfaces. It includes artifact, SBOM, scan, finding,
decision, approval, exception, readiness, and package-generation status, but it
does not include raw evidence payload bytes or private decision notes.

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

`POST /v1/evidence` creates immutable evidence metadata. Later changes are
represented by supersession, lifecycle events, links, or new evidence records.
Parser-normalization records are internal and cannot be created through this
generic route. SBOM, vulnerability-scan, OpenAPI-contract, VEX, parser-
normalization, and build-attestation evidence has fixed relationships because
those coordinates bind worker-owned projections; generic link and supersession
requests for those evidence types return a conflict.

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
      {"type": "library", "name": "openssl", "purl": "pkg:apk/openssl@3.1.0"}
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
  "justification": "vulnerable code path is not present",
  "impact_statement": "This release is not affected because the vulnerable runtime code is not included.",
  "action_statement": "No customer action is required for this finding.",
  "customer_visible": true,
  "internal_notes": "tenant-internal triage note",
  "evidence_ids": ["ev_supporting_review"],
  "vex_document_id": "vex_imported_review"
}
```

Supported decision statuses are `affected`, `not_affected`, `fixed`, and
`under_investigation`. Customer-visible decisions require
`impact_statement`; `internal_notes` are tenant-internal and must not be copied
into customer-safe package summaries. A later decision for the same finding
supersedes the previous active decision and records audit-chain entries for the
supersession and replacement. `evidence_ids` may reference tenant-scoped
supporting evidence from the same release; foreign-tenant or wrong-release
evidence links are rejected. `vex_document_id` can link a manual decision to an
imported VEX document from the same release, including cases where automated VEX
mapping did not create a decision.

Decision history:

```http
GET /v1/vulnerability-decisions?release_id=rel_...&vulnerability=CVE-2026-0099&active=true
```

The history endpoint supports `product_id`, `release_id`, `vulnerability`,
`component`, `status`, and `active` filters. It returns append-only decision
records, including timestamps and supersession fields. It is tenant-scoped and
requires `evidence:read`. In PostgreSQL mode, current product/release grants and
filters are applied before bounded keyset pagination. The response excludes
tenant-internal `internal_notes`; local-memory mode retains the compatibility
reader.

VEX import parser report:

```http
GET /v1/vex/{id}/import-report
```

The import report records parser version, statement counts, decision counts,
supersession counts, warnings, invalid statement issues, and mapping failures.
Every upload starts as `accepted`; the `parse_vex` worker creates any mapped
decisions from a bounded versioned request after the upload transaction commits
and changes the report to `parsed` or `failed`. When durable object storage is
available, the worker also reparses the raw payload and rejects a normalized
request that does not match it. Without a replayable object, decision processing
still occurs from the normalized request, but independent raw-payload replay is
not available. Upload never writes vulnerability decisions directly.
When worker replay fails it records safe `failure_code` and `failure_detail`
fields. It does not include raw VEX payload bytes, object-store payload
references, backend error strings, or bearer tokens.

VEX import preview:

```http
POST /v1/vex/preview
POST /v1/vex/cyclonedx/preview
```

Preview validates OpenVEX or CycloneDX VEX payloads and returns advisory
mapping counts, warnings, invalid-statement issues, and mapping failures. It
does not store raw payloads, create evidence, create decisions, or enqueue
worker jobs, so it does not require `Idempotency-Key`.

Customer-safe decision summary:

```http
GET /v1/reports/vulnerability-decision-summary?release_id=rel_...
```

The summary endpoint returns only active decisions marked `customer_visible`.
It excludes `internal_notes`, raw payload bytes, object-store references, bearer
tokens, and private review context. The response includes assumptions and
limitations and is intended for package viewers and exports. `release_id` is
required; blank, duplicate, and unknown query parameters are rejected. In
PostgreSQL mode, one release-scoped read snapshot checks current `report:read`
grants before selecting customer-visible decisions. Local-memory mode keeps
the compatibility reader.

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

Readiness is deterministic and evidence-scoped. It reports checks, reviewer
question sections, missing evidence, failed policy checks, blockers, gaps,
assumptions, non-claims, and limitations; it is not a legal compliance or
release-security conclusion.

The default `policy-set.v1.0.0` release checks require release-linked artifact
and digest evidence, SBOM evidence, vulnerability-scan evidence, handled open
critical/high findings, review-safe customer-visible decisions, justifications
for `not_affected` decisions, complete exception metadata, passed build
provenance, build-attestation subject coverage, a signed release bundle, and
valid redaction profiles for generated customer packages. Failed checks include
`remediation` text with the next evidence action to take.

## Authentication And Scopes

API keys and collector keys are tenant-scoped bearer secrets. Human SSO session actors derive scopes from role bindings and enforce resource constraints where those resources are part of the request.

Important scope boundaries:

| Boundary | Behavior |
|----------|----------|
| Tenant data | Cross-tenant reads return `404` where applicable. |
| Collector identity | Build attribution is derived from the authenticated collector key; clients must not submit `collector_id` for build attribution. |
| Instance admin | `GET /v1/admin/instance` and `GET /v1/admin/readiness` require explicit `instance:admin`; tenant admin and ordinary wildcard tenant keys are insufficient. |
| Customer portal | `POST /v1/customer-portal/package` and `/v1/customer-portal/package/download` are public token exchange endpoints and intentionally do not use bearer authentication. Optional NDA acceptance and distribution watermarks are recorded without storing supplied tokens. Successful exchanges and downloads are visible through the tenant audit log without storing the supplied token. |

## Endpoint Catalog

### System

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/v1/health` | Process liveness; does not probe dependencies. |
| `GET` | `/v1/ready` | Low-detail dependency readiness; returns `503` if a required dependency is unavailable. |
| `GET` | `/v1/version` | Immutable build identity and release-input-manifest digest. |
| `GET` | `/v1/metrics` | Tenant-safe counts; admin scope required. |
| `GET` | `/v1/openapi.json` | Generated OpenAPI. |
| `GET` | `/v1/admin/instance` | Low-detail instance counts from one PostgreSQL snapshot in the durable profile; explicit `instance:admin` required. No tenant identifiers, evidence payloads, or credential material are returned. |
| `GET` | `/v1/admin/readiness` | Vetted readiness diagnostics; `instance:admin` required. |

### Identity And Administration

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/organizations` | Create tenant-scoped organization. |
| `POST` | `/v1/users` | Create normalized human user. |
| `POST` | `/v1/users/{id}/deactivate` | Record deactivation transition. |
| `POST` | `/v1/role-bindings` | Assign role to user or collector. |
| `GET` | `/v1/role-bindings` | Page tenant-scoped bindings; `identity:admin` (or admin) scope and a tenant-wide grant for human sessions are required. |
| `POST` | `/v1/sso/providers` | Record OIDC or SAML provider metadata. |
| `POST` | `/v1/sso/providers/{id}/trust-material` | Rotate OIDC JWKS or SAML signing certificates used for local verification. |
| `POST` | `/v1/sso/providers/{id}/discover-oidc` | Fetch OIDC discovery metadata and refresh public JWKS trust material. |
| `POST` | `/v1/sso/identity-links` | Link verified provider subject to user. |
| `POST` | `/v1/sso/sessions` | Issue one-time session secret. |
| `POST` | `/v1/sso/session-exchanges` | Exchange a locally verified OIDC ID token or SAML assertion for a session secret and HttpOnly cookie. |
| `POST` | `/v1/sso/sessions/{id}/revoke` | Revoke session. |
| `POST` | `/v1/sso/logout` | Revoke the currently authenticated SSO session. |
| `POST` | `/v1/api-keys` | Create one-time API key secret. |
| `GET` | `/v1/api-keys` | Page tenant keys without secret hashes; admin scope and a tenant-wide grant for human sessions are required. |

Current SSO endpoints model admin-managed provider, identity-link, trust-material, and session records plus API-first session logout. OIDC provider records can include public JWKS material, and SAML provider records can include PEM-encoded assertion signing certificates; both can be rotated through `POST /v1/sso/providers/{id}/trust-material`. OIDC public JWKS can also be refreshed from the configured issuer with `POST /v1/sso/providers/{id}/discover-oidc`. `POST /v1/provider-verifications` can verify a supplied OIDC ID token or SAML assertion locally for issuer, audience, subject, time bounds, and signature. When an OIDC `access_token` is supplied, the same endpoint can call either the provider's discovered UserInfo endpoint or a configured operator-controlled provider validation gateway, verify the returned subject, and record any configured group-claim mapping checks without storing the access token. The provider validation gateway receives only non-secret request metadata and an `access_token_present` flag, not the supplied token. `POST /v1/sso/session-exchanges` uses local token/assertion verification and a verified identity link to issue a one-time SSO bearer secret and an HttpOnly cookie for browser clients. OIDC group claim values can map to session-scoped roles through the provider `groups_claim` and `role_mapping`; no permanent role binding is created from token claims. External group synchronization into permanent role bindings is not implemented in this slice.

### Products, Releases, Evidence, And Risk

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/products` | Create product. |
| `GET` | `/v1/products` | List products. |
| `GET` | `/v1/products/{id}` | Read product. |
| `POST` | `/v1/projects` | Create project under product. |
| `GET` | `/v1/projects/{id}` | Read project. |
| `POST` | `/v1/releases` | Create release. |
| `GET` | `/v1/releases/{id}` | Read release. |
| `POST` | `/v1/releases/{id}/evidence-flow/start` | Read high-level release evidence workflow plan. |
| `GET` | `/v1/releases/{id}/security-summary` | Read customer-safe release security summary status. |
| `POST` | `/v1/releases/{id}/freeze` | Append freeze transition; requires `If-Match` with current revision. |
| `POST` | `/v1/releases/{id}/approve` | Append approval transition; requires `If-Match` with current revision. |
| `POST` | `/v1/artifacts` | Register artifact digest metadata. |
| `GET` | `/v1/artifacts/{id}` | Read artifact digest metadata. |
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
| `GET` | `/v1/sboms/{id}` | Read one SBOM and its stored components when parsed; accepted pending records can have an empty spec version and no components. PostgreSQL validates tenant-owned source evidence, release, artifact, and matching source artifact reference before resource-grant authorization. |
| `GET` | `/v1/sbom-components` | Page stored SBOM components by SBOM, release, artifact, query, and exact PURL; `limit` is a transitional alias for `page_size`. PostgreSQL applies current tenant and grant filters before pagination. |
| `POST` | `/v1/sbom-diffs` | Compare stored SBOMs. |
| `POST` | `/v1/vulnerability-scans` | Upload normalized vulnerability scan. |
| `GET` | `/v1/vulnerability-scans/{id}` | Read one scan and its stored findings when parsed; accepted pending records have empty parser fields. PostgreSQL validates tenant-owned source evidence and current release/product ownership before resource-grant authorization. Scanner coverage is not independently verified. |
| `POST` | `/v1/vulnerability-findings/{id}/decisions` | Superseding decision record. |
| `GET` | `/v1/vulnerability-decisions` | List decision history by product, release, vulnerability, component, status, and active state. |
| `POST` | `/v1/vulnerability-findings/{id}/workflow` | Append workflow event. |
| `GET` | `/v1/reports/vulnerability-posture` | Aggregate stored scan-finding severities and open-critical counts. Optional single `release_id` filters one tenant-owned release; without it, human sessions need a tenant-wide `security:read` grant. This does not include decisions or VEX and does not verify scanner coverage. |
| `GET` | `/v1/reports/vulnerability-decision-summary` | Customer-safe active vulnerability decision summary for a release. |
| `GET` | `/v1/reports/release-readiness` | Deterministic readiness report. |
| `GET` | `/v1/reports/missing-evidence` | Missing evidence report for review. |
| `POST` | `/v1/reports/anomaly` | Generate deterministic evidence anomaly signals. |
| `POST` | `/v1/release-candidates` | Create release candidate. |
| `GET` | `/v1/release-candidates` | List release candidates. |
| `GET` | `/v1/release-candidates/{id}` | Read release candidate. |
| `POST` | `/v1/release-candidates/{id}/promote` | Promote release candidate; requires `If-Match` with current revision. |
| `POST` | `/v1/release-candidates/{id}/reject` | Reject release candidate; requires `If-Match` with current revision. |
| `POST` | `/v1/remediation-tasks` | Create remediation task. |

### Instance Outbox Operations

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/v1/admin/outbox` | Payload-free outbox backlog and terminal-job diagnostics; requires explicit `instance:admin`. |
| `POST` | `/v1/admin/outbox/{id}/replay` | Replay one terminal outbox job with `Idempotency-Key`; requires explicit `instance:admin` and appends an audit record. |

### CI, Source, Deployment, And Collectors

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/collectors` | Create collector and one-time key. |
| `GET` | `/v1/collectors` | List collectors without secrets. Human sessions need a current tenant-level `collector:read` grant; scoped credentials need that issued scope. |
| `POST` | `/v1/collectors/{id}/releases` | Record collector release evidence. |
| `GET` | `/v1/collectors/{id}/health` | Collector health report from current tenant-owned collector and latest/pinned release records. Human sessions require a tenant-wide `collector:read` grant; the report does not prove runtime integrity or vulnerability absence. |
| `POST` | `/v1/commercial-collectors` | Create commercial collector definition. |
| `GET` | `/v1/commercial-collectors` | List tenant-owned commercial collector definitions; human sessions need a tenant-level `collector:read` grant. |
| `POST` | `/v1/marketplace-collectors` | Register marketplace collector package metadata. |
| `GET` | `/v1/marketplace-collectors` | Keyset-page tenant-owned marketplace collector package records. Human sessions need a current tenant-level `collector:read` grant; PostgreSQL mode limits rows in SQL. |
| `GET` | `/v1/marketplace-collectors/{id}/health` | Review marketplace collector package evidence gaps from current tenant-owned signature, SBOM, and scan references. Reference presence is not proof of package safety or provider endorsement. |
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

### Deployment Environment Creation

`POST /v1/environments` in the PostgreSQL profile uses a focused command with
`deployment:write` authorization. Human sessions need a current tenant or
product grant; release/project-only grants do not authorize creation of a
product-wide environment. The product lookup is tenant-scoped and selects only
identity, not product metadata or all environments.

The normalized `(tenant, product_id, name)` identifies an environment. Requests
for an existing name return the original row, including its original `kind`,
without another audit entry. PostgreSQL serializes name reuse with a product-row
no-key-update lock, including the initially empty set. Different tenant or
product identities cannot reuse that row. Creation and its audit append commit
atomically with HTTP idempotency state; replay adds no effects and creates no
outbox job. `deployment-environment.v1.0.0` and response fields are unchanged.

Tenant/product IDs are bounded at 1024 bytes and kind text at 64 KiB. The sum
of tenant ID, product ID and normalized name is limited to 2304 UTF-8 bytes,
so the unique PostgreSQL key fits without relying on text compression. This
rejects oversized names with validation instead of a database insertion error;
historical rows are not changed. The existing 64 KiB HTTP JSON-envelope limit
still applies. Required text is trimmed and
must be non-empty, valid UTF-8 and NUL-free. Non-object envelopes, explicit
nulls, duplicate fields and unknown fields are rejected. Oversized stored
environment metadata fails with conflict rather than returning a truncated row.
The environment is metadata, not evidence that an actual deployment occurred.
Explicit local-memory mode retains its compatibility path.

Source/test evidence: `internal/operations/app/deployment_environment_commands.go`,
`internal/platform/wiring/deployment_environment_commands_test.go` and
`internal/adapters/httpapi/deployment_environment_commands_test.go`.

### Deployment Event Recording

`POST /v1/deployments` in the PostgreSQL profile uses an Operations-owned
command. It requires `deployment:write`, without a hidden `evidence:write`
requirement. Human sessions need a current tenant, product or release grant;
project/environment-only grants do not authorize recording. Bounded,
transaction-scoped identity reads check that the environment and release share
the tenant and product, each artifact belongs to the tenant, and an optional
rollback target belongs to the same tenant and environment. Unrelated resource
metadata and tenant collections are not loaded.

The deployment, fixed `deployment/event` evidence and two audit entries commit
together with HTTP replay state. The returned `evidence_id` is immediately
readable by an actor with the appropriate evidence-read grant. Any write or
commit failure rolls all effects back; replay adds none, and a changed request
body with the same key conflicts. This operation creates no outbox job or raw
payload. The synchronous fixed-shape bridge is the explicit ADR 0003 exception;
it does not allow arbitrary evidence mutations. EVY-906 owns its future saga
transition.

Reference IDs are non-empty, NUL-free UTF-8 text bounded at 1024 bytes. Artifact
lists are limited to 1024 supplied entries, normalized and sorted while
preserving duplicate IDs. Status remains `started`, `succeeded`, `failed` or
`rolled_back`. Omitted `started_at` defaults to command time; supplied times are
normalized to UTC and PostgreSQL microsecond precision before evidence hashing.
No new timestamp-ordering rule is imposed. JSON nulls, null artifact elements,
duplicate/unknown fields and non-object envelopes are rejected; the existing
64 KiB HTTP envelope limit remains. Event/evidence schemas, response fields,
metadata-only limitations and canonicalization profile are unchanged; historical
rows are not rewritten. Recording does not prove runtime security or availability.
Explicit local-memory mode retains its compatibility path.

Source/test evidence: `internal/operations/app/deployment_commands.go`,
`internal/evidence/app/deployment_evidence.go`,
`internal/platform/wiring/deployment_commands_test.go` and
`internal/adapters/httpapi/deployment_commands_test.go`.

### Controls, Reports, Packages, And Governance

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/control-frameworks` | Create framework version. |
| `GET` | `/v1/control-frameworks` | List frameworks. Human sessions need a current tenant-level `controls:read` grant; scoped credentials need that issued scope. |
| `GET` | `/v1/control-framework-template-packs` | List built-in starter packs. |
| `POST` | `/v1/control-framework-template-packs/{slug}/install` | Copy starter pack to tenant records. |
| `POST` | `/v1/controls` | Create control. |
| `GET` | `/v1/controls/{id}` | Read a control through its tenant-owned framework; uses the same `controls:read` grant rule. |
| `POST` | `/v1/controls/{id}/evidence` | Append control evidence link. |
| `GET` | `/v1/control-evidence` | Keyset-page tenant/grant-visible links whose control, framework, scope, and current subject ownership still resolve. Supports `control_id`, `product_id`, and `release_id` filters. PostgreSQL applies visibility before the page limit; local-memory mode uses the Ledger compatibility reader. |
| `GET` | `/v1/reports/control-coverage` | Deterministic control coverage. |
| `GET` | `/v1/reports/cra-readiness` | Technical evidence readiness report with limitations. |
| `GET` | `/v1/reports/cra-vulnerability-handling` | CRA-oriented vulnerability handling evidence report with limitations. |
| `GET` | `/v1/reports/security-update-evidence` | Release-scoped security update evidence report with limitations. |
| `POST` | `/v1/exceptions` | Create exception. |
| `POST` | `/v1/exceptions/{id}/approve` | Approve exception. |
| `GET` | `/v1/exceptions` | Page exceptions within current `verify:read` product/release grants; an unknown filtered release returns `404`, and an existing release outside those grants returns `403`. PostgreSQL filters grants before the keyset limit. |
| `POST` | `/v1/waivers` | Create waiver. |
| `POST` | `/v1/waivers/{id}/approve` | Approve waiver. |
| `POST` | `/v1/approvals` | Create immutable approval record. |
| `POST` | `/v1/redaction-profiles` | Create package redaction profile. |
| `POST` | `/v1/customer-packages` | Create scoped customer package manifest. |
| `GET` | `/v1/customer-packages/{id}` | Read package manifest and record access. |
| `GET` | `/v1/customer-packages/{id}/download` | Download scoped ZIP package with manifest metadata and verification guidance. |
| `POST` | `/v1/customer-portal/access` | Create named external reviewer access with one-time package token. |
| `GET` | `/v1/customer-portal/access` | List grant-visible external reviewer access records without token hashes or secrets. |
| `POST` | `/v1/customer-portal/access/{id}/revoke` | Revoke an external reviewer access record. |
| `POST` | `/v1/customer-portal/package` | Exchange package token for scoped manifest. |
| `POST` | `/v1/customer-portal/package/download` | Exchange package token for scoped ZIP package download. |
| `GET` | `/v1/customer-portal/package/view` | Render public token-entry page for scoped package review. |
| `POST` | `/v1/customer-portal/package/view` | Exchange package token from a form body for scoped HTML package review. |
| `POST` | `/v1/customer-portal/package/view/download` | Exchange package token from a form body for scoped ZIP package download. |

| `POST` | `/v1/questionnaire-templates` | Create questionnaire template. |
| `POST` | `/v1/questionnaire-packages` | Generate evidence-backed responses. |
| `POST` | `/v1/questionnaire-drafts` | Create evidence-backed draft answers for review. |
| `GET` | `/v1/questionnaire-answer-library` | List reusable questionnaire answer drafts. |
| `POST` | `/v1/questionnaire-answer-library` | Create reusable questionnaire answer draft. |
| `GET` | `/v1/reports/security-review-package` | Redaction-aware package report. |
| `GET` | `/v1/reports/cra-readiness-html` | HTML CRA-readiness review content. |
| `POST` | `/v1/reports/pdf` | Create reproducible PDF report package metadata and payload hash. |
| `GET` | `/v1/reports/incident-package` | Incident package report. |
| `POST` | `/v1/report-templates` | Create allowed-field template. |
| `POST` | `/v1/report-templates/{id}/render` | Render deterministic JSON report. |
| `POST` | `/v1/incidents` | Create incident. |
| `POST` | `/v1/incidents/{id}/timeline` | Append incident timeline event. |
| `POST` | `/v1/incidents/{id}/webhook-receivers` | Create incident-scoped Ed25519 webhook receiver. |
| `POST` | `/v1/incident-webhooks/{receiver_id}` | Receive signed incident timeline webhook without bearer authentication. |

The customer-portal access list requires `package:read` and a current tenant, product, release, or customer-package grant for human sessions. An existing `package_id` outside the caller's grants returns `403`; a missing or cross-tenant package returns `404` when the caller has at least one applicable resource grant. Without any grant, a filtered request fails with `403` before package lookup. PostgreSQL mode applies tenant and grant filters before keyset pagination in one read-only snapshot and does not select token hashes. Local-memory mode applies the same grant visibility before returning records, but retains its compatibility pagination path.

Questionnaire answer drafts are scoped per entry. A human session with a
product or release grant can read and create only drafts in that scope; drafts
without a product or release require a tenant grant. Filtering a list does not
broaden the caller's grant. Issued credentials still require `package:read` or
`package:write` as applicable. The PostgreSQL profile applies tenant, current
parent, linked-control/evidence, and grant filters before the page limit;
product and release filters must agree on the current tenant-owned parent.
Local-memory mode retains per-entry grant checks but uses an in-memory page.

Customer package manifests use the documented
[`customer-security-package.v2.0.0`](reference/customer-package-manifest.md)
schema. They include scoped release metadata, evidence summaries, redaction
profile details, readiness checks, verification material, limitations, and
non-claims while excluding raw payload bytes, object-store references, secrets,
token hashes, and internal decision notes. Redaction profiles can be created
from explicit `allowed_types` or the `customer_safe` / `security_review`
presets; preset policy fields cannot be overridden in the create request.

### Integrity, Verification, And Operations

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/release-bundles` | Create signed release bundle. |
| `GET` | `/v1/release-bundles/{id}` | Read a tenant-owned bundle with a current release and `bundle:read` grant. |
| `GET` | `/v1/release-bundles/{id}/manifest` | Read its manifest under the same grant. |
| `GET` | `/v1/release-bundles/{id}/verify` | Verify bundle. |
| `POST` | `/v1/evidence-bundles` | Export evidence bundle. |
| `POST` | `/v1/evidence-bundles/import` | Import evidence bundle. |
| `POST` | `/v1/verify` | Verify supported subject types. |
| `GET` | `/v1/audit-chain/verify` | Verify tenant audit chain. |
| `GET` | `/v1/audit-log` | List tenant audit entries; admin scope required, including a tenant-wide grant for human sessions. |
| `GET` | `/v1/signing-keys` | List tenant signing-key public metadata; `verify:read` and a tenant-level grant are required for human sessions. |
| `POST` | `/v1/signing-keys/rotate` | Rotate signing key. |
| `POST` | `/v1/signing-keys/{id}/revoke` | Revoke key for new signatures. |
| `POST` | `/v1/signing-providers` | Record external signing-provider metadata. |
| `POST` | `/v1/signing-operations` | Record external signing-provider operation receipt and signature ref. |
| `POST` | `/v1/provider-verifications` | Verify stored provider identity metadata and optional local OIDC ID-token signature/claims. |
| `POST` | `/v1/saas/profiles` | Create explicit-instance-admin SaaS edition profile record. |
| `POST` | `/v1/artifact-signatures` | Create artifact signature metadata. |
| `GET` | `/v1/artifact-signatures/{id}` | Read a tenant-owned artifact signature with a current artifact/digest and scoped association. |
| `POST` | `/v1/artifact-signatures/{id}/verify-cosign` | Verify a finalized offline Sigstore/Cosign bundle against configured trust material and explicit policy inputs. |
| `POST` | `/v1/merkle-batches` | Create signed checkpoint batch. |
| `GET` | `/v1/merkle-batches/{id}/verify` | Verify batch. |
| `POST` | `/v1/transparency-checkpoints` | Record external anchoring metadata. |
| `POST` | `/v1/public-transparency-logs` | Record optional public transparency log configuration. |
| `POST` | `/v1/public-transparency-log-entries` | Record published public transparency log entry metadata. |
| `POST` | `/v1/public-transparency-log-entries/{id}/verify` | Verify operator-supplied RFC6962-style public transparency inclusion proof material. |
| `POST` | `/v1/public-transparency-log-entries/{id}/fetch-proof` | Fetch proof material from the configured transparency endpoint or proof gateway and verify it locally. |
| `POST` | `/v1/object-retention-policies` | Record retention policy intent, optional tenant-prefixed sample object/legal-hold proof requirement, and maximum provider-observation age. |
| `POST` | `/v1/object-retention-policies/{id}/verify` | Record a provider observation without treating local intent as provider enforcement. |
| `POST` | `/v1/legal-holds` | Record legal hold. |
| `POST` | `/v1/retention-overrides` | Record retention override. |
| `GET` | `/v1/reports/retention` | List retention records. |
| `GET` | `/v1/reports/custody-review` | Review tenant signing-provider and object-lock verification metadata for deployment custody review. |
| `POST` | `/v1/backup-manifests` | Generate backup manifest. |
| `GET` | `/v1/backup-manifests/{id}/verify` | Verify backup manifest. |

The signing-key list pages public lifecycle metadata by tenant in PostgreSQL. It does not select encrypted private key bytes; local-memory mode retains the compatibility list and in-memory pagination. A human session must have a current tenant-level `verify:read` grant, while issued credentials use their `verify:read` scope.

In the PostgreSQL profile, both release-bundle reads use a single bundle/release/product
database statement. A human session needs a current tenant, product, or release
`bundle:read` grant; issued credentials use their `bundle:read` scope. A bundle
with a missing or cross-tenant release is not returned. The manifest response
shape is unchanged, and local-memory mode retains its Ledger-backed path.

In the PostgreSQL profile, `GET /v1/artifact-signatures/{id}` reads one
signature and its current artifact in one database statement. A human session
needs an `evidence:read` grant covering a current evidence or build association
with that artifact; a tenant grant or issued credential with `evidence:read`
does not need a narrower association. The existing response can include a
`payload_ref`, so treat it as tenant-scoped metadata rather than a public
object URL. Local-memory mode retains its Ledger-backed authorization path.

In the PostgreSQL profile, `GET /v1/artifacts/{id}` reads artifact metadata
without loading tenant-wide Ledger state. Human sessions need an `evidence:read`
grant for the tenant or a current evidence/build association to the artifact
within a granted product, project, or release. A build association must match
the artifact digest. Issued credentials remain scope-bound, and local-memory
mode retains the Ledger-backed read. The response shape is unchanged.

`POST /v1/artifact-signatures/{id}/verify-cosign` verifies a finalized stored
Sigstore bundle. Requests use `mode`, `offline`, and—for `keyless`—exact
`expected_identity` and `expected_issuer` values. The implemented profile
requires `offline: true`, configured operator trust material, an artifact-digest
match, signature verification, and an embedded Rekor inclusion proof. It does
not silently fetch or downgrade to metadata when an online profile is required.
Without configured trust material, the route returns `422` with
`COSIGN_FULL_VERIFICATION_UNAVAILABLE`.

All result-bearing verification APIs use the versioned machine-state taxonomy
and include an assurance profile plus limitations. `passed` is emitted only
when every profile-required check passed; it is not a broad security or
compliance claim. See [Verification results](reference/verification-results.md)
for the state definitions, profile fields, and legacy-record behavior.

Object-retention policy status is scoped to the retention observation rather
than the generic verification-result taxonomy. `configured` records intent;
`not_verified` covers missing, unavailable, or incomplete provider evidence;
`not_enforced` records a completed provider observation that did not satisfy
the requested condition; `verified` is a complete, time-bounded provider
observation; and `stale` must be refreshed before it is treated as current.
The response records the configured maximum age and, for an observed result,
provider, bucket, mode, duration, applicable legal-hold state, observation
time, expiry, checks, and limitations. These records support operator review;
they do not establish legal compliance or complete WORM enforcement.

### Security Evidence And Contracts

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/security-scans` | Upload SAST, DAST, secret scan, license scan, or API-security scan JSON. |
| `POST` | `/v1/api-security-scans` | Convenience API-security scan route. |
| `POST` | `/v1/security-documents` | Upload sensitive manual security document metadata/payload. |
| `POST` | `/v1/vex` | Upload OpenVEX; decisions are mapped asynchronously by the worker. |
| `POST` | `/v1/vex/preview` | Preview OpenVEX mapping without storing evidence. |
| `POST` | `/v1/vex/cyclonedx` | Upload CycloneDX VEX; decisions are mapped asynchronously by the worker. |
| `POST` | `/v1/vex/cyclonedx/preview` | Preview CycloneDX VEX mapping without storing evidence. |
| `GET` | `/v1/vex/{id}` | Read VEX metadata. PostgreSQL validates current tenant-owned source evidence, release, artifact, and matching artifact subject before resource-grant authorization. |
| `GET` | `/v1/vex/{id}/import-report` | Read the VEX parser report with counts, warnings, and mapping failures. PostgreSQL validates the document and report linkage in one snapshot; missing or ambiguous reports fail closed. |
| `POST` | `/v1/openapi-contracts` | Upload OpenAPI contract. |
| `GET` | `/v1/openapi-contracts/{id}` | Read contract metadata. |
| `POST` | `/v1/openapi-diffs` | Compare stored contracts. |
| `POST` | `/v1/policies/evaluate` | Evaluate built-in release policy. |
| `POST` | `/v1/custom-policies` | Create deterministic custom policy. |
| `POST` | `/v1/custom-policies/{id}/evaluate` | Store replayable policy evaluation. |

In the PostgreSQL profile, an OpenAPI-contract read requires its stored source
evidence, product, and optional release to resolve under the same tenant and
product. Human sessions need a current `evidence:read` grant for the product
or release; issued credentials remain scope-bound. Local-memory mode retains
the Ledger-backed read. The response shape is unchanged.

## Current Contract Limitations

- `openapi.yaml` is generated as compact JSON-style YAML and is optimized for drift checks and tooling, not prose review.
- The current OpenAPI precision gate reports every registered public operation
  as precise. New or changed routes should add endpoint-specific request,
  response, parameter, auth-scope, idempotency, and error metadata before they
  are merged.
- Operation-level examples are maintained here and in tests until the generator emits richer examples.
- OpenAPI diffing classifies operation removal/addition, required request-body and request-field changes, response status changes, and broad path-count fallback for older stored contracts.

These limitations should be called out in release evidence when API contract review is part of the release process.
