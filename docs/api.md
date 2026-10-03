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

Conditional release and release-candidate actions also bind the canonical
`If-Match` revision into that digest and validate the header before replay.
Changing the revision with the same key returns `409 IDEMPOTENCY_KEY_REUSED`;
an invalid or missing header returns `400` even for a completed key. Completed
conditional-action keys created by older versions using only a body digest
cannot be replayed under the stronger fingerprint: read the current resource
before retrying with a new key and its current revision. Do not blindly repeat
an action whose earlier outcome is unknown.

Native document uploads also bind their media type and relationship/version
headers into the request digest. During the bounded retention window, a retry
of a record created before those headers were included can fall back to the
legacy body-only digest only after the current fingerprint conflicts. Newly
created records always retain the stronger fingerprint, so changing a semantic
header while reusing their key still returns a conflict.

In PostgreSQL mode, retained native OpenAPI upload receipts additionally require
the original tenant, product, release, version, and payload hash to match. Native
SBOM receipts require the original tenant, release, optional artifact, and
format. A body-only receipt with different or missing required coordinates
returns `409`; it never executes a new upload. Current ownership and grants are
checked before replay.

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

In the PostgreSQL profile, freeze and approval use focused durable commands,
not cached Ledger release state. They require `release:write` and, for human
sessions, a matching tenant, product, or release grant. The locked transaction
checks current parent ownership, authorization, revision, and state; the state
change and audit entry commit together. Draft freeze advances the revision by
one and sets `frozen_at`; frozen approval advances it once more and sets
`approved_at`, preserving the immutable release metadata and freeze time.
Foreign releases return `404`; grant denial returns `403` without revision
metadata. Transition reads bound IDs to 1024 UTF-8 bytes and stored release
versions/product slugs to 64 KiB, rejecting oversized stored fields with a
conflict rather than returning truncated values. Local-memory mode keeps its
explicit compatibility binding.

In the PostgreSQL profile, candidate promotion/rejection uses a focused durable
command with one locked candidate and its current tenant-owned release/product
coordinate. It requires `release:write`; human sessions also need a matching
tenant, product, or release grant. Grant denial returns `403` without current
revision metadata; a foreign or dangling-parent candidate returns `404`.
Only an `open` candidate at the expected revision can transition, advancing
the revision once and setting `promoted_at` or `rejected_at`. The candidate's
name, reference lists, snapshot hash, schema version, and creation metadata
remain unchanged, and the state change and audit append commit together.

The request `reason` is required, trimmed, non-empty, NUL-free UTF-8 and at most
64 KiB of UTF-8 bytes; the entire HTTP JSON body is also capped at 64 KiB.
Stored candidate names are bounded at 64 KiB, IDs/schema identifiers at 1024
bytes, state at 32 bytes, hash at 128 bytes, and the JSON snapshot at 1 MiB.
Oversized or malformed stored snapshots return `409` rather than truncated
values. Transition times use microsecond-precision UTC. Local-memory mode
keeps its compatibility binding.

Candidate creation in PostgreSQL also uses a focused durable command. It
requires `release:write` and, for human sessions, a matching tenant, product,
or release grant. The active transaction verifies current tenant-owned parent
coordinates and every supplied build, artifact, SBOM, scan, VEX, OpenAPI, and
bundle ID. Builds and parsed evidence/bundle records must belong to the same
release; artifacts are tenant-scoped and human reuse additionally requires a
current authorized build/evidence association. Missing, foreign, wrong-release,
or inconsistent source-evidence references return `404`; grant denial returns
`403`. Validation does not read foreign-context payloads or cached Ledger maps.

Names and identifiers are trimmed, non-empty, NUL-free UTF-8. New names are
bounded at 64 KiB, and parent/reference IDs at 1024 UTF-8 bytes. The seven
reference arrays together are limited to 4096 entries and 64 KiB of identifier
bytes; sorting preserves duplicate IDs. The entire HTTP JSON body is limited
to 64 KiB, including syntax and escapes. Invalid input returns `400` without
candidate/audit writes. A new candidate starts `open` at revision 1, with a
microsecond-precision UTC timestamp and the existing versioned normalized-JSON
snapshot hash. Candidate and audit effects commit together. Same-key replay
returns the original candidate; changed request bytes with that key conflict.
Local-memory creation retains its compatibility binding.

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

Product slugs are trimmed and must contain no more than 1024 UTF-8 bytes. Longer
slugs return `400 VALIDATION_FAILED` before a database write; this limit keeps
the per-tenant natural identity within the supported PostgreSQL index budget.

Product create, read, and list responses contain `id`, `tenant_id`, `name`,
`slug`, and `created_at`. They do not return `schema_version`; the corrected
OpenAPI schema no longer advertises or requires that unsupported field.

In the PostgreSQL profile, product creation uses a focused durable command,
not cached Ledger products. It requires `product:write`; human sessions also
need a matching tenant-level grant, not a grant on an existing product. The
write transaction rechecks authorization before testing the tenant's slug
identity through a boolean existence query. Product and audit effects commit
together. A different-key request for an existing tenant/slug returns `409`;
same-key replay returns the original product, while changed request bytes
with that key conflict. Different tenants can use the same slug.

Names and slugs are trimmed, non-empty, NUL-free UTF-8. New names are bounded
at 64 KiB of UTF-8 bytes and slugs at 1024 bytes; the entire HTTP JSON body is
also limited to 64 KiB, including JSON syntax and escapes. Invalid input
returns `400` without product/audit writes. Creation timestamps use UTC at
microsecond precision. Explicit local-memory mode retains its compatibility
binding.

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

Project creation accepts only `product_id` and `name`; `slug` is not supported.
Project responses contain `id`, `tenant_id`, `product_id`, `name`, and
`created_at`, not a slug or schema-version field. The generated schemas now
match this existing runtime contract; clients generated from older schemas
must stop sending the previously advertised project `slug`.

In the PostgreSQL profile, project creation uses current durable product
coordinates, not cached Ledger products. It requires `project:write`; human
sessions also need a tenant or matching product grant, not just a grant on an
existing project. The product is tenant-filtered and rechecked inside the write
transaction, and project/audit effects commit together. Same-key replay returns
the original project; changed request bytes with that key conflict.

Product IDs and names are trimmed and must be non-empty. Product IDs are bounded
at 1024 UTF-8 bytes, and new project names at 64 KiB of UTF-8 bytes; both must be
valid UTF-8 and NUL-free. Unsupported input returns `400` without project/audit
writes. Oversized stored parent coordinates return `409`, never truncated
values. Explicit local-memory mode retains its compatibility path.

```json
{"product_id":"prod_...","version":"1.0.0"}
```

In the PostgreSQL profile, release creation uses current durable product
coordinates and a version-existence check, not cached Ledger products or
releases. It requires `release:write`; human sessions also need a tenant or
matching product grant. A new release starts in `draft` at revision `1`.
Versions are unique within each product: a different-key request for an existing
version returns `409`; same-key replay returns the original release, while
changed request bytes with that key conflict. Release/audit effects commit
together, and product coordinates are rechecked in the write transaction.

Product IDs and versions are trimmed and must be non-empty, NUL-free UTF-8.
Product IDs are bounded at 1024 UTF-8 bytes and new release versions at 64 KiB
of UTF-8 bytes. Unsupported input returns `400` without release/audit writes;
oversized stored parent coordinates return `409`, never truncated values.
Explicit local-memory mode retains its compatibility path. Recording a release
does not assert approval, verification, or compliance.

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

In the PostgreSQL profile, `POST /v1/artifacts` registers metadata through a
focused durable command, without reading or updating cached Ledger artifacts.
It requires `evidence:write`. Reuse of a tenant's existing digest also requires
current artifact access: for human sessions, a tenant grant or a matching
evidence/build association authorized by their resource grants. Reuse returns
the original immutable name, media type, size, and timestamp without another
audit entry; submitted metadata does not amend that record. Same-key replay
returns the original result, while changed request bytes with that key conflict.

Names and media types are trimmed and must be non-empty. The digest must be
`sha256:` followed by 64 hexadecimal digits; size must be non-negative and
defaults to zero when omitted. New stored names and media types must be NUL-free
UTF-8, each at most 64 KiB of UTF-8 bytes. Unsupported new storage text returns
`400`; oversized existing metadata returns `409`, never truncated values.
Explicit local-memory mode keeps its compatibility path. Registration records
declared metadata only: it does not upload bytes or establish digest, signature,
or provenance trust.

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

PostgreSQL manual creation and idempotency replay use current resource grants
and one durable transaction without reloading Ledger state. See the
[decision lifecycle reference](reference/vulnerability-decisions.md#canonical-lifecycle)
for input bounds, append-only storage, and local-memory compatibility limits.

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

### SBOM Ingestion

`POST /v1/sboms` (CycloneDX) and `POST /v1/sboms/spdx` require
`evidence:write`. Wrapped JSON supplies `release_id`, optional `artifact_id`,
and `payload` within the existing 64 KiB request limit. Native
`application/vnd.cyclonedx+json` or `application/spdx+json` uploads stream up to
20 MiB and require a single, nonblank `X-Evydence-Release-ID`; the single
`X-Evydence-Artifact-ID` is optional. Explicit null fields, duplicate wrapped
fields or native metadata headers, and unknown wrapped fields are rejected.
IDs are limited to 1024 UTF-8 bytes; required IDs must be nonblank and all IDs
must exclude NUL. See [evidence-format compatibility](reference/evidence-format-compatibility.md)
for accepted versions, parser identities, and format-specific limitations.

In PostgreSQL mode, the focused Evidence command resolves and locks current
tenant-owned release parents and checks current release and optional-artifact
grants before parsing or object staging. For human grant checks, missing and
foreign artifact IDs both return `403` under the existing artifact-write policy.
The stateless parsers verify the declared source size and SHA-256, while
retaining existing normalization and provenance. Component counts and string
lengths use the same bounds as [stored SBOM diffs](#stored-sbom-diffs).

SBOM, evidence, audit, payload lifecycle, parser/finalization jobs, and safe
idempotency completion share the active command transaction, including pending
parents in compound commands. Replay rechecks current ownership/grants without
parsing or staging. Failed commits leave no partial database effects;
unreferenced staged bytes remain recoverable through the
[payload recovery workflow](runbooks/object-store-recovery.md).

With worker-owned parsing and object storage, the response includes parsed
components, while the stored SBOM initially has zero components until its
parser job runs. Inline mode, or explicit development operation without an
object store, persists the parsed projection. Evidence remains `pending`;
acceptance does not prove SBOM completeness or release security. Local-memory
mode retains its explicit compatibility path.

Source/test evidence: `internal/evidence/app/sbom_ingestion_commands.go`,
`internal/app/evidence_parser_adapter.go`, and
`internal/platform/wiring/sbom_ingestion_commands_test.go`.

### Stored SBOM Diffs

`POST /v1/sbom-diffs` requires `evidence:read`, two distinct stored SBOM IDs,
and optional `release_id` matching an explicitly stored release of either
SBOM. In PostgreSQL mode, the focused Evidence command resolves current
tenant-owned source evidence, product/project/release/build/deployment parents,
and matching artifact references before loading components. Human sessions
need current matching grants for both inputs and any linked artifact.

Components are read in the command transaction under the tenant projection
fence. Each source is bounded to 100,000 components, 64 MiB of normalized JSON,
and 1 MiB per component string. Invalid projections fail as 400, not truncated
diffs. Input IDs are limited to 1024 UTF-8 bytes; blank required IDs, NUL,
invalid UTF-8, and explicit null fields are rejected. The request body retains
its 64 KiB limit. Existing component identity precedence, sorted added/removed
sets, unchanged count, dependency records, and response fields are retained.

Diff, dependency changes, audit, and idempotency completion commit atomically.
Replay checks current ownership/grants without reading components and returns
the original result; changed request bytes return 409. Trusted snapshot replay
cannot rewrite existing diffs or dependency records. Local-memory mode retains
its explicit compatibility path. A diff compares stored component data; it
does not prove SBOM completeness or vulnerability coverage.

Source/test evidence: `internal/evidence/app/sbom_diff_commands.go`,
`internal/adapters/postgres/repositories/sbom_diff_reads.go`, and
`internal/platform/wiring/sbom_diff_commands_test.go`.

### OpenAPI Contract Ingestion

`POST /v1/openapi-contracts` requires `evidence:write`. Wrapped JSON supplies
`product_id`, optional `release_id`, `version`, and `spec` within the existing
64 KiB request limit. Native `application/vnd.oai.openapi+json` uploads stream
up to 20 MiB and require single, nonblank `X-Evydence-Product-ID`,
`X-Evydence-Release-ID`, and `X-Evydence-Version` headers. Explicit null fields,
duplicate wrapped fields or native metadata headers, and unknown wrapped fields
are rejected. Product/release IDs are limited to 1024 UTF-8 bytes and version
to 65,536 bytes; required values must be nonblank and may not contain NUL.

PostgreSQL mode resolves and locks current tenant/product/release coordinates,
then checks human resource grants before parsing or object staging. The parser
verifies the full source size and SHA-256 digest, rejects external references,
and retains the existing operation normalization and provenance. Operation
projections use the same bounds as [stored contract diffs](#stored-openapi-contract-diffs).
Evidence, contract, audit, payload lifecycle, parser/finalization jobs, and safe
idempotency completion share the active command transaction. Failed commits
leave no partial database effects; unreferenced staged bytes remain recoverable
through the [payload recovery workflow](runbooks/object-store-recovery.md).

With worker-owned parsing and object storage, the response includes the parsed
operations, while the stored contract initially has zero paths and no operations
until its parser job runs. Inline mode, or explicit development operation
without an object store, persists the parsed projection. Evidence remains
`pending`; accepting an OpenAPI document does not prove API compatibility or
release security. Local-memory mode retains its explicit compatibility path.

Source/test evidence: `internal/evidence/app/openapi_ingestion_commands.go`,
`internal/app/evidence_parser_adapter.go`, and
`internal/platform/wiring/openapi_ingestion_commands_test.go`.

### Stored OpenAPI Contract Diffs

`POST /v1/openapi-diffs` requires `evidence:read` and two distinct stored
contract IDs belonging to the same product. Optional `release_id` may identify
any current release of that product, not only a source contract's release.
In PostgreSQL mode, identifier-only reads validate tenant-owned product,
release, source evidence, and coherent source parents before operation data is
read. Human sessions need current matching grants for both contracts and the
requested release. The same checks run before saved-response replay.

Each source's operation JSON is limited to 32 MiB and 524,288 operations before
database transfer, preventing compact arrays from expanding without a bound.
The application also enforces a shared 32 MiB budget for operation strings and
structure (64 bytes per operation, 8 per nested field/status value). Invalid
projections fail as 400 without truncated results. Input IDs are limited to
1024 UTF-8 bytes; NUL, invalid UTF-8, blank required IDs, and explicit null
fields are rejected. The request body retains its 64 KiB limit.

Operation comparison retains existing sorted change messages, last-operation
identity precedence, equal-hash behavior, and path-count fallback for historical
contracts without operations. Diff, audit, and idempotency completion share one
transaction under the tenant projection fence. Replay returns the original
result; changed request bytes return 409. Trusted snapshot replay cannot rewrite
historical diffs. Local-memory mode retains its explicit compatibility path.
This comparison does not prove complete API compatibility or release security.

Source/test evidence: `internal/evidence/app/contract_diff_commands.go`,
`internal/adapters/postgres/repositories/contract_diff_reads.go`, and
`internal/platform/wiring/contract_diff_commands_test.go`.

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

Build creation rejects NUL characters in scalar text and provider-metadata
JSON keys or string values with `400`; scalar text must also be valid UTF-8.
Metadata must be JSON-serializable. Invalid input is rejected before repository
reads or writes, without exposing database errors. Submitted CI identity remains
unverified metadata; it cannot set `oidc_verified` to `true`.

Container-image registration in the PostgreSQL profile uses current durable
artifact coordinates and grants, not cached Ledger artifacts. It requires
`evidence:write`; human sessions must also be authorized for a supplied artifact
or an existing image's actual artifact association, even if `artifact_id` is
omitted. Reuse of `(tenant, repository, digest)` returns the original immutable
image without another audit entry; submitted tag and platform do not amend it.
Same-key HTTP replay also returns the original result; changed input with that
key conflicts.

Normalized artifact IDs are limited to 1 KiB of UTF-8 bytes and repository text
to 64 KiB. New stored tag/platform text is limited to 64 KiB of UTF-8 bytes and
must be NUL-free. Unsupported new storage text returns `400` without writes;
oversized existing records return `409`, never truncated metadata. Explicit
local-memory mode keeps its compatibility path. Registration records submitted
metadata; it does not download or verify a registry image.

### Source Repository Creation

`POST /v1/source/repositories` in the PostgreSQL profile uses an Integration-owned
command with bounded, transaction-scoped ownership and metadata reads. It
requires `source:write`. Human sessions need a current product/project grant
for a supplied project; detached creation requires a tenant-wide grant.
Keys and collectors retain their tenant-scoped credential authorization.

Normalized `(tenant, provider, full_name)` is repository identity, independent
of project. Reuse returns the original project, clone URL and default branch
without changing them or appending another audit entry. The submitted project
and the existing repository's actual project are authorized separately. An
existing row's minimal identity is checked before private metadata is read;
supplying an allowed project cannot reveal another project's repository.
Detached existing repositories also require a tenant-wide human grant.
The explicit local-memory compatibility path applies the same authorization
corrections.

Creation serializes name reuse even when no row exists yet. The PostgreSQL
adapter takes the worker-projection fence before the tenant-row lock, then
performs bounded parent and identity reads. Repository, audit and HTTP replay
state commit together. A failed write/commit leaves no effects; replay adds no
effects and creates no outbox job. The v1 stored schema and response fields are
unchanged.

Tenant/project IDs are limited to 1024 UTF-8 bytes. The combined tenant ID,
provider and normalized full name is limited to 2304 bytes so the unique index
fits without text compression. Optional clone URL/default-branch metadata is
limited to 64 KiB; text is trimmed, valid UTF-8 and NUL-free. The existing 64 KiB
HTTP envelope limit remains. Non-object envelopes, null string fields,
duplicate fields and unknown fields fail validation. Oversized stored metadata
returns conflict instead of a truncated record. Historical rows are unchanged.

The endpoint records submitted metadata only. It does not contact the provider,
fetch the clone URL, verify repository contents or establish provider trust.
Do not include credentials or secrets in repository metadata.

Source/test evidence: `internal/integration/app/source_repository_commands.go`,
`internal/platform/wiring/source_repository_commands_test.go`,
`internal/app/source_repository_creation_authz_test.go` and
`internal/adapters/httpapi/source_repository_commands_test.go`.

### Source Commit Recording

`POST /v1/source/commits` in the PostgreSQL profile uses an Integration-owned
command, not Ledger maps. It requires `source:write`, with the repository's
current tenant/product/project ownership checked before reading commit metadata.
Human sessions need a current product/project grant for attached repositories
or a tenant-wide grant for detached ones. Foreign-tenant repositories return
not found; removed or wrong-project grants cannot read existing commits.

Repository ID and normalized lowercase 40-character hexadecimal SHA identify
the immutable record. Reuse returns the original author, message hash and
timestamps even if a new request supplies different metadata. It appends no
second audit entry. The local-memory compatibility path also normalizes SHAs
before reuse, correcting case-only duplicate creation. SHA-256 Git object IDs
are not supported by the current 40-character contract.

The command stores only `sha256:` plus the SHA-256 digest of the exact submitted
message bytes, without trimming nonblank messages. Empty/whitespace-only
messages have no hash. The raw message is not passed to persistence or auditing;
author metadata is intentionally retained and must not contain secrets.
Recording metadata does not verify provider identity, repository contents,
commit signatures or provenance.

The adapter takes the worker-projection fence before locking the tenant-owned
repository, which serializes first creation and duplicate SHA reuse. Parent
ownership and existing commit reads are bounded. Commit, audit and successful
HTTP replay state share a transaction; failures roll back, replay adds no
effects, and no outbox job is created. This endpoint migration does not remove
the remaining Ledger-backed CI workflows.

Tenant/repository IDs are limited to 1024 UTF-8 bytes. Author metadata is trimmed,
valid UTF-8, NUL-free and limited to 64 KiB; message input is limited to 64 KiB.
The existing 64 KiB HTTP envelope limit remains. Non-object bodies, null fields,
unknown/duplicate fields and malformed timestamps fail validation. Omitted
`committed_at` defaults to recording time; new PostgreSQL-profile timestamps
use UTC microseconds. Oversized or inconsistent stored commit metadata returns
conflict instead of a truncated record. Historical rows and v1 response fields
are unchanged.

Source/test evidence: `internal/integration/app/source_commit_commands.go`,
`internal/platform/wiring/source_commit_commands_test.go`,
`internal/app/source_commit_reuse_test.go` and
`internal/adapters/httpapi/source_commit_commands_test.go`.

### Source Branch Upserts

`POST /v1/source/branches` in the PostgreSQL profile uses a focused
Integration command with `source:write`. The repository's current
tenant/product/project ownership is authorized before branch or head-commit
reads. Attached repositories require a current human product/project grant;
detached repositories require a tenant-wide grant. Keys and collectors retain
their tenant-scoped credential authorization.

Normalized `(tenant, repository_id, name)` is branch identity. Creation and
updates both return 201. An update preserves ID, name, schema version and
creation time, while replacing `head_commit_id`, `protected` and
`protection_hash`. Omitted values clear the head and protection hash and set
`protected` to false; this is replacement, not PATCH behavior. A supplied head
must exist in the same tenant and repository. A whitespace-only supplied head
fails lookup rather than silently clearing an existing head.

The shared source write adapter acquires the worker-projection fence before
the repository-row lock, serializing first creation and subsequent updates.
Only bounded ownership, head identity and branch metadata projections are
read; repository clone URLs and commit author/message metadata are not loaded.
Every executed update appends `source_branch.updated`, even when values are
unchanged. Branch changes, audit entries and successful HTTP replay state share
a transaction. Replay does not reapply an old branch state or append another
audit; rollback leaves both the branch and audit unchanged. No outbox job is
created. The explicit local-memory profile retains its compatibility path.

Tenant, repository and head IDs are limited to 1024 UTF-8 bytes. Combined
tenant/repository/normalized-name identity is limited to 2304 bytes to fit the
unique index without relying on text compression. Protection-hash metadata is
limited to 64 KiB. Text is trimmed, valid UTF-8 and NUL-free; the existing
64 KiB HTTP envelope limit remains. Non-object bodies, null fields, unknown or
duplicate fields and wrong types fail validation. Oversized or inconsistent
stored branch metadata returns conflict without a truncated response.
Historical rows and the v1 response shape are unchanged; new PostgreSQL-profile
creation timestamps use UTC microseconds.

The protection hash remains opaque submitted metadata, not a newly enforced
digest format or a proof of provider branch protection. Recording does not
verify provider identity, branch rules or repository contents. Do not put
secrets in branch metadata.

Source/test evidence: `internal/integration/app/source_branch_commands.go`,
`internal/platform/wiring/source_branch_commands_test.go` and
`internal/adapters/httpapi/source_branch_commands_test.go`.

### Pull-Request Recording

`POST /v1/source/pull-requests` in the PostgreSQL profile uses an
Integration-owned command with `source:write`. The current repository's
tenant/product/project ownership is authorized before provider or head-commit
reads. Human sessions need a current product/project grant for attached
repositories or a tenant-wide grant for detached ones. Foreign-tenant
repositories and foreign/wrong-repository heads return not found.

Records are append-only snapshots, not an upsert keyed by provider ID. Each
executed call creates a new record and `pull_request.recorded` audit, even if
the same provider ID was recorded before. Earlier snapshots remain unchanged.
HTTP idempotency replay returns the original response without another record or
audit; changed content under the same key is rejected. Snapshot, audit and
successful replay state share a transaction. Failed writes/commits leave no
partial snapshot, and no outbox job is created. Creation returns 201 with the
existing v1 response shape.

An omitted/blank provider defaults to the stored repository provider; an
explicit provider remains submitted metadata and need not match that default.
The default is read through a bounded projection only after authorization.
Repository clone URLs, head-commit author/message metadata and earlier
pull-request records are not loaded. A supplied head must exist in the same
tenant and repository; whitespace-only supplied heads fail lookup instead of
silently becoming an omitted head. Source/target branch names and review
decisions remain opaque metadata, not resolved branch IDs or approval policy.

Tenant, repository and head IDs are limited to 1024 UTF-8 bytes. Provider,
provider ID, title, source/target branch names and review-decision text are
limited to 64 KiB; text is trimmed, valid UTF-8 and NUL-free. Provider ID and
title are required, and state must be `open`, `closed` or `merged`. The existing
64 KiB HTTP envelope limit remains. Non-object bodies, null fields, unknown or
duplicate fields and wrong types fail validation. Oversized stored provider
defaults return conflict without a truncated value. Historical records are
unchanged; new PostgreSQL-profile creation timestamps use UTC microseconds.

Title/review metadata is intentionally stored in the scoped snapshot, not in
audit entries. Do not submit secrets. Recording does not contact a provider,
verify repository contents, establish review approval or prove merge authority.
Local-memory mode retains its compatibility path. For combined provider source
snapshots, see the contract below. CI build snapshots remain separate migration
work.

Source/test evidence: `internal/integration/app/pull_request_commands.go`,
`internal/platform/wiring/pull_request_commands_test.go` and
`internal/adapters/httpapi/pull_request_commands_test.go`.

### Provider Source Snapshots

`POST /v1/collectors/github/source-snapshots` and
`POST /v1/collectors/gitlab/source-snapshots` in the PostgreSQL profile use an
Integration-owned orchestration command, not Ledger. The route fixes the
provider label. The required `repository` object and optional `commit`, `branch`
and `pull_request` objects reuse the focused source commands above, including
current submitted-project and actual-repository ownership checks. IDs for
repository and head relationships come from command results, never supplied
nested IDs. Access to a submitted project does not authorize reuse of a
repository owned by another project.

All supplied components, their audit entries and successful HTTP idempotency
state commit in one transaction. This also holds for direct command callers
without an ambient HTTP transaction. A late validation, write or commit failure
returns no partial result and rolls back earlier inserts and branch updates.
No outbox job is created. Repository/name and commit/SHA reuse return original
metadata; each supplied branch executes a current-state replacement and each
supplied pull request appends a new snapshot. A new idempotency key can therefore
add branch/PR effects even for the same repository and commit. Replay adds none;
changed content under the same key is rejected.

Creation returns 201 with the existing four-key result: `repository`, `commit`,
`branch`, `pull_request`. Omitted components retain the existing zero-valued
response objects. An omitted commit means supplied branch/PR records have an
empty head; omitting a branch or PR does not delete historical records.
Omitted commit time defaults to server time. Only the hash of exact nonblank
commit-message bytes is stored; raw messages do not enter the database, audit
or replay response. Repository reuse and new creation expose the same UTC
timestamp representation.

The existing 64 KiB HTTP envelope limit and focused source field limits apply.
Non-object bodies, unknown/duplicate fields, wrong types and explicit null
components or fields fail validation. Omit optional components/fields instead
of sending null; this tightens the legacy nullable decoding to the existing
non-nullable schema in the PostgreSQL profile. The commit-time schema now
reflects its existing server default, and PR title is marked required to match
existing runtime validation. No stored schema or route changed.

These are collector-submitted records, not authenticated provider fetches or
verified webhooks. Recording does not prove GitHub/GitLab origin, signature
validity, repository contents, branch protection or review/merge authority.
Local-memory mode retains its compatibility workflow.

Source/test evidence: `internal/integration/app/source_snapshot_commands.go`,
`internal/platform/wiring/source_snapshot_commands_test.go` and
`internal/adapters/httpapi/source_snapshot_commands_test.go`.

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
| `POST` | `/v1/control-frameworks` | Create framework version with `controls:admin`; PostgreSQL human sessions need a current tenant-level grant. |
| `GET` | `/v1/control-frameworks` | List frameworks. Human sessions need a current tenant-level `controls:read` grant; scoped credentials need that issued scope. |
| `GET` | `/v1/control-framework-template-packs` | List built-in starter packs. |
| `POST` | `/v1/control-framework-template-packs/{slug}/install` | Atomically install a starter pack with `controls:admin`; PostgreSQL human sessions need a current tenant-level grant. |
| `POST` | `/v1/controls` | Create control under a current tenant-owned framework with the same `controls:admin` grant rule. |
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

### Built-in Policy Evaluation

`POST /v1/policies/evaluate` accepts `release_id` and appends an immutable
`policy_evaluation` using the existing `policy-set.v1.0.0` checks. It requires
`verify:read`; PostgreSQL human sessions also require a current matching
tenant/product/release grant. The release and its product must belong to the
caller’s tenant. This records technical readiness checks, not a legal compliance
conclusion or a guarantee of release security.

In PostgreSQL mode, a focused Risk command resolves current release ownership
before gathering facts. The bounded readiness projection runs inside the same
command transaction, holding the tenant projection fence until evaluation,
audit, and idempotency completion commit. It selects facts and bounded IDs,
not raw payloads or prior evaluation history. A decision handles an open finding
only when its scan and release coordinates match the finding being evaluated.
Expired exceptions/package profiles and signing-key lifecycle are evaluated
against a timestamp sampled after the release projection fence is acquired.
Existing check names, explanations, policy-set
version, and JSON fields are retained; new timestamps use UTC microseconds.

Replay checks current ownership/grants without gathering readiness facts, then
returns the original evaluation. Changed request bytes return 409; removed
grants return 403 and missing/inconsistent release ownership returns 404. A new
evaluation rejects oversized or malformed readiness projections rather than
truncating them. Release IDs are limited to 1024 UTF-8 bytes, with invalid UTF-8,
NUL, blank values, and explicit null rejected as 400. The entire JSON body
retains its 64 KiB limit. Decision/exception diagnostic IDs and package counts
share a 4096-record budget, selected IDs are limited to 1024 bytes, and signed
bundle verification considers at most 256 signature rows with bounded public
material. Trusted snapshot replay may add historical evaluations but cannot
rewrite existing results, checks, or policy-set versions. Local-memory mode
retains its explicit compatibility path.

Source/test evidence: `internal/risk/app/policy_evaluation_commands.go`,
`internal/adapters/postgres/policy_evaluation_repository.go`, and
`internal/platform/wiring/policy_evaluation_http_test.go`.

### Custom Policies

`POST /v1/custom-policies` creates an immutable tenant-wide policy definition
with `name`, `version`, optional `description`, and a nonempty `rules` array.
Name/version/description are trimmed; rule names and severity labels retain
their original text and order. Severity is any nonblank label, not a closed
severity enum. Evidence types use the existing custom-policy vocabulary;
omitting `evidence_type` makes a metadata-only rule. Duplicate tenant/name/version
definitions return 409. Creation requires `policy:write`; in PostgreSQL mode,
human sessions require a tenant-wide grant, not merely a product or release grant.

`POST /v1/custom-policies/{id}/evaluate` accepts `release_id` and appends an
evaluation. It requires `policy:read` and, for PostgreSQL human sessions, a
matching current tenant/product/release grant. Both policy and release must belong to the caller's
tenant, with valid current product ownership. Evaluation checks evidence presence
only: a required missing type fails, an optional missing type passes, and a
metadata-only rule passes. It does not verify payloads, freshness, approvals,
vulnerability resolution, SBOM completeness, or legal compliance. Evidence with
inconsistent tenant/product/project/release parents is not counted.

In PostgreSQL mode, these routes use focused commands and one transaction for
record, audit, and idempotency completion. Current ownership/grants are checked
before saved-response replay without loading rules or evidence payloads. A new
evaluation reads one bounded definition and at most 19 evidence-presence facts,
not all tenant state or prior evaluations. Same-key replay preserves the original
record; different request bytes return 409. Existing JSON fields, schema versions,
rule explanations, and normalized-JSON input hashes are retained. New record
timestamps use UTC microseconds. Trusted snapshot replay can add historical
policies/evaluations but rejects changes to existing records.

New inputs reject invalid UTF-8, NUL, explicit null fields/items, blank required
labels, and unsupported evidence types with 400. IDs, names, and versions are
limited to 1024 UTF-8 bytes each; tenant/name/version together to 2048 bytes to
stay within the database uniqueness-index budget. Descriptions and rule names
are limited to 65536 bytes, severity/evidence-type labels to 128 bytes, and
definitions to 4096 rules. Stored rule JSON has an 8 MiB read ceiling; oversized
definitions fail without truncation for new evaluations. The HTTP body still
has its existing 64 KiB limit, including JSON syntax and escapes. Local-memory
mode retains its explicit compatibility path.

Source/test evidence: `internal/risk/app/custom_policy_commands.go`,
`internal/adapters/postgres/repositories/custom_policy_reads.go`, and
`internal/platform/wiring/custom_policy_http_test.go`.

### Vulnerability Workflow Annotations

`POST /v1/vulnerability-findings/{id}/workflow` appends one annotation with
`action` and `reason`. Supported actions are `scanner_metadata`, `sla_set`,
`scanner_disagreement`, `superseded`, and `reopened`. These labels do not
themselves mutate a scan finding or supersede/reopen a vulnerability decision.

In PostgreSQL mode, a focused command resolves the finding through its current
tenant-owned scan, typed source evidence, and product/release parents. It
selects bounded identifiers only, not scanner documents, findings payloads,
SBOM context, or historical workflow reasons. Ambiguous finding IDs return 409;
missing or inconsistent ownership returns 404. `security:write` is required,
with a matching tenant/product/release grant for human sessions. A scan with no
declared release retains its release-less response and requires tenant-wide
permission, not a product-only grant.

Action/reason must be nonempty after trimming. Finding IDs are limited to 1024
UTF-8 bytes, actions to 128 bytes, and reasons to 65536 bytes; invalid UTF-8,
NUL text, or explicit null fields return 400. The entire JSON body retains its
64 KiB limit, including syntax and escapes. Workflow record, audit entry, and
idempotency completion commit together. Same-key replay returns the original
record only after current parent/grant checks; changed request bytes conflict.
New records retain `vulnerability-workflow.v1.0.0` and UTC microsecond timestamps.
Local-memory mode keeps its non-durable compatibility path.

Source/test evidence: `internal/risk/app/vulnerability_workflow_commands.go`,
`internal/adapters/postgres/repositories/vulnerability_workflow_reads.go`, and
`internal/platform/wiring/vulnerability_workflow_http_test.go`.

### Exception Lifecycle

`POST /v1/exceptions` creates a release-owned exception with optional finding
and control references. `POST /v1/exceptions/{id}/approve` records its approval
transition. Both require `release:write`; human sessions need a matching
tenant, product, or release grant.

In PostgreSQL mode, transaction-only commands resolve current tenant-owned
release/product coordinates before reservation and replay. A finding must
belong to that same release/product, and a control and its framework must
remain tenant-owned. Approval rechecks these references before reading one
bounded exception record. Neither route refreshes Ledger state.

Creation requires a future expiry. Approval preserves all original core
fields and commits approval metadata, audit, and replay completion atomically.
Unlike waiver approval, approving an already-approved, unexpired exception
with a new key returns the original approval without another audit event.
Expired exceptions reject new approvals with 409. Completed responses remain
replayable after expiry, subject to current grants and parent ownership.

PostgreSQL identifiers and owner are limited to 1024 UTF-8 bytes, and reasons
to 65536 bytes. Invalid text or explicit null creation fields returns 400.
Expiry must fit years 1–9999 and is normalized to UTC microsecond precision.
Authorization reads exclude historical reasons; oversized historical records
cannot be approved through the bounded command. The approval route retains
its existing ignored-body behavior. Local-memory mode retains its explicit
compatibility path, not durable transaction guarantees.

Trusted relational/snapshot replay never rewrites existing exception rows.
Unchanged older snapshots may omit later approval metadata but cannot undo it.
Changed historical content or new approvals supplied only through bulk replay
are rejected; initial legacy imports into an empty destination remain supported.

Source/test evidence: `internal/risk/app/exception_commands.go`,
`internal/adapters/postgres/repositories/exception_reads.go`, and
`internal/platform/wiring/exception_http_test.go`.

### Waiver Lifecycle

`POST /v1/waivers` creates a waiver scoped to a `release`, `finding`, `control`,
or `policy`. `POST /v1/waivers/{id}/approve` records the explicit approval
transition; approval records created through `/v1/approvals` do not trigger it.

In PostgreSQL mode, these routes bind transaction-only commands rather than
Ledger mutation scopes. Current tenant-owned parent coordinates and
`policy:write` authorization are checked before reservation and replay. Human
sessions need a matching product/release grant for release/finding scopes and
a tenant grant for control/policy scopes. Optional control and policy links
must belong to the tenant. Supersession additionally requires authorization
for the prior waiver's current scope; a grant on the new scope alone cannot
supersede an inaccessible waiver.

Creation requires a future expiry. New approvals reject expired or already
approved waivers with 409. Completed responses remain replayable after those
transitions, subject to current ownership and authorization checks. Waiver
writes, the audit event, and replay completion share one transaction. Existing
approval/supersession metadata transitions are preserved; approval does not
rewrite the waiver's scope, reason, owner, risk, or expiry.

PostgreSQL identities, owner, and risk are limited to 1024 UTF-8 bytes; reasons
to 65536 bytes. Invalid text, explicit null creation fields, and unsupported
scopes return 400. Expiry must fit years 1–9999 and is normalized to UTC at
PostgreSQL microsecond precision. Authorization and supersession queries do
not fetch historical reasons; approval reads one bounded record afterward.
Oversized historical records remain usable as supersession targets but cannot
be approved through the bounded command. Local-memory mode retains its
compatibility path and is not evidence of durable operation.

Trusted relational/snapshot replay preserves existing waiver core fields and
durable lifecycle metadata. Replaying an older unapproved or unsuperseded
snapshot cannot undo a later transition. Changed historical content or a new
transition supplied only through bulk replay is rejected; legacy rows can still
be imported into an empty destination.

Source/test evidence: `internal/risk/app/waiver_commands.go`,
`internal/adapters/postgres/repositories/waiver_reads.go`, and
`internal/platform/wiring/waiver_http_test.go`.

### Approval Creation

`POST /v1/approvals` records an immutable `approved`, `rejected`, or `accepted`
decision for a `release`, `contract_diff`, `waiver`, `security_review`, or
`customer_package`, matching the published request enum. Creating a record does
not itself approve a waiver or change release state. The release security
summary counts release-scoped records of all three decisions in `total`, but
only `approved` records in `approved`; `accepted` is not an approval.

In PostgreSQL mode, current tenant-owned parent coordinates and `release:write`
grants are checked before new requests and idempotency replay. Human sessions
need a matching product/release grant; a waiver on a tenant-wide control or
policy instead requires a tenant grant. Optional `evidence_id` must belong to
the tenant; it is not required to match the subject's release. The approval,
audit entry, and successful replay record commit atomically without Ledger
cloning or whole-state refresh.

PostgreSQL command identities are limited to 1024 UTF-8 bytes and the reason to
65536 bytes. Invalid UTF-8, NUL text, explicit null fields, unsupported subjects,
and unknown decision values return 400. Local-memory mode retains its explicit
compatibility command; it is not proof of durable operation.

Manual framework/control creation in PostgreSQL uses focused commands and
existence-only reads in the active transaction, not Ledger inventories. Each
record and its audit append commit together; same-key replay returns the
original response and changed request bytes conflict. Duplicate framework
`slug`/`version` or framework/control `code` identities return `409`. Missing or
foreign frameworks return `404`, and denied administration grants return `403`.
New timestamps use microsecond-precision UTC.

Creation text is trimmed, NUL-free UTF-8. Framework names/descriptions and
control titles/objectives are each bounded at 64 KiB; framework slug/version
text together is bounded at 1024 bytes. A blank/omitted slug uses the existing
ASCII name-derived slug; explicit slugs are retained. Framework IDs and control
codes are each bounded at 1024 bytes, and tenant ID plus framework ID plus code
at 2048 bytes. The whole HTTP JSON body remains limited to 64 KiB including
syntax and escapes. Invalid or excessive input returns `400` without resource
or audit writes.

Evidence requirements preserve request order, reject repeated or unsupported
types, and accept freshness from 0 through 3650 days. Each requirement must
include its non-null `required` boolean; `false` is valid. Applicability is
trimmed and sorted without removing duplicates or empty entries; limitations
retain order/duplicates but omit trimmed blanks. Together these two lists are
bounded at 1024 input entries and 64 KiB of input text. Optional arrays may be
omitted; explicit null fields/items are rejected in both runtime profiles.
Local-memory creation retains its compatibility command. Evidence linking
remains a separate compatibility command at this stage.

PostgreSQL template installation uses a focused transaction with the same
tenant-wide administration policy. It appends the framework, all starter
controls, and one installation audit attributed to the authenticated principal.
Starter names, objectives, requirements, limitations, and schema versions are
preserved. A different-key duplicate tenant/slug/version returns `409`; same-key
replay returns the original framework, and changed request bytes conflict.
The trimmed slug must be NUL-free UTF-8 of at most 1024 bytes; invalid paths are
rejected with `400` before durable replay reservation, and unknown slugs return
`404`. The body is optional; when supplied it must be an empty JSON object
(a blank body retains its existing empty-object behavior). Malformed bodies,
null, arrays, and unknown fields now return `400` in both profiles instead of
being ignored. Local-memory mode retains its compatibility installation
command. Starter packs organize technical evidence, not compliance or control
effectiveness conclusions.

| Method | Path | Notes |
|--------|------|-------|
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
