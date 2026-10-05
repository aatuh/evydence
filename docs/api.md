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

Native PostgreSQL replay decoding and safe-response redaction preserve exact
stored JSON numbers, including large artifact sizes and decimal values, without
converting them through floating point. This does not recover values already
rounded in an older stored response or change a manifest's hashing profile.

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

In PostgreSQL mode, one read-only repeatable-read snapshot resolves current
tenant-owned release parents and optional artifact ownership. Human release
and artifact `evidence:read` grants are checked before full parsing or candidate
selection. Artifact visibility uses the current evidence/build association
policy; an unrelated same-tenant artifact is no longer sufficient for a human
preview. Missing or foreign parent IDs return `404`; denied grants return
`403`. The optional artifact is an authorized reference, not a filter on the
release's scan findings.

The request remains wrapped JSON, capped at 64 KiB, with the
[VEX ingestion](#vex-ingestion) ID and normalized-document bounds. Null,
duplicate, and unknown envelope fields are rejected. The query selects only
relevant finding coordinates and active-decision presence, never private notes,
source evidence metadata, or object-store bytes. It allows at most 4096 release
scans, 4096 candidate findings, and 8 MiB of combined candidate text. Oversized
or malformed stored projections fail closed with `409`, not truncation or a
partial preview. Pending scans with no findings contribute no candidates.

Risk-context matching retains the existing ambiguity and duplicate rules,
original statement indexes, parser versions, warnings, assumptions, and
limitations. New preview timestamps use UTC microsecond precision. Previews
create no audit, outbox, or idempotency records and do not prove future worker
mapping, source authority, vulnerability coverage, or release security.
Local-memory mode retains its explicit compatibility path. Source/test evidence:
`internal/evidence/query/vex_preview.go`, `internal/risk/app/vex_preview.go`, and
`internal/platform/wiring/vex_preview_query_test.go`.

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

### API Key Issuance

`POST /v1/api-keys` uses a focused Identity command in the PostgreSQL profile.
It requires `admin`, an `Idempotency-Key`, and a current tenant-wide grant for
human sessions. A tenant wildcard does not permit delegating `instance:admin`;
that scope requires explicit instance authority. Current authority is checked
before reservation and replay. Explicit local-memory mode retains its Ledger
path; credential issuance does not load key or tenant inventories in PostgreSQL.

The API key, audit event, and replay completion commit atomically. Keys use the
same random `evy_` secret, twelve-character public prefix, configured pepper,
and HMAC hash as authentication. Production rejects the default/local pepper.
The first response returns the secret once; restart replay preserves only the
public `api_key` DTO, never its hash or secret. A lost initial response cannot
recover the secret. A failed insert, audit, replay completion, or commit returns
no credential and leaves no key/audit effects.

Names and scopes are trimmed; scopes are sorted without removing duplicates,
unknown strings, or historically accepted blank entries. Blank/unknown entries
grant no recognized authority. Names are not unique: a new idempotency key can
issue another key with the same name. Optional past expiry is retained for
compatibility, but an expired or revoked credential cannot authenticate.
New durable timestamps use UTC microseconds; expiry inputs are cloned.

JSON bodies are limited to 64 KiB. Malformed, duplicate/trailing, unknown,
explicitly null fields (including optional expiry), and null scope items return
`400`. Direct inputs require UTF-8/NUL-free text, names of at most 64 KiB,
at most 1024 scopes of at most 128 bytes each, canonical IDs of at most 1024
bytes, and expiry years from 1 through 9999 after UTC normalization. See the
[unreleased compatibility note](reference/api-versioning.md#unreleased-api-key-write-boundary).

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

#### Organization And User Writes

In the PostgreSQL profile, organization creation, user creation, and user
deactivation use focused Identity commands, not Ledger state. All three require
`identity:admin` (or admin); human sessions additionally need a current
tenant-wide grant. Authorization and current optional organization/user parents
are checked before durable reservation and replay. A foreign parent returns
`404`; an existing slug/email or a new deactivation of an inactive user returns
`409`. A completed request with the same idempotency key and body replays the
original public DTO without repeating writes or audits. Slugs are trimmed but
remain case-sensitive; emails are trimmed/lowercased and must parse as a plain
mailbox address, not a display-name wrapper. This does not verify email ownership.

Strict request decoding rejects invalid UTF-8, unknown/duplicate fields, trailing JSON,
non-object bodies and explicit null fields. Deactivation accepts only an empty
object (or an omitted body, as in the existing decoder). HTTP JSON remains
limited to 64 KiB. Direct calls also reject invalid UTF-8/NUL, IDs above 1024
bytes, names above 65536 bytes, and tenant plus slug/email keys above 2304 bytes.
New timestamps use UTC microseconds. Deactivation reads one bounded user and
locks current parents; oversized stored user metadata returns `409`, never a
truncated response. Organization metadata and unrelated users are not loaded.

User status, audit, and safe replay completion share one transaction. A committed
deactivation makes the user's SSO sessions fail current-user authentication;
rollback leaves them active. Authorized user replay retains the required email
only in the fixed, versioned public DTO within the existing 24-hour idempotency
expiry window; expiry does not itself prove physical deletion. Unknown fields,
credential material, generic log redaction,
and customer-package redaction do not acquire that exception. Local-memory mode
retains its explicit compatibility binding and shares input normalization.

#### Role Binding Writes

`POST /v1/role-bindings` uses focused Identity commands in PostgreSQL mode.
It requires `identity:admin` (or admin) and a current tenant-wide grant for
human sessions; a product-only grant cannot delegate roles. Current subject and
resource ownership is checked before durable reservation and completed replay.
The binding, audit entry, and safe replay completion commit atomically without
loading user, collector, credential, or evidence inventories.

Subjects are `user` or `collector`. Roles remain `tenant_admin`,
`security_engineer`, `release_manager`, `customer_verifier`, and `collector`.
An omitted/empty resource type with an empty ID means tenant-wide; `tenant`
accepts an empty ID or the current tenant ID. The other supported types are
`product`, `project`, `release`, `customer_security_package`, and `evidence_bundle`;
their missing IDs and foreign targets return `404`. Current organization,
collector-key, product, and optional release parents must resolve in the tenant;
a package's release must match its product. Target metadata and manifests are
not loaded. Binding metadata does not activate revoked credentials or grant
the reserved explicit `instance:admin` scope.

All fields are trimmed without changing case. Direct inputs require UTF-8/NUL-free
text, type/role values at most 128 bytes, and IDs at most 1024 bytes. The same
strict HTTP decoding and 64 KiB body limit as membership writes apply. New
timestamps use UTC microseconds. Repeating a completed key and body returns
the original public binding without more effects; a different key intentionally
creates another assignment even when its grant coordinates match. Local memory
retains its compatibility binding and shares input normalization. See the
[unreleased compatibility note](reference/api-versioning.md#unreleased-role-binding-write-boundary).

Current SSO endpoints model admin-managed provider, identity-link, trust-material, and session records plus API-first session logout. OIDC provider records can include public JWKS material, and SAML provider records can include PEM-encoded assertion signing certificates; both can be rotated through `POST /v1/sso/providers/{id}/trust-material`. OIDC public JWKS can also be refreshed from the configured issuer with `POST /v1/sso/providers/{id}/discover-oidc`. `POST /v1/provider-verifications` can verify a supplied OIDC ID token or SAML assertion locally for issuer, audience, subject, time bounds, and signature. When an OIDC `access_token` is supplied, the same endpoint can call either the provider's discovered UserInfo endpoint or a configured operator-controlled provider validation gateway, verify the returned subject, and record any configured group-claim mapping checks without storing the access token. The provider validation gateway receives only non-secret request metadata and an `access_token_present` flag, not the supplied token. `POST /v1/sso/session-exchanges` uses local token/assertion verification and a verified identity link to issue a one-time SSO bearer secret and an HttpOnly cookie for browser clients. OIDC group claim values can map to session-scoped roles through the provider `groups_claim` and `role_mapping`; no permanent role binding is created from token claims. External group synchronization into permanent role bindings is not implemented in this slice.

#### SSO Provider Registration

In PostgreSQL mode, `POST /v1/sso/providers` uses focused Identity commands:
provider creation, `sso_provider.created` audit and successful replay receipt
commit together without loading provider inventories or refreshing Ledger
state. Current tenant-wide `identity:admin` authority and input validation run
before reservation or completed replay. Product-scoped or foreign-tenant human
grants cannot administer providers. Success remains `201` with the published
provider DTO; another key creates another provider even for identical metadata.

The JSON body is limited to 64 KiB. Invalid raw UTF-8, duplicate/unknown fields,
trailing values, explicit null fields, null role-map values and null certificate
items return `400`. Stored metadata must be NUL-free; name, issuer, client ID
and groups claim are bounded to 65,536 bytes each, type to 128 bytes, and encoded
role mapping to 64 KiB. Required names/client IDs must be nonblank. Issuers must
be absolute HTTPS URLs with a host, no userinfo and no fragment; issuer paths
and existing query strings are retained. Top-level text is trimmed; group/role
mapping strings are preserved. Unknown role names remain accepted but do not
grant session scopes. Optional trust material remains optional for both types.

Authorized replay preserves harmless public group names such as
`token-reviewers` within the versioned provider DTO, not credential-shaped
strings or unknown response fields. Generic log/customer-package redaction is
unchanged. Local memory shares input rules but remains non-durable. Invalid
private-material requests cannot replay retained PostgreSQL successes; this
does not delete or scrub historical records. Registration makes no live
provider call and does not prove provider ownership or key custody.

#### SSO Trust Rotation

In PostgreSQL mode, `POST /v1/sso/providers/{id}/trust-material` uses focused
Identity commands, not Ledger state or provider inventories. Current tenant-wide
`identity:admin` authority, input validation and tenant-owned provider lookup run
before reservation or completed replay. Missing/foreign providers return `404`;
scoped human grants return `403`. One locked provider row supplies unchanged
public metadata and the expected trust version. Its text fields are bounded to
65,536 bytes (type/status 128, schema version 1024); each stored JSON field is
limited to 128 KiB of JSONB text before transfer. Oversized or ill-typed stored
metadata returns `409`, never a truncated response.

OIDC rotation requires nonempty `jwks` and no SAML certificates; SAML requires
certificates and no JWKS. The 64 KiB body limit, strict UTF-8/duplicate/unknown
field checks, and non-null fields/items apply in both profiles. Retained JWK
strings must be NUL-free. Provider update, canonical-hash
`sso_provider.trust_material_updated` audit and safe replay completion share one
transaction. ID, tenant, creation time and unrelated provider metadata remain
unchanged; the new trust timestamp uses UTC microseconds.

Success remains `200` with the provider DTO. A completed matching key/body returns
the original DTO without another update or audit; changed content returns `409`.
Replay preserves normalized public PEM line breaks and harmless group names
within this versioned DTO, not arbitrary PEM or private material. Generic
diagnostic/customer-package redaction is unchanged. Local memory shares trust
normalization and strict decoding but remains non-durable. No live provider call
is made, and neither provider ownership nor key custody is proved. Existing rows,
receipts and backups are not scrubbed or repaired. See the
[compatibility note](reference/api-versioning.md#unreleased-sso-trust-rotation-boundary).

#### OIDC Discovery Refresh

In PostgreSQL mode, `POST /v1/sso/providers/{id}/discover-oidc` uses focused
Identity commands and the same bounded tenant-owned provider projection as
[trust rotation](#sso-trust-rotation). Current tenant-wide `identity:admin`
authority, provider ownership/type and body checks run before reservation or
completed replay, without provider calls. Omit the body or send `{}`; null,
non-object, unknown fields, trailing JSON, invalid raw UTF-8 and bodies above
64 KiB return `400`. The provider must be OIDC; missing/foreign providers return
`404`, and oversized/ill-typed stored metadata returns `409`.

Only a newly acquired command invokes the runtime's existing hardened discovery
adapter. Its HTTPS, destination, same-origin JWKS and configured timeout policy
remain; the request contains tenant/provider IDs and issuer, not credentials.
Issuer mismatch, empty/private keys, unsafe retained public text or provider
failure returns `422` without a provider update or audit. The safe failure
receipt contains no raw provider error or partial response. Valid refresh
conditionally updates trust and commits the canonical-hash
`sso_provider.oidc_trust_material_refreshed` audit and safe replay together.
Creation time and unrelated provider metadata remain; the new trust timestamp
uses UTC microseconds.

Success remains `200` with the provider DTO. Completed matching retries return
that original DTO without refetching, even if the provider is subsequently
unavailable; current local authorization and provider checks still apply.
Discovery runs within the active command transaction, so provider latency can
delay writes until the configured timeout. Local memory shares normalization
and body rules but remains non-durable. Discovery does not authenticate users,
prove provider ownership/key custody, synchronize groups or scrub historical
material. See the [compatibility note](reference/api-versioning.md#unreleased-oidc-discovery-boundary).

#### SSO Session Revocation And Logout

`POST /v1/sso/sessions/{id}/revoke` requires current tenant-wide
`identity:admin` authority and a current tenant-owned session. It can invalidate
an expired session or one whose user/provider is inactive or missing; it does
not depend on those parents being usable for login. The trimmed path ID is
NUL-free UTF-8 bounded at 1 KiB. A new command for an already-revoked session
returns `409`. A completed matching admin replay returns the original safe
metadata after current authority/ownership checks, without another audit.

`POST /v1/sso/logout` needs an authenticated human session, no administration
grant, and revokes only that caller's session. API/collector keys return `403`.
The old bearer/cookie secret stops working, so a later request using it returns
`401` even when a saved logout receipt exists. The `/v1` cookie retains
`HttpOnly`, `Secure` and `SameSite=Strict` and is cleared only after successful
durable commit; error responses do not clear it. Admin revocation sets no cookie.

Both routes require an idempotency key and accept only an empty body or one
strict empty JSON object, at most 64 KiB. Null, fields, duplicate members,
trailing values and malformed UTF-8 return `400`. In both profiles, cookie-only
mutations require exactly one `Origin` header containing an HTTPS origin with
the same host/port as the request `Host`; missing, ambiguous or foreign origins
return `403`. HTTPS reverse proxies must preserve the public `Host`. An explicit
bearer credential takes precedence over an incidental cookie and does not need
an Origin header. Non-browser clients should use bearer authentication.

PostgreSQL locks one bounded, hash-free session projection through conditional
revocation, actual-caller audit and safe replay completion. No user/provider
inventory or credential hash is loaded. Stored identity/prefix/version fields
are bounded at 1 KiB each and stored groups JSON at 128 KiB; oversized or invalid
stored metadata returns `409` without partial output. New revocation timestamps
use UTC microseconds; existing immutable session fields/hashes are unchanged.
Local memory retains its explicit non-durable compatibility path and shares
body, path and cookie-Origin rules. See the
[compatibility note](reference/api-versioning.md#unreleased-sso-session-revocation-boundary).

#### Administrator-Issued SSO Sessions

`POST /v1/sso/sessions` requires current tenant-wide `identity:admin` authority,
a current active tenant-owned user and a tenant-owned provider. The provider
need only exist; activation is not a new issuance precondition. This is an
administrator-issued credential, not proof of a provider login. It grants no
new roles and sets no browser cookie; authentication derives current user
grants through the existing credential verifier.

`user_id`, `provider_id` and `expires_at` are required and non-null. IDs are
trimmed, limited to 1 KiB each, valid UTF-8 and NUL-free. Expiry must be a valid
timestamp and strictly later than command time for new issuance; timestamps
use UTC microseconds. Administrative issuance retains the existing lack of
an upper lifetime cap, unlike credential exchange. Null/ambiguous/non-object
JSON, unknown fields, trailing values, malformed UTF-8 and oversized bodies
return `400`. Missing/foreign users/providers or an inactive user return `404`.

PostgreSQL uses one focused transaction for the session, actual-caller
`sso_session.created` audit and safe replay completion. Parent ownership and
user status are held through commit without selecting display metadata,
provider trust material or identity/session inventories. The first `201`
response includes `session` and its one-time `evysso_` bearer `secret`; only the
peppered HMAC hash is stored. A matching restart replay returns original
session metadata, never its secret/hash or a newly minted credential. Current
authority and parent checks still apply. Replay is not a current lifecycle
read: a subsequently revoked or expired secret remains unusable even though
the original metadata can be replayed. New issuance with an elapsed request
expiry fails; completed metadata replay may outlive that expiry.

Local memory shares input rules through its explicit non-durable compatibility
path. Historical rows/receipts are not rewritten. See the
[compatibility note](reference/api-versioning.md#unreleased-sso-session-issuance-boundary).

#### SSO Identity Linking

`POST /v1/sso/identity-links` records an administrator's verified-ownership
assertion; it does not verify a provider token or assertion. It requires
tenant-wide `identity:admin` authority (including the existing admin grant),
a current tenant-owned user and provider, and an exact match between the user's
stored email and the trimmed/lowercased input. Subjects are trimmed but remain
case-sensitive. Missing/foreign parents or an email mismatch return `404`.
Inactive target users/providers remain linkable administrative metadata;
linking neither activates them nor grants a role or session.

All five request fields (`user_id`, `provider_id`, `subject`, `email`, `verified`)
are required and non-null, and `verified` must be `true`. IDs are at most 1 KiB
each. The normalized tenant/provider/subject strings together must fit 2304
UTF-8 bytes, and tenant/email together must also fit 2304 bytes. Email must be
a plain mailbox, not a display-name address. Invalid UTF-8, NUL, oversized
text, malformed/non-object/duplicate/unknown/trailing JSON or bodies above
64 KiB return `400` before reservation. A new key for an existing
tenant/provider/subject returns `409`; links are not reassigned or superseded.

In PostgreSQL mode, the focused command locks current parent rows without
selecting names, user/provider inventories, JWKS, certificates or credentials.
Link insertion, `identity_link.created` audit attributed to the real caller,
and safe replay completion share one transaction. Success remains `201` with
the link DTO. Matching retries return the saved DTO without duplicate links or
audits, but current authority, parent ownership and email checks still apply.
The versioned administration replay retains the published email and plain
email-shaped provider subjects; unknown fields and credential-like text remain
redacted. Generic logs/customer packages retain their PII redaction policy.

Local memory shares input/replay policy through its explicit compatibility
path and remains non-durable. Historical rows and receipts are not rewritten.
See the [compatibility note](reference/api-versioning.md#unreleased-sso-identity-link-boundary).

#### SSO Credential Exchange

`POST /v1/sso/session-exchanges` is public and accepts `provider_id`, `subject`,
and exactly one nonempty `id_token` or `saml_assertion`. It verifies credentials
against configured local public trust, requires a verified tenant-owned identity
link and active user, and requires current user or mapped provider-group grants.
It does not perform live provider verification, redirect/callback orchestration,
or external group synchronization.

Both profiles reject duplicate/unknown fields, non-object bodies, explicit null
fields, invalid UTF-8, and NUL-bearing text with `400`. The provider ID is bounded
at 1 KiB and subject/credential text at 64 KiB each before trimming, within the
64 KiB request-body limit. Omitted or zero `expires_at` defaults to eight hours;
explicit expiry must be future and at most twelve hours. Unsupported timestamps
outside years 1–9999 are rejected.

PostgreSQL reads only the selected provider, tenant-owned link/user, and at most
256 role bindings. Provider fields retain the stored bounds documented for
[trust rotation](#sso-trust-rotation); user/link identity fields and schema
versions are capped at 1 KiB, subject/email/display text at 64 KiB, and status/role
text at 128 bytes. Grant resource fields are capped at 1 KiB. Locked size checks
precede link/user metadata transfer. Oversized stored metadata or more than 256
bindings produces `409`, without truncation, session creation, or a cookie.

Verification happens outside the write transaction. The transaction rechecks
provider trust, link presence, user state and loaded grants before atomically
committing verification, session and both audits. A failed assessment persists
only a safe verification receipt and audit. A storage/audit/commit failure
returns no session secret or cookie. Successful exchange returns the existing
verification/session/secret envelope and sets a Secure, HttpOnly,
SameSite=Strict cookie scoped to `/v1`.

This route does not create idempotency receipts. Repeated valid requests may
issue fresh sessions; no one-time consumption of provider tokens/assertions is
claimed. Only session hashes are stored. Local memory remains non-durable, and
production Ledger startup removal is still pending.

#### Provider Identity Verification Receipts

`POST /v1/provider-verifications` records an administrative assessment, not a
login. It requires `identity:admin` (or admin scope); human sessions additionally
need a matching tenant-wide grant. Current authority and tenant-owned provider
type are checked before idempotency reservation or replay. An inactive provider
may be assessed. No session, role binding, user activation or provider trust
change is performed.

The required fields are `provider_type` (`oidc` or `saml`), `provider_id` and
`subject`. With no credentials, the receipt describes stored metadata and a
verified link only; it does not prove a provider credential. Optional OIDC
`id_token` and SAML `saml_assertion` use configured local public trust. Optional
OIDC `access_token` uses the configured live provider validator, if present;
missing configuration or provider errors cannot become a passed assessment.
OIDC rejects SAML assertions; SAML rejects ID/access tokens.

Both profiles reject malformed, duplicate, unknown, trailing or non-object JSON,
explicit null fields, invalid UTF-8 and NUL text with `400`. Before trimming,
provider IDs are limited to 1 KiB, subject/local credentials to 64 KiB each and
access tokens to 16 KiB, within the 64 KiB body limit. Metadata labels must not
contain a supplied credential. Cookie-authenticated requests require exactly
one HTTPS `Origin` matching the public request Host; proxies must preserve Host.
Deliberate bearer authentication takes precedence over an incidental cookie.

PostgreSQL uses focused Identity commands and bounded tenant-owned provider/link
reads, with the stored field limits from [trust rotation](#sso-trust-rotation)
and [credential exchange](#sso-credential-exchange). Oversized stored rows
produce `409`, without truncating an assessment. Provider/link state, including
link presence, is revalidated and held stable through the write transaction.
Preflight takes the existing worker/audit mutation fence before tenant and
provider/link locks, including when the HTTP transaction keeps those locks.
Receipt, caller-attributed audit and safe idempotency response commit together;
fresh-server replay does not call the provider again. The HTTP idempotency
transaction can hold selected rows while the bounded provider call runs.

Direct application calls persist a failed assessment and its audit before
returning verification failure. The HTTP create contract instead returns `422`,
rolls back that receipt/audit in its outer transaction, and retains only a safe
failed-retry marker; retrying that key returns `409`. Storage/audit/commit
failures expose neither partial receipts nor internal errors.

Provider checks/limitations redact supplied credentials before assessment,
persistence and replay. Local/live adapter output must include named checks in
the documented check-state vocabulary, with at most 256 checks, groups and
limitations each and 256 KiB combined text. Check names/results are limited to
128/64 bytes, details/limitations to 64 KiB each and group values to 1 KiB.
The sanitized assessment is checked again after redaction, including expansion
of text and combined output size. Malformed or excessive output becomes a safe
failed assessment, never truncated success. Group mapping counts are
informational and do not grant access.
Existing JSON fields and versioned assurance profiles are preserved. This route
does not prove provider truth or legal compliance; production Ledger startup
removal remains pending.

#### SSO Public Trust Material

SSO trust normalization is a stateless Identity policy shared by provider
creation, trust rotation and OIDC discovery refresh. Nonempty JWKS is limited
to 64 KiB and 1-10 RSA or Ed25519 public keys with nonempty `kid` and required public
parameters. Recognized private/symmetric JOSE members (`d`, `p`, `q`, `dp`,
`dq`, `qi`, `oth`, `k`) are rejected, even when null, at the root or in a key.
Rejected new creation/rotation commands return `400`; rejected discovery
material produces a verification failure without replacing current trust or
appending an audit.

Only `keys` and supported public JWK members are retained: `kty`, `kid`, `crv`,
`x`, `n`, `e`, `alg`, `use`, `x5u`, `x5t`, `x5t#S256`, `key_ops`, and `x5c`.
`key_ops` and `x5c` must be string arrays; other retained members must be strings.
Unrecognized root/key extensions are omitted, not a metadata storage channel.
SAML normalization retains at most five parsed RSA public certificates, each
at most 16 KiB; only the normalized certificate is returned, not trailing PEM
blocks. This checks supported metadata shape, not provider ownership, key
custody, or the validity of a token/assertion. Never supply secrets in public
fields. Historical records, retained replay receipts and backups are not
retroactively scrubbed; see the
[compatibility and operator note](reference/api-versioning.md#unreleased-sso-public-trust-normalization).

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
| `POST` | `/v1/evidence-summaries` | Create evidence-cited technical summary with assumptions and limitations; see [evidence summary creation](#evidence-summary-creation). |
| `POST` | `/v1/evidence-graph-snapshots` | Persist product/release evidence adjacency snapshot; see [graph snapshot creation](#graph-snapshot-creation). |
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
| `POST` | `/v1/reports/anomaly` | Generate deterministic evidence anomaly signals; see [anomaly report generation](#anomaly-report-generation). |
| `POST` | `/v1/release-candidates` | Create release candidate. |
| `GET` | `/v1/release-candidates` | List release candidates. |
| `GET` | `/v1/release-candidates/{id}` | Read release candidate. |
| `POST` | `/v1/release-candidates/{id}/promote` | Promote release candidate; requires `If-Match` with current revision. |
| `POST` | `/v1/release-candidates/{id}/reject` | Reject release candidate; requires `If-Match` with current revision. |
| `POST` | `/v1/remediation-tasks` | Create remediation task. |

### Anomaly Report Generation

`POST /v1/reports/anomaly` remains experimental. It requires `report:read`,
an `Idempotency-Key`, and nonblank `subject_type` and `subject_id`. Supported
canonical types are `tenant`, `product`, `release`, `evidence`, `build` and
`customer_package`. Raw NUL-free UTF-8 type/ID values are capped at 128/1024
bytes before trimming. Malformed/non-object JSON, null, duplicate/unknown or
mixed-case fields, unsupported types and invalid raw text return `400`.
The independent HTTP body limit remains in force. Cookie-authenticated
mutations require a single same-host HTTPS Origin; bearer credentials retain
precedence over cookies.

PostgreSQL binds focused Experimental commands. Coordinate-only reads resolve
current tenant ownership before reading facts; missing or foreign subjects
return `404`. Human sessions need a matching current tenant, product, project,
release or customer-package grant as appropriate. Tenant-wide subjects and
unscoped evidence need a tenant grant. The same checks run before cached replay.
Report, audit and replay completion share one transaction. Root locks and the
shared writer/worker projection fence remain held through commit. Failed reads,
inserts, audit writes, cancellation or commit publish no successful report.
Operator SQL writes must coordinate with those fences; this is not a claim that
uncoordinated external database edits are serialized automatically.

Release reports use three fixed-size facts from SQL predicates shared with
readiness, not a full readiness snapshot or tenant Ledger. No raw evidence,
scanner details, report packages or signing-key material are returned by the
fact port. The signals, in order, are:

- `missing_passed_build` (medium): no passed build output matches a registered,
  tenant-owned artifact digest linked to release evidence.
- `missing_matching_attestation` (medium): no matching attestation has a passed
  receipt for the current DSSE-attestation signature profile/schema.
- `unhandled_critical_finding` (high): an open critical finding has no current
  matching fixed/not-affected decision or approved unexpired scoped exception.

Malformed stored findings fail validation rather than silently becoming clear.
Decision supersession and exception expiry are evaluated at report creation.
The query result is bounded; database work still scales with the relevant
release records. Other supported subject types currently have no anomaly
checks and return `clear` with omitted `signals`. `attention_required` means
at least one of the three signals was found. Neither result is a malicious-
behavior, evidence-completeness, security or compliance conclusion.

Replay returns the original report without recalculating signals after facts
change. Different request bytes with the same key conflict with `409`; a new
key creates a fresh immutable report. Signal text/order, assumptions,
limitations, schema version and audit type are unchanged. Durable timestamps
use UTC microseconds. Explicit local memory shares the pure signal builder and
input validation, but retains in-process persistence and locking limitations.

### Incident Commands

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/incidents` | Create an incident for a product and optional matching release. |
| `POST` | `/v1/incidents/{id}/timeline` | Append a timeline event with optional evidence. |
| `POST` | `/v1/remediation-tasks` | Create a task for an incident and/or release with optional evidence. |

All three require `incident:write`. PostgreSQL mode binds focused Operations
commands, not Ledger maps. Current tenant-owned parent coordinates are
share-locked through commit, and human sessions need a current tenant,
product, or release grant for the incident. Optional evidence is separately
authorized from its current product/project/release/build/deployment parents;
evidence without narrower parents needs a tenant grant. Every supplied task
reference is independently checked. Authorized incident and remediation
release references may deliberately belong to different products; incident
creation's optional release must match its specified product. Issued
credentials remain scope-bound. Local-memory mode retains its explicit
compatibility path.

JSON envelopes retain the 64 KiB limit. In PostgreSQL mode, null fields
(including optional `due_at`), malformed/duplicate-key/unknown-field bodies,
invalid UTF-8, and NUL bytes fail with `400`. IDs are at most 1024 UTF-8 bytes;
title, timeline event type/summary, and task owner are at most 64 KiB each for
direct commands. Trimmed severity accepts `low`, `medium`, `high`, or
`critical`, case-insensitively. Omitted `opened_at`/`occurred_at` default to
creation time; omitted `due_at` remains absent. New timestamps are normalized
to UTC microsecond precision to match durable reads and replay.

The record, principal-attributed audit, and safe idempotency response commit
together. Current grants and reference ownership are rechecked before replay,
which does not append duplicate records or audits. Command failures can retain
response-free failed-key records; completion/commit failures roll back the
reservation and permit retry. Recorded evidence links and tasks organize
technical evidence; they do not prove incident root cause or remediation
completeness. Signed webhook receivers and ingestion are separate workflows.

### Signed Incident Webhooks

`POST /v1/incidents/{id}/webhook-receivers` requires `incident:write` and a
current incident product or release grant for human sessions. Its JSON fields
are `name`, `provider`, and `public_key`. Public keys contain the 32 Ed25519
public-key bytes in raw or padded standard base64; storage uses raw standard
base64. The private key remains external. Receiver, principal audit, and HTTP
idempotency completion share one transaction, with current parent/grant checks
before replay. IDs are capped at 1024 UTF-8 bytes, name/provider at 64 KiB
each, and encoded key input at 1024 bytes.

`POST /v1/incident-webhooks/{receiver_id}` is public and needs neither a bearer
token nor `Idempotency-Key`. Supply exactly one nonblank value for each header:

- `X-Evydence-Webhook-Event-ID`: the provider event identity.
- `X-Evydence-Webhook-Timestamp`: an RFC3339 timestamp within five minutes.
- `X-Evydence-Webhook-Signature`: the standard-base64 Ed25519 signature,
  optionally prefixed with `ed25519=`.

Sign the concatenation of the timestamp formatted as UTC RFC3339 **seconds**,
a newline, the trimmed event ID, a newline, and the exact raw request body.
Fractional input timestamps still use seconds in this existing signature
protocol. Signature verification precedes payload parsing. JSON supplies
required `event_type`/`summary` and optional `evidence_id`/`occurred_at`.
Omitted `occurred_at` defaults to creation time. Both HTTP bodies retain the
64 KiB limit; direct ingestion permits at most 2 MiB. Explicit null,
duplicate/unknown fields, invalid UTF-8, and NUL fail validation. Receiver and
event IDs are capped at 1024 UTF-8 bytes; event IDs cannot contain interior
CR/LF. The combined tenant/receiver/event replay key is capped at 2304 bytes.
Encoded keys/signatures cannot contain interior CR/LF.

PostgreSQL binds focused Operations ports, not Ledger maps. Bounded point
reads lock the active receiver and coherent current incident/evidence parents
through commit. Evidence must belong to the incident product and, when
release-scoped, its release; tenant-only or different-product evidence is not
within receiver authority. These checks also apply to natural event replay.
Same event ID and identical body bytes return the original receipt/timeline,
even when freshly signed; changed bytes yield `409`. Signature/key failures
yield `401`, missing/inactive/foreign references yield `404`, and malformed
verified inputs yield `400`. Event, timeline, and webhook-attributed audit
commit together; failures leave no public replay reservation and are retryable
with the same provider event ID after the cause is resolved. New timestamps
and durable replay are UTC microsecond precision. Local memory retains its
explicit compatibility path and shares the signing/base64 protocol helpers.
Recorded timelines do not prove incident resolution or remediation completeness.

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

### Vulnerability Scan Ingestion

`POST /v1/vulnerability-scans` requires `evidence:write` and streams generic
scan JSON or a versioned native-scanner envelope up to 20 MiB. See
[evidence-format compatibility](reference/evidence-format-compatibility.md#generic-vulnerability-scan-json)
for the supported adapter schemas and normalization rules.

In PostgreSQL mode, scope-only authorization precedes a complete bounded JSON
token probe for the release ID. This probe verifies declared size and SHA-256
without materializing findings. Normalized release IDs must be nonblank,
NUL-free UTF-8, at most 1024 bytes. The focused Evidence command then checks
current tenant-owned release parents and human resource grants before full
normalization or object staging. The shared parser retains its depth, value,
string, and selected-adapter finding limits. Normalized projections are bounded
to 100,000 findings, 1 MiB per string, and 64 MiB of combined projection strings;
severity summaries must exactly match the findings. Invalid projections fail
validation rather than being truncated.

Scan, evidence, audit, payload metadata, outbox jobs, and idempotency completion
join one transaction, including pending parents in compound commands. A failed
commit leaves no partial database effects; unreferenced staged bytes remain
recoverable through the [payload recovery workflow](runbooks/object-store-recovery.md).
Identical payloads reuse their digest-scoped finalization job, while each new
scan gets its own parser job. New timestamps use UTC microsecond precision.

Same-byte replay retains the existing body-digest fingerprint, rechecks current
ownership/grants, and requires the original tenant and release coordinates.
It still probes the bounded incoming document, but does not normalize findings
or stage objects. Changed bytes return `409`.

With worker-owned parsing and object storage, the upload response contains
parsed findings, while the stored scan initially has empty parser fields and
no findings or summary until its parser job runs. Inline mode, or explicit
development operation without object storage, persists the parsed projection.
Evidence remains `pending`; acceptance does not establish scanner authority,
vulnerability coverage, or release security. Local-memory mode retains its
explicit compatibility path; historical rows and parser identities are unchanged.

Source/test evidence: `internal/evidence/app/vulnerability_scan_ingestion_commands.go`,
`internal/app/evidence_parser_adapter.go`, and
`internal/platform/wiring/vulnerability_scan_ingestion_commands_test.go`.

### VEX Ingestion

`POST /v1/vex` (OpenVEX) and `POST /v1/vex/cyclonedx` require
`evidence:write`. Wrapped JSON supplies `release_id`, optional `artifact_id`,
and `payload` within the existing 64 KiB request limit. OpenVEX also accepts
native `application/vnd.openvex+json` uploads up to 20 MiB, with one nonblank
`X-Evydence-Release-ID` and one optional `X-Evydence-Artifact-ID`. Explicit
null fields, duplicate wrapped fields or native metadata headers, and unknown
wrapped fields are rejected. IDs must be NUL-free UTF-8, at most 1024 bytes;
required IDs must be nonblank. Wrapped source bytes are the `payload` JSON
value, preserving its internal formatting but excluding surrounding envelope
whitespace; native uploads preserve all document bytes. See
[evidence-format compatibility](reference/evidence-format-compatibility.md#openvex-json)
for versions, parser identities, and format-specific limitations.

In PostgreSQL mode, the focused Evidence command resolves and locks current
tenant-owned release parents and checks current release and optional-artifact
grants before full parsing or object staging. Human artifact checks retain the
existing `403` policy for missing or foreign artifacts. The stateless shared
parser verifies the declared source size and SHA-256. Normalized projections
are bounded to 100,000 statements, 1 MiB per string, and 64 MiB of combined
projection strings. The versioned worker decision request additionally permits
at most 1,000,000 values and 20 MiB of combined decision text; normalized
reference expansion beyond these budgets fails validation, never truncation.
Statement indexes, status summaries, and parser versions must agree.

VEX document, accepted import report, evidence, audit, payload metadata,
parser/finalization jobs, and idempotency completion share one transaction,
including pending parents in compound commands. Uploads never write decisions:
normalized VEX metadata and an `accepted` report are always stored, regardless
of the worker-owned parsing flag. The `parse_vex` worker maps decisions after
commit and completes the report. Raw replay verification requires the payload
object; without it, the worker consumes the bounded normalized request.

Replay rechecks current ownership/grants without parsing or staging. Native
OpenVEX fingerprints include metadata headers; retained body-only receipts are
replay-only and require exact tenant, release, optional artifact, and format.
Changed bytes return `409`. Failed commits leave no partial database effects;
unreferenced staged bytes remain recoverable through the
[payload recovery workflow](runbooks/object-store-recovery.md).

New timestamps use UTC microsecond precision; historical rows and parser
identities are unchanged. Evidence remains `pending`. Acceptance does not
establish source authority, signature trust, legal sufficiency, or release
security. Local-memory mode retains its explicit compatibility path.

Source/test evidence: `internal/evidence/app/vex_ingestion_commands.go`,
`internal/app/evidence_parser_adapter.go`, and
`internal/platform/wiring/vex_ingestion_commands_test.go`.

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

#### Marketplace Collector Creation

`POST /v1/marketplace-collectors` requires authenticated `collector:admin`
(or admin/wildcard scope); human sessions additionally need a current
tenant-wide grant. Product, project, or release grants do not authorize this
tenant-wide record. These checks and current reference ownership run before
returning an idempotent replay.

The request is a strict JSON object: exact snake-case fields, no unknown or
duplicate fields, no null values, and at most 64 KiB including whitespace.
All text must be valid UTF-8 without NUL. Bounds apply to raw bytes before
trimming: `name`, `provider`, and `publisher` are 256 bytes each; `version`
and `manifest_hash` are 128 bytes each; optional `signature_id`, `sbom_id`,
and `scan_id` are 1024 bytes each. The five metadata fields are required and
nonblank. The trimmed digest is `sha256:` plus 64 hexadecimal characters;
hex case is preserved. Optional references may be omitted or empty, but
not whitespace-only or null. Each supplied reference must currently belong
to the actor's tenant; foreign or missing references return `404`.

Successful registration returns `201`, state `registered`, the existing
schema and limitation, and omits empty reference fields. PostgreSQL writes
the collector, audit binding to its declared manifest digest, and replay
response atomically; durable timestamps use UTC microseconds. In PostgreSQL,
a duplicate tenant/provider/name/version returns `409`; in both profiles,
a changed raw request under the same idempotency key returns `409`.
Invalid input returns `400`, insufficient
authority `403`, and storage failures safe Problem Details without a success
record. Cookie-authenticated mutations require Origin; Bearer authentication
takes precedence. Local memory shares normalization and authorization rules
and copies returned limitations rather than exposing stored slices.

Registration records metadata and references only. It does not retrieve or
verify package bytes, publish a package, establish marketplace trust, or
endorse a provider. See [API versioning](reference/api-versioning.md#unreleased-marketplace-collector-boundary)
for release-review requirements on tightened input and authorization.

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

### Evidence Summary Creation

`POST /v1/evidence-summaries` accepts `subject_type`, `subject_id`, and optional
`evidence_ids`. Supported roots are `tenant`, `product`, `release`, `evidence`,
`build`, and `customer_package`. Omit the array or send `[]` for automatic
selection. Explicit IDs are trimmed, sorted, non-blank, unique after trimming,
and limited to 512. Subject/evidence IDs must be NUL-free UTF-8 text of at most
1024 bytes after trimming. Null fields/items, malformed/non-object JSON,
unknown or duplicate fields, and invalid UTF-8 are rejected with `400`.

The PostgreSQL profile resolves and locks the tenant-owned root before reading
citations. A human session needs a current `report:read` grant covering that
root (tenant, product, project, release, or customer-security-package as
applicable); issued credentials use their `report:read` scope. Root ownership
and authorization are rechecked before an idempotent replay is returned.
Foreign/missing roots or explicit evidence IDs return `404`; evidence outside
the root's selection coordinates returns `400`.

Selection deliberately retains the stored product/project/release semantics.
For an evidence root, it can include siblings sharing those coordinates. A
build root selects its project/release evidence, not only rows with that build
ID. A customer-package root selects current product/release evidence, not its
frozen manifest; package expiry and redaction are not applied to this internal
summary. Do not distribute it as a redacted customer package. Resolved parent
coordinates authorize the root but do not add inferred selection filters.

Only evidence ID, type, title, and canonical hash become citations. PostgreSQL
preflights lengths and locks selected rows before transferring their text;
payload references, arbitrary metadata, source identity, and package manifests
are not read. It rejects rather than truncates automatic selections above 512
records. Titles are limited to 64 KiB, type text to 128 bytes, and hashes to
1024 bytes. Selected citation text/coordinates and the complete encoded public
summary each have a 4 MiB budget. Summary, caller-attributed audit entry, and
successful replay commit atomically; failures return no summary body.

Cookie-authenticated creates require a single same-host HTTPS `Origin`, while
explicit bearer credentials retain precedence. Local-memory mode keeps its
Ledger-backed report generation with the same request decoder and existing
item/output limits. Response names, deterministic citation order, schema
version, assumptions, and limitations are unchanged. Summaries organize
recorded technical evidence; they do not establish legal compliance,
certification, or release security.

### Graph Snapshot Creation

`POST /v1/evidence-graph-snapshots` requires `evidence:read`, an
`Idempotency-Key`, and at least one non-blank `product_id` or `release_id`.
Raw IDs are bounded at 1024 UTF-8 bytes before trimming and cannot contain NUL.
Both profiles reject malformed/non-object JSON, unknown or duplicate fields,
case aliases, null fields, and invalid UTF-8 with `400`. Cookie-authenticated
creation requires the same-host HTTPS `Origin`; bearer credentials take
precedence. Foreign/missing roots and mismatched product/release pairs return
`404`. Human sessions need a current matching tenant, product, or release grant.

The PostgreSQL profile binds focused Package commands. Current ownership and
grants are checked before replay without reading labels or existing snapshots.
Creation holds the worker/audit fence and current root/evidence/parent locks
through snapshot, audit, and replay commit. Stored labels, IDs, coordinates,
and structured subject references are selected only after length/count
preflight; payloads, source identities, arbitrary metadata, and other snapshots
are never loaded. Storage/audit/commit failures publish no graph result.

Selection retains the submitted stored-coordinate filters. Product-only graphs
include rows with that stored product ID, not rows whose product can merely be
inferred from a release. Release-only graphs can include rows with an omitted
stored product ID; the inferred product authorizes ownership but adds neither a
product node nor a product filter. Nodes are ordered as submitted product root,
release root, then evidence IDs in bytewise order. Evidence edges use the stored
release or, if absent, product parent. Non-empty subject IDs become recorded
`references_<type>` edges; digest-only references add no edge. External/opaque
references and edges to nodes outside this materialized view are not verified
object existence or complete graph traversal.

Limits are 4096 nodes, 8192 edges, 64 KiB per label, 1024 bytes per identifier,
128 bytes per reference type, and 8192 reference records per selected evidence.
PostgreSQL preflights a 4 MiB selected metadata/reference budget; the existing
4 MiB encoded adjacency budget remains. Overflow fails rather than truncates.
The schema version, adjacency-only limitation, and normalized-JSON SHA-256 over
exact `nodes`/`edges` fields remain unchanged. Durable timestamps use UTC
microsecond precision. Explicit local-memory mode uses the same pure graph
builder and current replay guard, but retains its in-process persistence limits.

This is an internal evidence view, not a redacted customer package. Labels and
recorded references can contain sensitive metadata. Existing privacy-safe
replay redaction may alter labels without changing the original stored graph
hash; verify the authorized original snapshot, not a redacted replay projection.
The graph does not prove evidence completeness, reference trust, release
security, or legal compliance.

### Collector Writes

`POST /v1/collectors`, `POST /v1/collectors/{id}/releases`, and
`POST /v1/commercial-collectors` use focused Integration commands in the
PostgreSQL profile. All require `collector:admin` and an `Idempotency-Key`;
human sessions also need a current tenant-wide grant. Issued keys retain their
tenant-scoped credential authority. Guards check current authority before
reservation and replay; explicit local memory retains the Ledger path.

Collector registration atomically commits the collector, HMAC-hashed API key,
audit entry, and replay record. The credential uses the same pepper and format
as authentication; production rejects the local/default pepper. The first
response includes the secret once. Restart replay retains public collector and
key metadata, including the key binding, but never the secret or hash. A lost
initial response cannot recover its secret. Omitted or empty scopes default to
`build:write` and `evidence:write`; the eight build/evidence/source/bundle read
and write scopes are the allowlist, with reads explicitly opt-in.

Names, types, versions, and scopes are trimmed; scopes are sorted without
discarding duplicates. Collector names are unique per tenant. Commercial
identity is `(tenant, provider, name, version)` and requires non-empty allowed
scopes and a SHA-256 manifest hash. Its hash is not whitespace-normalized.
Duplicate creation under a new idempotency key returns `409`; same-key replay
returns the original metadata. No code is downloaded or installed.

Release recording reads only the current collector identity, signature digest
and tenant-owned artifact, SBOM/evidence coordinates, and scan/evidence
coordinates. Parent ownership and parsed/evidence release coordinates must
agree, including before replay. Raw signatures, components, findings, and
unrelated inventories are not transferred. Optional references may be omitted;
all three references produce the historical `evidence_complete`/`healthy`
labels, which describe recorded reference presence, not runtime safety,
scanner authority, or vulnerability absence. A new pin clears previous pins
only if its release and audit commit succeeds.

JSON bodies are limited to 64 KiB; malformed, duplicate/trailing, unknown, or
explicitly null fields and null scope entries return `400`. Text must be valid
UTF-8 and NUL-free. IDs are bounded to 1024 bytes, scalar text to 64 KiB,
scopes to 1024 entries of at most 128 bytes each, and combined indexed identity
parts to 2304 bytes (`tenant + name`, or
`tenant + provider + name + version`). Oversized direct inputs fail before
storage. New timestamps use UTC microseconds. See the
[unreleased compatibility note](reference/api-versioning.md#unreleased-collector-write-boundary).

### Source Repository Creation

`POST /v1/source/repositories` in the PostgreSQL profile uses an Integration-owned
command and native durable replay, without a Ledger clone or publication. Its
read-only guard checks current tenant and ownership before reservation or
completed replay, without reading clone URLs, branch metadata, or prior audit
entries and without allocating IDs or timestamps. It requires `source:write`.
Human sessions need a current product/project grant
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
holds share locks on the submitted project's product/project and, when present,
the existing repository and its actual product/project through the outer replay
commit. Repository, audit and HTTP replay state commit together. A failed write
or commit leaves no repository/audit effects. Early command failures retain a
failed-key marker; replay-completion and outer-commit failures roll back the
reservation. Completed replay preserves the original public JSON, even when
current metadata exceeds fresh-read bounds, and creates no outbox job. The v1
stored schema, response fields, and original request-byte fingerprints remain.

Tenant/project IDs are limited to 1024 UTF-8 bytes. The combined tenant ID,
provider and normalized full name is limited to 2304 bytes so the unique index
fits without text compression. Optional clone URL/default-branch metadata is
limited to 64 KiB; raw bounds are checked before trimming, and text must be valid
UTF-8 and NUL-free. The existing 64 KiB
HTTP envelope limit remains. Non-object envelopes, null string fields,
duplicate fields and unknown fields fail validation. Oversized stored metadata
returns conflict instead of a truncated record. Historical rows are unchanged.
Cookie-authenticated writes require a same-host HTTPS `Origin`; an explicit
bearer credential takes precedence. Local memory shares decoding, input bounds
and current ownership/grant guards, but retains nondurable replay and map-based
storage rather than PostgreSQL transaction guarantees.

The endpoint records submitted metadata only. It does not contact the provider,
fetch the clone URL, verify repository contents or establish provider trust.
Do not include credentials or secrets in repository metadata.

Source/test evidence: `internal/integration/app/source_repository_commands.go`,
`internal/platform/wiring/source_repository_commands_test.go`,
`internal/platform/wiring/source_repository_native_http_test.go`,
`internal/platform/wiring/source_repository_fence_test.go`,
`internal/app/source_repository_creation_authz_test.go` and
`internal/adapters/httpapi/source_repository_commands_test.go`.

### Source Write Replay Boundary

Commit recording, branch upserts and pull-request recording use native durable
HTTP execution in PostgreSQL, not a Ledger clone or publication. Their shared
read-only guard checks current tenant/repository/product/project ownership and
the authenticated actor's grants before reservation and completed replay. A
supplied head is checked only by its current tenant/repository coordinates.
The guard never reads commit author/message data, mutable branch metadata,
provider defaults or PR snapshots, and never uses a clock or ID generator.

The common writer fence precedes tenant, repository and parent locks. Tenant,
product/project and supplied-head share locks survive through the outer replay
commit; the repository serialization lock is held in that same transaction.
Completed replay preserves original public JSON and request-byte fingerprints
without reapplying branch state, adding snapshots or appending audit. Early
command failures retain a failed-key marker; replay-completion and outer-commit
failures roll back the reservation. No outbox job is created.

All three paths check raw input bounds before trimming. Cookie-authenticated
writes require same-host HTTPS `Origin`; explicit bearer credentials take
precedence. Local memory shares decoding, input bounds and current ownership
guards but retains nondurable replay and map storage, not PostgreSQL locking or
bounded stored-metadata guarantees. This migration does not finish API startup
or the remaining CI/source-snapshot HTTP wrappers.

Tests: `internal/platform/wiring/source_writes_native_http_test.go`,
`internal/platform/wiring/source_writes_fence_test.go`,
`internal/integration/app/source_write_guard_test.go`,
`internal/adapters/httpapi/source_writes_native_test.go` and
`internal/app/source_write_replay_guard_test.go`.

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

The [source-write replay boundary](#source-write-replay-boundary) applies.
The adapter takes the worker-projection fence before locking the tenant-owned
repository, which serializes first creation and duplicate SHA reuse. Parent
ownership and existing commit reads are bounded. Commit, audit and successful
HTTP replay state share a transaction; failures roll back, replay adds no
effects, and no outbox job is created. This endpoint migration does not remove
the remaining Ledger-backed CI workflows.

Tenant/repository IDs and raw SHA text are limited to 1024 UTF-8 bytes.
Author metadata is trimmed,
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
returns not found rather than silently clearing an existing head.

The [source-write replay boundary](#source-write-replay-boundary) applies.
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
The [source-write replay boundary](#source-write-replay-boundary) applies.

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
tenant and repository; whitespace-only supplied heads return not found instead of
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

### Customer Portal Lifecycle

In PostgreSQL mode, focused Package commands issue/revoke access and verify
package tokens without Ledger maps or reloads. Issuance and revocation require
`package:write` and, for human sessions, a current matching tenant, product,
release, or customer-package grant. Current package/product/release ownership
is checked before both writes and idempotency replay. Cookie-authenticated
writes require a same-host HTTPS `Origin`; bearer authentication takes precedence.

Creation keeps the existing response fields and `evycp_` token/HMAC format.
Only the first successful response contains `secret`; replay preserves the
existing privacy-safe projection, omitting recipient PII and redacting sensitive
strings rather than returning those fields again. Changed body bytes conflict
with the original key. Replay never generates another token, even after expiry.
New creation/revocation timestamps use UTC microseconds.

Creation IDs accept at most 1024 UTF-8 bytes and recipient/watermark labels at
most 640 bytes before the historical 160-rune/control-character normalization.
Reviewer email labels are lowercased. JSON fields are exact, non-nullable, and
reject duplicate/unknown/mixed-case fields, invalid UTF-8 and NUL. Optional
fields may be omitted. A new token expiry must be in the future. Token/NDA JSON
also uses exact non-nullable fields; NDA labels have the same 640-byte bound.
Browser forms retain their existing 256-byte acceptance-label bound. These
JSON routes retain the 64 KiB body limit. Revocation bodies remain ignored.

Token access resolves at most two prefix candidates, then verifies one locked
credential after acquiring the tenant writer fence. Ambiguous prefixes fail
closed. Raw PostgreSQL-profile token input is limited to 1024 UTF-8 bytes.
Tokens and hashes are never returned in package, HTML, ZIP, audit, or replay
outputs. Access checks token revocation/expiry and current package ownership/
expiry, and reads only the selected package's bounded manifest (at most 8 MiB).
NDA acceptance, portal counters and access/download audit entries commit
together. NDA-required denials commit an audit event; wrong tokens sharing a
live prefix commit a failed-access counter/audit and revoke access on the fifth
failure. Storage/audit/commit failure rolls back every effect. This records
acceptance as evidence; it does not establish legal NDA sufficiency.

HTML keeps escaping, restrictive CSP and no-store/no-referrer headers. ZIP
rendering keeps its existing size limits and sensitive-content guard: an
email-bearing default watermark can be rejected, so use an explicit
customer-safe watermark for distribution. No private payloads are added.
Local-memory mode remains explicit compatibility mode; production Ledger
startup retirement and other extension workflows remain open EVY-905 work.

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
native durable HTTP replay, not Ledger cloning or inventories. Read-only guards
check current tenant-wide administration and tenant existence before every
fresh request and replay; control creation additionally checks its current
tenant-owned framework. The common writer fence precedes tenant/framework
share locks held through outer replay commit, blocking parent reparenting.
Replay does not check duplicate keys or reread installed metadata. Each record,
principal audit and replay result commit together, without an outbox job;
same-key replay returns the original response and changed request bytes
conflict. Duplicate framework
`slug`/`version` or framework/control `code` identities return `409`. Missing or
foreign frameworks return `404`, and denied administration grants return `403`.
New timestamps use microsecond-precision UTC.

Creation text is NUL-free UTF-8 and bounded before trimming. Framework
names/descriptions and control titles/objectives are each bounded at 64 KiB; framework slug/version
fields are each bounded at 1024 raw bytes, and their normalized text together
at 1024 bytes. A blank/omitted slug uses the existing
ASCII name-derived slug; explicit slugs are retained. Framework IDs and control
codes are each bounded at 1024 bytes, and tenant ID plus framework ID plus code
at 2048 bytes. The whole HTTP JSON body remains limited to 64 KiB including
syntax and escapes. Invalid or excessive input returns `400` without resource
or audit writes.

Evidence requirements preserve request order, reject repeated or unsupported
types, and accept freshness from 0 through 3650 days. Each requirement must
include its non-null `required` boolean; `false` is valid. At most ten
requirements are accepted, with each raw type bounded at 1024 bytes.
Applicability is trimmed and sorted without removing duplicates or empty entries; limitations
retain order/duplicates but omit trimmed blanks. Together these two lists are
bounded at 1024 input entries and 64 KiB of input text. Optional arrays may be
omitted; explicit null fields/items are rejected in both runtime profiles.
Both profiles require a same-host HTTPS `Origin` for cookie-authenticated
writes; explicit bearer authentication takes precedence. Local-memory creation
retains compatibility storage and nondurable replay, with the same input bounds
and tenant-wide human administration checks. Evidence linking has a separate
`controls:write` policy described below.

### Control-Evidence Linking

`POST /v1/controls/{id}/evidence` in PostgreSQL mode binds focused Risk commands
and native durable replay, without Ledger cloning or inventories. A read-only
guard resolves the current tenant, control/framework ownership and subject
coordinates before fresh execution and completed-response replay. Human
sessions need a matching current tenant, product, project or release grant;
supplied scope labels do not confer authority. Artifact grants must match a
current evidence/build association, including the build-output digest. Parsed
subjects require coherent source-evidence kind and tenant/parent relationships;
ambiguous finding IDs return `409` rather than choose a scan.

The actor-tenant writer fence precedes tenant/control/framework share locks;
these remain held through outer replay commit. Subject projections use that
shared writer coordination. Replay does not read stored link notes or duplicate
metadata, allocate IDs, or append audit entries. Fresh natural-key reuse returns
the original link without replacing notes/confidence or adding an audit. New
links, principal audits and replay results commit together, with no outbox job.
Changed request bytes under the same key return `409`.

Raw path/subject/scope identifiers and kind labels are bounded at 1024 UTF-8
bytes before trimming, confidence at 64 bytes and notes at 65536 bytes. The
normalized tenant/control/evidence-kind/subject-kind/subject/product/release
tuple is bounded at 2048 bytes. The entire JSON body is limited to 64 KiB;
malformed, duplicate/trailing, unknown or null fields, NUL text and invalid
UTF-8 return `400`. Unsupported subject kinds retain `404` behavior. Cookie
writes require same-host HTTPS `Origin`; bearer authentication takes precedence.

Local memory retains local-map reference behavior and nondurable storage/replay,
with the shared input bounds, current control/framework ownership checks and
local resource grants. It does not establish PostgreSQL parsed-source or writer
coordination guarantees. Linking records technical evidence relationships, not
control effectiveness or framework compliance.

### Control-Framework Template Installation

PostgreSQL template installation uses a focused transaction with the same
tenant-wide administration policy. It appends the framework, all starter
controls, and one installation audit attributed to the authenticated principal.
Starter names, objectives, requirements, limitations, and schema versions are
preserved. A different-key duplicate tenant/slug/version returns `409`; same-key
replay returns the original framework, and changed request bytes conflict.
Current tenant existence and tenant-wide administration are checked on every
retry, including completed-response replay. Revoked/downgraded human grants do
not retain access to an earlier result. Replay neither rereads installed
framework/control metadata nor rechecks duplicate versions, and does not clone
Ledger state. Installation, principal audit and durable replay commit together;
there is no background job. Unsafe cookie-authenticated requests need a
same-host HTTPS `Origin`; explicit bearer authentication takes precedence.
The raw slug must be NUL-free UTF-8 of at most 1024 bytes before trimming;
invalid paths are rejected with `400` before durable replay reservation, and
unknown slugs return `404`. The body is optional; when supplied it must be an empty JSON object
(a blank body retains its existing empty-object behavior). Malformed bodies,
null, arrays, and unknown fields now return `400` in both profiles instead of
being ignored. Local-memory mode retains its compatibility installation
command and nondurable replay, enforcing the same tenant-wide human grant and
raw-slug bounds. Starter packs organize technical evidence, not compliance or
control effectiveness conclusions.

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/questionnaire-templates` | Create questionnaire template. |
| `POST` | `/v1/questionnaire-packages` | Generate evidence-backed responses. |
| `POST` | `/v1/questionnaire-drafts` | Create evidence-backed draft answers for review. |
| `GET` | `/v1/questionnaire-answer-library` | List reusable questionnaire answer drafts. |
| `POST` | `/v1/questionnaire-answer-library` | Create reusable questionnaire answer draft. |
| `GET` | `/v1/reports/security-review-package` | Redaction-aware package report. |
| `GET` | `/v1/reports/cra-readiness-html` | HTML CRA-readiness review content. |
| `POST` | `/v1/reports/pdf` | Create reproducible PDF report package metadata and payload hash; see [PDF report packaging](#pdf-report-packaging). |
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

### Redaction Profile Creation

`POST /v1/redaction-profiles` requires `package:write` and an `Idempotency-Key`.
Human sessions need a current tenant-wide grant; product/release grants alone
cannot create tenant-wide policy. Use a `customer_safe` or `security_review`
preset, or supply a nonblank `name` and nonempty `allowed_types`. Presets retain
their server-owned names, descriptions, allowlists, and excluded fields.
Nonempty `allowed_types`/`excluded_fields` cannot override a preset.

Both profiles validate raw, NUL-free UTF-8 before trimming or deduplication:

- `name`, `description`, and `preset`: at most 65536 bytes each.
- `allowed_types` and `excluded_fields`: at most 1024 submitted entries each,
  with at most 1024 bytes per entry.
- HTTP JSON body: the existing 64 KiB limit; newly encoded profile records:
  at most 4 MiB. OpenAPI character limits do not replace UTF-8 byte limits.

Allowed types are trimmed, sorted, and deduplicated; blank allowed types fail
validation. Excluded fields are also trimmed, sorted, and deduplicated, with
blank entries discarded. Unknown type and field names remain metadata, not new
authorization or proof that a customer export is safe.

Malformed/non-object JSON, duplicate or case-aliased keys, null fields/items,
unknown fields, invalid text, and exceeded bounds return `400`. Some malformed
values previously decoded as omissions are now rejected. Cookie mutations
require a same-host HTTPS Origin; bearer credentials retain precedence.
The established snake_case response and omitted empty optional fields remain.
Creation timestamps use PostgreSQL's microsecond precision. Existing profiles
are neither rewritten nor constrained by these new creation rules.

PostgreSQL creation uses a focused command with no evidence, manifest, signing,
or existing-profile read port. It locks the current tenant identity under the
shared writer/audit fence. Profile, audit, and durable replay writes commit in
one transaction; insert, audit, or commit failure returns no successful profile.
Replay rechecks current package-write authority and tenant existence, returns
the original result without duplicating effects, and rejects changed request
content with `409`. Local memory shares policy rules and current replay
authorization but retains its documented nondurable storage limitation.

### Customer Package Creation

`POST /v1/customer-packages` requires `package:write`, an `Idempotency-Key`,
current tenant-owned `product_id` and `redaction_profile_id`, a nonblank `title`,
and future `expires_at`. Optional `release_id` must belong to that product and
tenant. Human authorization is evaluated against the selected product/release;
package-read authority alone cannot create a package.

Creation now shares focused Package application rules across adapters:

- Raw IDs are limited to 1024 NUL-free UTF-8 bytes and title to 4096 bytes,
  checked before trimming. OpenAPI character limits do not replace byte limits.
- The complete snapshot and final redacted manifest are each limited to 8 MiB,
  JSON depth 32, and 4096 entries per array. Exceeded stored-input bounds return
  `409`; invalid create inputs return `400`. Results are rejected, not truncated.
- Profile allowlists and excluded fields retain the existing manifest format;
  hard exclusions apply even to typed JSON-compatible adapter metadata. The
  manifest hash uses the existing normalized-JSON profile, not a new hash
  version. Created-at timestamps use microsecond precision.
- Fresh creation rechecks expiry after write locks and compares the current
  policy with the snapshot policy. Equivalent timestamp locations and empty
  lists do not count as policy changes. Package and generation audit write
  atomically, with no successful top-level result on insert/audit/commit failure.

Both profiles reject malformed/non-object JSON, unknown fields, duplicate or
case-aliased keys, explicit null fields, invalid UTF-8 and exceeded raw byte
bounds with `400`. The 64 KiB request-body limit applies independently. Cookie
mutations require a same-host HTTPS Origin; bearer credentials retain precedence.
Some previously decoded omissions/aliases now fail validation. Historical
records are not rewritten, and response schemas are not restricted by the new
creation bounds. Existing access/download bounds remain unchanged.

PostgreSQL wiring binds `CustomerPackageCommands`, the complete native snapshot
reader and the durable command executor to this route, with no Ledger-backed
creation or replay dependency. The reader selects the policy and every public
package section in one bounded, read-only repeatable-read view with a fixed
generation time. It publishes no partial view on section or transaction failure.
The write adapter takes the common worker/audit fence before current
tenant/product/release and selected-policy locks. Package, generation audit and
successful replay record commit in one unit of work.

Current human grants, coherent tenant/product/release roots and the selected
tenant-owned policy are checked before reservation, including restart replay.
Missing/foreign roots or a mismatched release return `404`; denied current grants
return `403`; changed request bytes with the same key return `409`. Replay returns
the original safe package without reading evidence or applying a later policy.
An expired original request can still replay during the idempotency retention
window; fresh creation and package access enforce their separate expiry rules.
Command failure may retain only the existing safe failed-key tombstone, never
the package, generation audit, successful replay or private backend error.
Outer-commit failure leaves no successful command effects and the key can retry.

Explicit local memory uses the same request/domain rules and current grant check
before replay, but retains its nondurable compatibility reader. Focused native
reader and HTTP tests cover consistent views, scope, privacy, exact-number
replay, byte limits and transaction failures. They do not establish that broad
API startup is Ledger-free. EVY-905 remains incomplete; see the
[bounded-context ADR](adr/0003-bounded-contexts.md) for the ownership boundary.

### Customer Package Archive Download

`GET /v1/customer-packages/{id}/download` requires `package:read` and the current
tenant, product, release, or customer-package grant applicable to the selected
package. It checks current tenant-owned product/release parents and expiry;
foreign or missing packages return `404`, denied grants `403`, and expired or
invalid stored package state `409`. Package IDs used by focused access must be
NUL-free UTF-8 and at most 1024 raw bytes before trimming. Invalid raw IDs return
`400`, as does an unsafe or oversized archive render.

The PostgreSQL profile reads and locks only the selected package, bounding its
manifest to 8 MiB before transfer. The shared worker/audit fence is taken before
the package row lock. Access count and `customer_package.accessed` audit commit
together, including on repeated or restarted download requests; this GET has
the same established audited-access side effect as the package JSON read.
Audit or transaction-commit failure returns no ZIP and rolls back the count.

After access commits, the existing record-only renderer produces fixed ZIP
entry names, scoped public manifest metadata, verification guidance and HTML.
It does not fetch evidence payloads or rebuild a package from current tenant
state. Existing rendering bounds remain: 10 MiB per file, 4 MiB for generated
HTML, 40 MiB expanded ZIP content, and 32 MiB archive bytes. Responses retain
`Content-Type: application/zip`, attachment filename, `Content-Length`, and
`X-Evydence-Archive-Hash` over the returned bytes. The frozen stored manifest
is not rewritten by access or rendering.

Access auditing is not proof of delivery: a later render or network failure can
leave the already committed access count/audit. No archive headers or bytes are
returned on access or rendering errors. Explicit local memory retains its
storage facade and the same record-only renderer; this does not make local
memory durable or establish a compliance, certification, or secure-release
conclusion.

### PDF Report Packaging

`POST /v1/reports/pdf` requires `report:read`, an `Idempotency-Key`, nonblank
`report_type` and `title`, and at least one nonblank `product_id` or `release_id`.
IDs are NUL-free UTF-8 capped at 1024 raw bytes before trimming; report type is
capped at 128 bytes and title at 64 KiB. Type and title must be single-line
UTF-8 without control characters or Unicode line/paragraph separators. Blank,
malformed/non-object JSON, null fields, duplicate/unknown fields, mixed-case
aliases and invalid text return `400` in both profiles. Existing HTTP body
limits apply independently. Cookie mutations require one same-host HTTPS
Origin; explicit bearer credentials retain precedence.

Current tenant-owned product/release coordinates must agree; missing/foreign
roots or mismatched pairs return `404`. Human sessions need a matching current
tenant, product or release grant. Release-only requests authorize the current
product parent but retain an omitted `product_id` in the record and response.
The PostgreSQL profile uses focused Package commands and coordinate-only reads,
not Ledger maps, evidence payloads, labels or report snapshots. The worker/audit
fence and root locks remain held through report, audit and replay commit.

Configured object storage stages digest/size-verified bytes, lifecycle metadata
and a `finalize_payload` outbox job in the same transaction as the report and
audit. The worker finalizes the object; creation does not claim it is already
finalized. Storage, metadata, outbox, report, audit or commit failure returns no
successful report projection. A failed transaction can leave physical staged
bytes for the documented [object-store recovery](runbooks/object-store-recovery.md)
process; database rows and jobs are rolled back. Production composition requires
an object store supporting transactional staging. Non-production PostgreSQL
without objects remains hash/metadata-only, with no downloadable payload.
Explicit local memory uses the same validated envelope bytes but retains its
in-process persistence/finalization behavior.

Replay rechecks current roots and grants before returning stored metadata and
never regenerates or restages the payload. The existing privacy-safe replay
projection omits `payload_ref` and can redact sensitive title text; the payload
digest remains the digest of the original bytes. Changed request bytes conflict
with `409`; a new key creates a new report record. Schema version and the
limitation are unchanged; durable timestamps use UTC microsecond precision.

The payload is currently a minimal title-only PDF-marked envelope, not a
fully rendered evidence report or a guarantee of PDF-reader interoperability.
`report_type` is descriptive metadata, not a renderer selector. Its SHA-256
covers only payload bytes, not product/release IDs or report-type metadata.
No evidence, findings, citations or report-specific pages are embedded. It
does not establish evidence completeness, legal compliance or certification.

### Questionnaire Template Creation

`POST /v1/questionnaire-templates` creates a tenant-wide definition and requires
`package:write`; human sessions need a current tenant-level grant. Product or
release grants cannot create tenant-wide templates. Name/version and question
IDs/prompts must be nonblank after trimming. Question IDs must be unique after
trimming, and question order is preserved. Optional `control_id` values are
trimmed and must identify current tenant-owned controls with same-tenant
frameworks. Evidence types remain selectors, not claims that evidence exists.
`allowed_fields` remains inert metadata: entries are trimmed and sorted while
duplicates and blank strings are preserved; it is not a redaction policy.

Raw UTF-8/NUL-free inputs are bounded before trimming: 1024 bytes for name,
version, question ID, control ID, evidence type and each allowed field; 64 KiB
for each prompt. There must be 1–512 questions and at most 128 allowed fields
per question. Aggregate input text and the encoded public template each have
a 4 MiB budget; overflow fails instead of truncating. The existing HTTP body
limit still applies independently. Both profiles reject explicit null
fields/items, duplicate/unknown fields, and mixed-case field aliases. Cookie
mutations require one same-host HTTPS Origin; explicit bearer credentials
retain precedence.

PostgreSQL uses focused Package commands, locking only the tenant and selected
control/framework identities after the worker/audit fence. It does not load
other templates, evidence payloads, control objectives, or an answer library.
Template, caller-attributed audit and successful idempotency completion commit
together. Replay retains the body-based fingerprint and rechecks current
tenant-wide authority and referenced control ownership. A different key with
the same tenant/name/version still conflicts. New durable timestamps use UTC
microsecond precision. Historical rows, response fields, schema versions and
optional-field omission are unchanged. Local memory keeps its storage facade,
with the same normalization and current authority/ownership replay checks.

### Questionnaire Answer Library Creation

`POST /v1/questionnaire-answer-library` requires `package:write`, a nonblank
answer, and at least one nonblank `question_id`, `evidence_type`, or `control_id`.
Human sessions need a current matching tenant/product/release grant; entries
without product/release scope require tenant-wide authority. Optional parents
must belong to the tenant and agree. Release-only input resolves the product
for authorization but leaves `product_id` omitted in the stored/public record.
An explicit control must have a current same-tenant framework. Evidence-type
selectors and answer text are recorded drafts, not independently verified facts.

Citation IDs are checked against current tenant-owned evidence and coherent
product/project/release/build/deployment parents. Explicit product/release
filters match the evidence's stored coordinates: an inferred parent does not
make an otherwise nonmatching citation eligible. PostgreSQL selects only
bounded ownership metadata; it does not load evidence payloads, control
objectives, package manifests, or existing private answers.

Raw UTF-8/NUL-free fields are bounded before trimming: 1024 bytes for selectors,
scope IDs and each citation ID; 64 KiB for the answer and each limitation. Limits
are 4096 citation occurrences and 128 limitations. Aggregate input text,
selected citation coordinates, and encoded public output each have a 4 MiB
budget. The complete HTTP body still has its independent 64 KiB limit.
Citations must be nonblank. Citations/limitations are trimmed and sorted, with
duplicates preserved; blank limitations remain inert metadata. Omitted or empty
limitations use the existing human-review warning. Both profiles reject null
fields/items, duplicate/unknown/mixed-case fields, invalid UTF-8 and NUL. Cookie
mutations require one same-host HTTPS Origin; bearer credentials retain precedence.

The PostgreSQL composition root binds the focused Package command. The shared
worker/audit fence precedes selected root/reference locks. Answer, caller audit
and successful body-keyed replay completion commit together. Same-key replay
rechecks current root grants and every referenced ownership boundary; changed
body content conflicts. A different key may create another entry with identical
content. New durable timestamps use UTC microsecond precision. Historical
records, response fields, schema versions and optional-field omission remain
unchanged. Local memory keeps its storage facade with shared validation,
current replay guards and copied result slices. Missing/foreign references fail
with `404`; inconsistent durable citation parents fail with `409`. These drafts
require human review, not customer-package redaction or compliance conclusions.

### Questionnaire Package Creation

`POST /v1/questionnaire-packages` requires `package:write`, one tenant-owned
`template_id`, and optional coherent `product_id` / `release_id` selection.
Human sessions need current matching tenant/product/release grants; omitting
both selection coordinates requires tenant-wide authority. Reusable answer
text is independently authorized under `package:write` before it is read.
Ranking, response order, citation order and fallback wording follow the
[questionnaire selection rules](#questionnaire-draft-creation).

Optional `package_id` is an association with a current tenant-owned customer
package, not an implicit evidence filter. Its current product/release parents
must be coherent and agree with explicit selection coordinates. The association
is separately authorized by tenant/product/release or customer-package grants;
a package-only grant cannot authorize the evidence selection. Release-only
input resolves its product for authorization without adding `product_id` to
selection or output. Association does not download a package, enforce NDA or
expiry, increment access counts, or apply its redaction profile. Generated
answers are technical drafts requiring human review, not customer-safe exports
or compliance conclusions.

PostgreSQL reads bounded selectors, candidate ownership metadata, authorized
winning answer text and citation coordinates, not template prompts, associated
package manifests or raw evidence payloads. Limits are 512 questions, 4096
combined candidate occurrences, 4096 combined citation occurrences, 1024-byte
IDs/selectors, 64 KiB per answer/limitation, 128 limitations per response, and
4 MiB each for selected selector metadata and encoded output. Overflow fails
instead of truncating. Raw input is UTF-8/NUL-free and bounded before trimming;
both HTTP profiles reject null, duplicate/unknown/mixed-case fields. Cookie
mutations require one same-host HTTPS Origin; bearer credentials take precedence.

The worker/audit fence precedes selected root/template/package locks. Package,
manifest-hash-linked caller audit, and successful replay completion commit
together. Response fields, schema version, optional-field omission and the
normalized-JSON response hash remain unchanged. Replay rechecks current roots
and association without reading answer text, and binds canonical credential
scopes and human resource grants. Changed permissions or historical body-only
fingerprints conflict with `409` when current access remains allowed; use a new
key for a new result. Missing current authority still fails authorization.
Local-memory mode retains its explicit storage facade with shared scope/record
validation, current replay guards and copied returned response slices.

### Questionnaire Draft Creation

`POST /v1/questionnaire-drafts` requires `package:read`, a tenant-owned
`template_id`, and optional coherent `product_id` / `release_id`. Human sessions
need a matching tenant, product, or release grant. Each reusable answer is
authorized independently; product authority cannot disclose tenant-wide answer
text. Candidate matching uses any matching question ID, control ID, or evidence
type, then ranks matching question/control/type at 8/4/2 points and each scoped
product/release at 1 point. Newest creation time and ID ascending break ties.
The existing stored-coordinate selection is retained: omitting `product_id`
does not include product-scoped library entries merely because a release has
that parent. Without an authorized answer, control-linked or type-matched
evidence supplies citations, otherwise the response states that none is
recorded. Every citation must belong to the tenant and requested scope.

The PostgreSQL profile reads question selectors and candidate scope metadata,
not template prompts, raw evidence payloads, or every private library answer.
Only the authorized winning answer text is fetched. Limits are 512 questions,
4096 combined candidate occurrences across questions, 4096 combined citation
occurrences, 1024-byte identifiers/selectors, 64 KiB per answer/limitation, and
128 limitations per response. Question/candidate selector text has one 4 MiB
budget; encoded responses and the public draft each have a 4 MiB bound.
Overflow fails rather than silently truncating evidence. Both HTTP profiles
reject null, duplicate/unknown fields, invalid UTF-8/NUL identifiers, and raw
identifier input above 1024 bytes before trimming. Cookie writes require one
same-host HTTPS Origin; explicit bearer credentials retain precedence.

Draft, manifest-hash-linked caller audit, and successful idempotency completion
commit together. The existing normalized-JSON response hash, schema version,
question order, library citation order, sorted fallback citations, and fallback
wording remain unchanged. Replay checks current root access and binds its
request identity to the caller's sorted, deduplicated scopes and human resource
grants: changed permissions return `409` when root access remains allowed,
or the ordinary authorization error when it does not. Use a new key for a new
draft under changed permissions. Permission ordering alone does not change the
fingerprint. Older body-only draft replay keys conflict rather than exposing
answers created under unrecorded authority; historical drafts are not rewritten.
Local-memory storage retains its compatibility command with scoped answer and
citation checks and the same HTTP replay binding. Drafts require human review;
they are not redacted customer packages or compliance conclusions.

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
| `POST` | `/v1/signing-operations` | Invoke the configured signing executor and record a bound receipt; see [signing operation creation](#signing-operation-creation). |
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

### Artifact Signature Recording

`POST /v1/artifact-signatures` requires `evidence:write` (or `admin`) and
records detached signature evidence with status `recorded`; creation does
not verify cryptographic trust. Human sessions retain the current tenant,
product, project or release grant rule: narrower grants need a matching
owned evidence or build association. A build association must match the
artifact's current digest. Foreign/missing artifacts return `404`, and a
removed or inconsistent grant association cannot authorize replay (`403`).

Both profiles require a strict JSON object capped at the existing 64 KiB
HTTP limit. Required fields are `artifact_id`, `algorithm` and `signature`;
optional fields are `key_id`, `payload` and `payload_media_type`. The payload
must be a non-null JSON object; its exact supplied bytes are staged without
re-encoding numbers or fields. Raw IDs are capped at 1024 bytes, algorithm
and signature text at 64 KiB, and media-type text at 4096 bytes before
trimming. Text must be NUL-free UTF-8. Unknown, duplicate, case-aliased,
null, ill-typed, malformed, trailing and oversized input returns `400`.
Cookie mutations require same-origin protection; bearer credentials take
precedence.

PostgreSQL uses native durable execution, not Ledger replay. A read-only
current artifact/grant guard runs before reservation and every replay. The
common writer fence precedes tenant/artifact share locks held through the
outer commit. Fresh signature, payload lifecycle, finalization job, caller
audit and successful replay commit together. Completed retries return the
original public DTO without selecting changed artifact metadata/digest or
staging again. Replay retains only a canonical tenant/digest-bound payload
reference from the versioned DTO; arbitrary paths and unknown sensitive
response fields keep generic redaction. Changed request bytes return `409`,
revoked grants `403` and revoked sessions `401`. Failed delivery keys retain
their `409` policy; recovery uses a new key. Explicit local memory retains
a current-map guard and nondurable replay.

Staging is not finalization. A PostgreSQL failure rolls back durable rows,
not the filesystem side effect; it can leave unreferenced staged bytes for
object reconciliation. Recording or historical delivery does not establish
current cryptographic trust, artifact safety or legal compliance.

### Offline Cosign Verification

`POST /v1/artifact-signatures/{id}/verify-cosign` requires `verify:read` (or
`admin`) and returns `200` only when the full offline profile passes. Humans
need a current tenant-wide verification grant: product or release grants do
not authorize a tenant-owned artifact. The request requires `mode` (`key` or
`keyless`) and `offline: true`. Keyless mode also requires `expected_identity`
and `expected_issuer`; key mode rejects nonblank identity/issuer values.

Both profiles cap the body at 64 KiB, signature IDs at 1024 bytes and optional
identity/issuer values at 4096 UTF-8 bytes before trimming. They reject unknown,
duplicate, case-aliased, null, invalid UTF-8 and malformed fields, as well as
unsupported modes and online requests. Cookie mutations require same-origin
protection; explicit bearer credentials take precedence.

PostgreSQL uses native durable execution. Current authority and flat owned
tenant/signature/artifact coordinates are checked before reservation and every
replay. The common writer fence precedes tenant, artifact and signature locks,
which remain held through the enclosing commit. This replay guard reads no
digest, image, payload, trust-root or previous-verification metadata.
Fresh execution retains finalized tenant/digest-bound object reads capped at
4 MiB, configured Sigstore trust material and the full embedded Rekor-proof
requirement. Both verification receipts, caller audit and successful replay
commit together. Failed or unavailable inspection returns `422`, never a
success envelope, and the HTTP transaction rolls back receipt/audit writes.
The standalone focused command retains its existing failed-observation receipt
semantics; it does not imply a successful HTTP delivery.

Completed replay returns the original receipt without re-reading changed
digests, image metadata, payload lifecycle or trust material, or verifying
again. Changed request bytes return `409`; changed ownership returns `404`,
revoked grants `403` and revoked sessions `401`. A durable failed delivery key
retains its existing `409` failure policy; recovery uses a new key. Explicit
local memory retains nondurable compatibility storage, with current
tenant-level authority checked before replay.

This offline receipt does not prove current trust validity, artifact safety,
provenance completeness, provider runtime integrity or legal compliance. It
does not fetch online trust or silently downgrade an unavailable full profile.

### Offline DSSE Attestation Verification

`POST /v1/build-attestations/{id}/verify-signature` requires `verify:read`
(or `admin`) and a current tenant-owned attestation, source evidence, build,
project, release and product. Human sessions additionally need a matching
tenant, product, project or release verification grant. Both profiles require
an empty JSON object, at most 64 KiB including whitespace, and cap raw IDs at
1024 NUL-free UTF-8 bytes before trimming. Missing, malformed, non-object,
unknown or duplicate input returns `400`. Unsafe cookie mutations require
same-origin protection; explicit bearer credentials take precedence.

PostgreSQL uses native durable execution without a Ledger clone. Before
reservation and every replay, the guard resolves only flat current ownership
coordinates and grants. The common writer fence precedes tenant, source
evidence, parent and attestation share locks, held through the outer commit.
It does not read payload metadata/bytes, trust policies, build outputs or
previous verification results. Missing/foreign attestation or source evidence
returns `404`; inconsistent current parent provenance returns `409`.
Revoked grants return `403` and revoked sessions `401`, including on replay.

Fresh PostgreSQL inspection retains the existing seven-check offline Ed25519 DSSE PAE,
in-toto Statement v1 and SLSA provenance v1 profile. Expected subjects come
from registered release artifacts and build outputs, not parsed attestation
claims alone. Metadata is bounded to 4096 records and 8 MiB; finalized
tenant/digest/size/media-bound payload reads are capped at 8 MiB. Receipt,
caller audit, verification job and successful replay commit atomically.
Failed HTTP inspection returns `422` with no success envelope and rolls back
business effects. The standalone command retains its failed-observation
receipt semantics. Missing usable trust can produce `200` with all required
checks and result `not_verified`; it is not a passing verification.

Completed replay returns the original receipt without re-inspecting changed
metadata, bytes or trust material. Changed request bytes return `409`.
A durable failed delivery key retains its existing `409` policy; recovery
uses a new key. Explicit local memory remains nondurable, with current
owned parents and resource grants checked before replay. The generic
[`POST /v1/verify`](#generic-subject-verification) uses the same focused DSSE
inspection profile with its own native current-scope replay guard.

This offline receipt does not prove current trust validity, certificate-chain
trust, revocation, transparency inclusion, provenance completeness,
CI-provider runtime integrity, artifact safety or legal compliance.

### Generic Subject Verification

`POST /v1/verify` requires `verify:read` (or `admin`) and dispatches a closed
set: `audit_chain`, `evidence_item`, `release_bundle`, `build_attestation`,
`artifact_signature`, `merkle_batch`, `audit_chain_checkpoint`,
`audit_chain_release_manifest`, and `backup_manifest`. Each retains its
existing assurance profile and inspection limits. In particular, artifact
signature metadata can remain `limited`, unavailable DSSE trust remains
`not_verified`, and backup verification checks recorded observations, not a
new live backup or restore rehearsal.

Both profiles require a strict non-null JSON object capped at 64 KiB, with
only `subject_type` and `subject_id`. Raw text is NUL-free UTF-8, bounded at
64 and 1024 bytes respectively before trimming. The type is required;
`audit_chain` permits an omitted or blank ID, while every other type requires
a nonblank ID. Unknown, duplicate, case-aliased, null, ill-typed, invalid
UTF-8, oversized and trailing input returns `400`. Cookie-authenticated
mutations require same-origin protection; explicit bearer credentials take
precedence.

PostgreSQL uses the complete focused dispatcher and native durable replay,
never partial-service or Ledger fallback. Before reservation and every
replay, a read-only guard locks current tenant, subject and required parent
ownership coordinates. The common writer fence precedes those share locks,
which remain held through the outer commit. Human sessions need matching
resource grants for evidence, attestations and release bundles; audit-chain,
Merkle, both checkpoint, backup and artifact-signature profiles require a
tenant-wide verification grant. A release grant alone cannot authorize a
full-chain release-manifest checkpoint.

Completed replay returns the original response without reading changed
payloads, manifests, digests, trust policies or prior verification metadata.
Missing/foreign subjects return `404`; inconsistent or oversized current
ownership can return `409`. Revoked grants return `403`, revoked sessions
`401`, and changed request bytes `409`. Fresh receipts, caller audit,
verification jobs and successful replay commit atomically. Failed HTTP
inspection returns `422` with no success envelope and rolls back business
effects. A failed delivery key retains its `409` policy; recovery uses a new
key. Explicit local memory retains nondurable replay with a current ownership
and grant guard. Historical responses are not rewritten and do not prove
current trust validity, artifact safety, provider runtime integrity or legal
compliance.

### Merkle Batch Creation

`POST /v1/merkle-batches` requires current tenant-wide `keys:admin` authority
and returns `201`. Human sessions need a matching tenant grant. Its only body
fields are optional nonnegative int64 `from_sequence` and `to_sequence`.
Zero or omission selects sequence `1` and the current last sequence on fresh
creation; a nonzero upper bound cannot precede the lower bound. Both profiles
cap the body at 64 KiB and reject unknown, duplicate, case-aliased, explicitly
null, invalid UTF-8 and malformed fields. Cookie-authenticated mutations require
same-origin protection; an explicit bearer credential takes precedence.

PostgreSQL uses focused durable execution without a Ledger clone. Before
reservation and every replay, a current tenant-admin guard locks only the tenant
root through the common writer fence. It does not read chain leaves, audit
bodies or signing keys. Fresh creation takes locks in fence/tenant/chain/leaf/key
order, checks the contiguous nonblank chain index, and reads only the selected
stored entry hashes: at most 4096 leaves within an 8 MiB encoded-view budget.
It retains existing Merkle hashing and local Ed25519 signing. An initial key,
if needed, commits atomically with the signature, batch, caller audit and
successful replay; read, write, completion or commit failure returns no partial
success. No signing-provider network call occurs.

Completed retries return the original range, leaves, root and signature
references without selecting the current chain or signing again. New audit
entries do not extend a replayed default range. Later source/key corruption
does not rewrite that saved result or make it current-validity evidence.
Changed request bytes conflict with `409`; revoked grants return `403` and
revoked sessions `401`. Explicit local memory uses the same request and current
authority rules but retains nondurable storage. Creating a batch commits stored
hashes; it does not independently verify every audit record, establish external
publication, prove release security or make a legal compliance conclusion.

### Recorded Transparency Checkpoints

`POST /v1/transparency-checkpoints` requires current tenant-wide `keys:admin`
authority and returns `201` with state `recorded`. Human sessions need a
matching tenant grant. Required fields are nonblank `batch_id` and `provider`;
at least one of `external_url` or `external_id` must also be nonblank. Text is
trimmed after validating NUL-free UTF-8 and raw byte limits: 1024 bytes for
`batch_id`, and 1 MiB combined across all four application input fields. The
HTTP body has a stricter 64 KiB limit. Both profiles reject unknown, duplicate,
case-aliased, explicitly null and malformed fields. Cookie-authenticated
mutations require same-origin protection; explicit bearer credentials take
precedence.

PostgreSQL uses focused native durable execution. Before reservation and every
replay, a current tenant-admin guard checks a flat tenant-owned batch row;
missing or foreign batches return `404`. The common writer fence precedes
tenant and batch locks, held through the enclosing transaction. Fresh creation
reads only the bounded stored root, not batch leaves, signature arrays or
unrelated tenant state. Its existing canonical hash binds `batch_id`,
`root_hash`, `provider`, `external_url` and `external_id`. The checkpoint,
caller audit and successful replay commit together; write, replay-completion
or commit failures do not return partial success.

Completed retries return the original assertion without reading the current
root or hashing again. Later root corruption does not rewrite that result or
make it current-validity evidence. Changed request bytes return `409`; revoked
grants return `403` and revoked sessions `401`. Explicit local memory keeps
nondurable storage and rechecks current tenant authority before replay.
Provider labels and external coordinates are operator assertions: this command
does not fetch a URL, contact or authenticate a provider, verify publication or
timestamp authenticity, prove release security or make a legal compliance
conclusion. Do not put credentials or secret material in recorded coordinates.

### Backup Manifest Generation

`POST /v1/backup-manifests` requires current tenant-wide `admin` authority,
an empty JSON object (`{}`), and returns `201`. Human sessions need a matching
tenant grant. Both profiles cap the body at 64 KiB and reject missing, null,
non-object, unknown-field, duplicate, case-aliased, invalid UTF-8 and malformed
input. Cookie-authenticated mutations require same-origin protection; explicit
bearer credentials take precedence.

PostgreSQL uses focused native durable execution. Before reservation and every
replay, the current tenant-admin guard locks only the tenant root, not state
rows, audit pages or signing material. The common writer fence precedes tenant
and audit-chain locks. Fresh generation streams the complete declared
`tenant-relational-state.v2` metadata profile in one committed read view,
including append-only decision supersession history. The commitment is bounded
by 32768 rows and 8 MiB of encoded input; overflow returns `409` rather than a
truncated prefix hash. Credential material, replay bookkeeping and raw object
payload bytes are excluded. The emitted `backup-manifest.v2.0.0` records the
state hash, existing resource counts and actual local audit consistency checks.
Failed checks are retained as failed observations. Manifest, caller audit and
successful replay commit together; failures do not return partial success.

Completed retries return the original manifest without reading or hashing
current state or inspecting the current chain again. Subsequent changes or
corruption do not rewrite that result or turn it into current-validity evidence.
Changed request bytes return `409`; revoked grants return `403` and revoked
sessions `401`. Explicit local memory keeps nondurable storage and its distinct
v1 whole-state hash; historical manifests retain their recorded versions.

This endpoint does not create a restorable backup, verify a successful restore,
prove external anchoring or make a legal compliance conclusion. Operators still
need database and object-store backups from the same point in time; use the
[backup and restore runbook](runbooks/backup-restore.md) for that procedure.

### Signed Release Bundle Creation

`POST /v1/release-bundles` requires `bundle:write` (or `admin`) and current
tenant-owned release/product access. Human sessions need a matching tenant,
product, or release grant; a project grant cannot authorize this operation.
The body contains only `release_id`: nonblank NUL-free UTF-8, at most 1024 raw
bytes before trimming. Both profiles cap the body at 64 KiB and reject unknown,
duplicate, case-aliased, explicitly null, invalid UTF-8, and over-budget inputs.
Cookie mutations require same-host HTTPS Origin; explicit bearer credentials
retain precedence.

PostgreSQL uses native durable execution without a Ledger command clone or
whole-state read. Before reservation and every replay, the command fences the
actor tenant, share-locks only the owned release and its owned product, and
checks current scoped authority. Locks remain held through the outer commit.
Missing/foreign roots return `404`; revoked grants return `403` and revoked
sessions `401`, without recording a successful replay.

Fresh creation reads the bounded, complete manifest snapshot in one
repeatable-read view, uses the existing local Ed25519 signature format, and
revalidates the public signing-key lifecycle and signature before insertion.
Private fields and credential/PII-like text are sanitized before hashing and
signing. Retention proofs retain only boolean location-presence facts, not
object paths; the public `sample_object_key_configured` flag remains part of
the signed commitment.
Bundle, signature, caller audit entry, `sign_bundle` job, and successful replay
commit atomically. Command failures may retain only a safe failed-key marker;
replay completion or outer commit failure rolls back entirely.

Same-key/same-bytes replay returns the original public response values, without
reading changed manifest inputs, selecting signing-key material, signing again,
or adding another job/audit. JSON object key order is not significant. Changed
request bytes return `409`. Historical replay does not assert that its signing
key remains active today; use the verification endpoint for a current result.
Replay preserves the flag only in an explicit, already-public, versioned
creation DTO whose manifest still matches its exact hash. Generic redaction
is unchanged. Previously saved, already-redacted replies are not rebuilt or
backfilled from current bundle records.
Explicit local memory retains nondurable compatibility storage and current
scoped access checks. A signed bundle is technical evidence, not a legal
compliance conclusion, complete evidence, or a guarantee of release security.

### Legal Holds And Retention Extensions

`POST /v1/legal-holds` and `POST /v1/retention-overrides` append tenant-scoped
records; they do not edit prior markers, enforce external storage lifecycle,
or establish legal sufficiency. Both require current tenant-wide `admin`
authority. Human sessions need a matching tenant grant; product/project/release
grants do not authorize these administrative records.

Supported subjects are `tenant`, `product`, `project`, `release`, and `evidence`.
PostgreSQL uses Operations-owned commands and native durable replay, without a
Ledger clone or whole-state read. Before reservation and every replay, the
command checks current authority, fences the actor tenant, and locks only the
tenant-owned subject identity. These locks survive through the outer commit;
the marker, caller audit entry, and successful replay are atomic. Audit subjects
remain the original scope type/ID, not the newly generated marker ID. Missing
or foreign subjects return `404`; revoked grants return `403` and revoked
sessions `401`. Failed writes may retain only a safe failed-key marker; replay
completion or outer commit failures roll back entirely.

The JSON body has a 64 KiB limit. Both profiles reject unknown, duplicate,
case-aliased, explicitly null, invalid UTF-8/NUL, and over-budget fields before
execution. Raw UTF-8 bounds before trimming are 64 bytes for `scope_type`,
1024 bytes for `scope_id`, and 64 KiB each for nonblank `reason` and `owner`.
Cookie mutations require same-host HTTPS Origin; explicit bearer credentials
retain precedence. Local memory retains nondurable compatibility storage.

Extensions require a nonzero RFC3339 `retention_until`, normalized to UTC and
later than the fresh command's creation time. JSON-representable UTC years are
`1..9999`. Replay checks input shape and current access, but does not recheck
that historical extension date against today's clock or generate another
marker/audit. Changed request bytes conflict with the existing key. Saved
responses retain ordinary secret/PII redaction; do not put credentials in
reason or owner fields. Retention reports remain records, not provider proof.

### Object Retention Policy Creation And Verification

`POST /v1/object-retention-policies` requires current tenant-wide `admin`
authority; `POST /v1/object-retention-policies/{id}/verify` requires current
tenant-wide `verify:read`. Human sessions need a matching tenant grant;
product/release grants are insufficient. Creation records intent and does not
call the provider or prove object-lock enforcement. Verification without a
configured provider records `not_verified`, not an enforcement claim.

In PostgreSQL mode both routes use focused commands and native durable replay,
without a Ledger clone or whole-state read. Current authorization and tenant
existence precede reservation and replay. Verification additionally locks only
the current tenant-owned policy identity: replay does not load changed receipt
metadata or repeat a provider call. The common tenant mutation fence precedes
tenant/policy/audit locks, which remain held through the outer transaction.
Fresh verification reads one bounded policy and compares the complete original
snapshot before writing, so even same-status receipt races fail closed.

Policy changes, their caller audit entry, and successful replay commit together.
A same-key retry returns the original public result, including its safe
tenant-prefixed sample `object_key`; changed request bytes return `409`.
Private payload references and credential-like text retain ordinary replay
redaction. Previously stored, already-redacted replay records are not rebuilt
or backfilled from current policy data. Revoked tenant grants return `403`,
revoked sessions `401`, and
missing/foreign policies `404`. Command failure may retain a safe failed-key
marker without a result; replay-write or outer commit failure rolls back
entirely. A provider observation cannot be rolled back by database failure,
and a fresh retry may therefore observe the provider again.

Both profiles cap the JSON body at 64 KiB and reject unknown, duplicate,
case-aliased, explicitly null, invalid UTF-8/NUL, and over-budget inputs.
Name, mode, object prefix, and object key are bounded at 4096 raw UTF-8 bytes
before trimming; verification IDs have a 1024-byte raw bound. Retention days
must be `1..2147483647`. The maximum observation age defaults to 24 hours;
an explicitly supplied value must be `1..8784`. A blank optional prefix
defaults to `tenants/<tenant_id>/`; sample keys must be under the chosen
tenant-owned prefix, and `require_legal_hold: true` requires a sample key.
Verification accepts `{}` and retains legacy blank-body compatibility.
Cookie-authenticated mutations require a same-host HTTPS Origin; explicit
bearer credentials retain precedence. Local memory keeps nondurable replay
and the same normalization and current tenant-wide authorization rules.

### Signing Provider And DSSE Trust Configuration

`POST /v1/signing-providers` records a provider type and credential-free key
reference; it makes no provider request and does not establish key custody.
`POST /v1/dsse-trust-roots` records an operator-supplied 32-byte Ed25519 public
key and policy. Registration does not verify builder identity or provenance.
Never submit private keys, passwords, tokens, or embedded reference credentials.

Both operations require current tenant-wide `keys:admin` authority. Human
sessions need a matching tenant grant; product/release grants cannot administer
trust configuration. PostgreSQL routes use focused commands and native durable
replay, with no Ledger read or command clone. Authorization and tenant existence
are checked before reservation and every replay. The common tenant mutation
fence precedes tenant/audit locks and remains held through metadata, audit, and
successful replay commit. A same-key retry returns the original record; changed
request bytes return `409`. Revoked grants return `403`, revoked sessions `401`,
and missing tenant roots `404`, without creating a record or successful replay.
Command failure can retain only a safe failed-key marker, without a result;
replay-write and outer commit failures roll back entirely.

The whole JSON body is capped at 64 KiB. Both profiles reject unknown,
duplicate, case-aliased, explicitly null, invalid UTF-8/NUL, and over-budget
fields before execution; trust-root arrays also reject null items. Provider
name/type/reference and trust-root name/algorithm are bounded at 4096 raw UTF-8
bytes before trimming; trust-root key ID is bounded at 1024 bytes and its base64
public key at 128 bytes. Provider types and trust-policy values are enumerated
in OpenAPI. `encrypted` remains optional (default `false`); local encrypted
development and native PKCS#11 types require it to be `true`.

The three trust-policy lists share a raw budget of 4096 entries and 1 MiB of
UTF-8 text, with 4096 bytes per entry; the smaller HTTP body limit still applies.
Existing trimming and sorting are preserved; normalized lists must be nonempty
and contain no blank or duplicate values. Newly rejected oversized
whitespace-padded scalars, aliases, and null array items are malformed-input
compatibility restrictions, not stored-record or schema changes. Unsafe
cookie-authenticated requests require a matching HTTPS origin; explicit bearer
credentials retain precedence. Local memory shares validation and current
tenant-admin checks but retains nondurable replay. Broad API startup and other
unmigrated operations still depend on Ledger; EVY-905 is not complete.

### Public Transparency Metadata

`POST /v1/public-transparency-logs` and `POST /v1/public-transparency-log-entries`
record configuration and declared publication metadata. They make no outbound
request, publish nothing to a provider, and do not establish inclusion or
public-log trust. A nonblank `public_key` is operator-supplied public metadata,
not a cryptographically validated trust root; never submit private key material.
The separate verify/fetch-proof operations assess proof material.

Both metadata operations require `keys:admin` (or admin/wildcard scope);
human sessions additionally need a current tenant-wide grant. Product/project/
release grants are insufficient. Authorization, current tenant existence,
and supplied-reference ownership are checked before idempotent replay.
Cookie mutations require Origin; Bearer takes precedence over cookies.

Requests are exact non-null JSON objects, with no unknown, duplicate or
mixed-case fields, valid UTF-8 without NUL, and at most 64 KiB including
whitespace. Raw byte limits apply before trimming. Log creation requires
`name` (256), `endpoint` (4096), and `public_key` (16384); all must be nonblank.
The endpoint must parse as absolute `https://` with a host, no userinfo, and
no fragment. This syntactic validation is not endpoint/provider verification.
Publication requires nonblank `log_id`, `checkpoint_id`, and `external_id`
(1024 bytes each). The log, checkpoint, and linked Merkle batch must all
currently belong to the actor tenant; foreign or missing roots return `404`.
Malformed/oversized stored Merkle-root digests fail validation, not truncation.

Responses preserve `201`, state `configured` or `published`, existing schema
versions, and snake-case fields. The entry hash remains normalized canonical
JSON over `log_id`, `checkpoint_id`, the exact recorded `merkle_root`, and
trimmed `external_id`. Creation/publication returns no inclusion-verification
fields. PostgreSQL records metadata, audit, and replay together with UTC
microsecond timestamps. Changed raw request bytes under the same key return
`409`; denied authority returns `403`, bad input `400`, and storage failures
safe Problem Details without publishing a success response. Historical
records are not rewritten. See [API versioning](reference/api-versioning.md#unreleased-public-transparency-metadata-boundary)
for compatibility-review requirements.

### Public Transparency Proof Verification

`POST /v1/public-transparency-log-entries/{id}/verify` accepts the required
`root_hash`, `leaf_index`, `tree_size`, and `inclusion_proof` fields, plus an
optional `leaf_hash`. The JSON object uses exact field names; duplicate,
unknown, missing required, and null fields/items are rejected. It cannot set
the internal fetched-proof source marker. The body limit is 64 KiB. IDs are
capped at 1024 raw bytes; each digest at 128 raw bytes before trimming. Values
must be NUL-free UTF-8; normalized digests have `sha256:` and exactly 64 hex
digits. Blank/omitted `leaf_hash` defaults to the published entry hash. Proof
arrays contain at most 64 nodes; empty arrays are valid input. `tree_size` is
positive and `0 <= leaf_index < tree_size`.

Both profiles require current tenant-wide human `keys:admin` authority (or an
issued credential with that scope), and a current tenant-owned entry, log,
checkpoint, and matching Merkle batch before execution or replay. Cookie
mutations require Origin validation; bearer credentials retain precedence.
PostgreSQL reads one bounded entry, not old check/limitation arrays, log keys,
endpoints, or Merkle leaves. The entry and root chain remain locked through
atomic assessment, audit, and replay commit. Compare-and-swap includes the
previous proof hash/time and publication coordinates, not just terminal state.

Well-formed material returns `200` with `inclusion_verified` or
`inclusion_not_verified`. Passing requires exact normalized leaf-string binding
and local RFC6962-style root recomputation; it does not authenticate the
supplied root or establish public-log trust. The proof commitment preserves
the existing canonical field names, omission of operator-source metadata,
and empty-proof JSON `null` normalization. Changed raw request bytes under the
same key return `409`; changed authority or ownership cannot reuse a saved
success. Storage/commit failures return safe Problem Details, not a success
assessment. Historical audit entries are not rewritten. Production startup
Ledger retirement remains EVY-905 work.

### Public Transparency Proof Fetching

`POST /v1/public-transparency-log-entries/{id}/fetch-proof` accepts no input
parameters. An absent/whitespace-only body or an exact empty JSON object is
accepted; other values, duplicate/unknown fields, and trailing JSON are rejected
before fetching. The body limit is 64 KiB and IDs are capped at 1024 raw,
NUL-free UTF-8 bytes before trimming. Raw request bytes remain the idempotency
fingerprint, so changing an empty body to `{}` under the same key returns `409`.

Both profiles enforce the same current tenant-wide authority, owned root chain,
and cookie-Origin policy as [operator verification](#public-transparency-proof-verification),
before fetching or returning a saved result. PostgreSQL selects one bounded
entry and at most 4096 raw bytes of log endpoint text, without log public keys,
names, old diagnostics, or Merkle leaves. The endpoint must be structured HTTPS
without credentials/fragments. Existing direct/gateway HTTP adapters retain
their outbound-host, redirect, address and response-size checks. A disabled
fetcher returns `400` without a provider request.

The fetch call has a 30-second maximum context deadline, or an earlier parent/
adapter deadline. PostgreSQL holds the actor-tenant worker/audit fence and
entry/root-chain locks during the call and through local audit/replay commit;
this administrative operation can delay other mutations in that tenant while
the provider responds. Current entry commitments, assessment hash/time, and
endpoint are compared again before writing. Local memory freezes the same
snapshot and rejects changes during fetching.

Provider material is input to the existing local proof verifier, not an
authenticated public-log trust assertion. Optional returned external IDs must
match; digest strings and proof-node counts use the operator-verification
bounds. Provider checks/limitations are discarded, not copied into assurance.
Successful local processing returns `200` with the passing/failing assessment
and the preserved `source: fetched` proof commitment. Invalid/unavailable
provider material returns safe `422`; request cancellation propagates without
publishing an assessment. A replay does not refetch. Local transaction rollback
cannot undo remote observation/logging; a retry after a failed commit may fetch
again. Production startup Ledger retirement remains EVY-905 work. See
[API versioning](reference/api-versioning.md#unreleased-public-transparency-fetch-boundary)
for compatibility review.

### SaaS Profile Creation

`POST /v1/saas/profiles` records experimental hosted-deployment intent only.
It does not provision a deployment, enforce the requested isolation model,
validate region availability, or certify readiness. It requires an authenticated
actor with the exact issued `instance:admin` scope and an `Idempotency-Key`;
tenant `admin` and `*` do not confer this authority.

The body has exactly four non-null string fields: `name`, `region`,
`admin_tenant_id`, and `isolation_model`. Both runtime profiles reject malformed,
non-object, duplicate, unknown, mixed-case, null, invalid UTF-8 and NUL-containing
inputs with `400`. Raw byte caps, applied before trimming, are 256 for name,
128 for region, 1024 for admin tenant ID, and 256 for isolation model.
All normalized values must be nonblank. The independent 64 KiB body limit
returns `400` with a `/body` `invalid_size` violation before command invocation.
Cookie mutations require a single same-host HTTPS Origin; bearer credentials
take precedence over a cookie.

The profile belongs to the actor's tenant. An explicit instance administrator
may intentionally reference another existing tenant as `admin_tenant_id`;
this is not tenant-level delegation. Both tenant roots must currently exist,
including before completed replay, or creation/replay returns `404`.
PostgreSQL reads at most two tenant IDs, not tenant names, secrets, evidence,
or a Ledger snapshot. Tenant key-share locks prevent deletion through commit
and remain compatible with opposite-direction admin references. The actor's
tenant also holds the shared writer/worker projection fence.

Profile, audit and successful replay completion share one database transaction.
Failed insert, audit or commit publishes no successful profile. Completed replay
returns the original result without another profile/audit; changed request bytes
using that key return `409`. Current issued authority is required for every
request, including replay. The status remains `proposed`, the schema remains
`saas-edition-profile.v1.0.0`, and the limitation explicitly states intent only.
The existing normalized-JSON configuration hash commits to the four raw field
values under the legacy `Name`, `Region`, `AdminTenantID`, and `IsolationModel`
keys; trimming stored labels does not change that commitment. Durable timestamps
use UTC microseconds. Explicit local memory shares input/actor rules, hashing,
record construction and copied limitations, but retains in-process persistence
and locking limitations. Historical records are not rewritten.

### Signing Operation Creation

`POST /v1/signing-operations` requires `keys:admin` (or admin), an
`Idempotency-Key`, and exactly `provider_id`, `subject_type`, `subject_id`,
and `payload_hash`. Human sessions also need a current tenant-wide grant;
a product/release grant is insufficient. Supported canonical subjects are
`tenant`, `product`, `release`, `evidence`, `build`, and `customer_package`.
The provider and subject must currently belong to the actor's tenant. Missing
or foreign roots return `404`; inactive providers return `422` without signing.
These checks also run before completed replay. Cookie-authenticated mutations
require a single same-host HTTPS Origin; bearer credentials take precedence.

Both profiles reject malformed/non-object JSON, duplicate/unknown/mixed-case
fields, null and caller-supplied signature fields with `400`. Raw values must
be NUL-free UTF-8: provider/subject IDs are capped at 1024 bytes, subject type
and payload hash at 128 bytes, all before trimming. The normalized hash is
`sha256:` followed by exactly 64 hexadecimal digits; hexadecimal case is
preserved. The independent 64 KiB JSON body limit returns `400` with a
`/body` `invalid_size` violation before command invocation when exceeded.

PostgreSQL binds focused Verification commands. A bounded provider point read
and coordinate-only subject reads replace tenant Ledger reconstruction.
Provider metadata selects only type/status/key reference, with 128/128/4096
byte caps. Parent/provider locks and the shared writer/worker projection fence
remain held through signing, receipt/operation/audit writes, and replay commit.
No provider private key or raw evidence payload is selected. Operator SQL writes
must respect the same fences; external database edits are not automatically
serialized by this contract.

The configured executor signs the canonical `evydence-provider-signing.v1`
request, not raw uploaded bytes. Its SHA-256 commitment includes tenant,
provider/type/key reference, subject/type, the declared payload hash, a fresh
request ID, and nonce. The response must match provider/type/key reference,
canonical hash, and request ID. Signature text is capped at 32768 bytes;
algorithm labels at 128; optional executor key/receipt IDs at 1024. At most
64 executor checks are accepted, each with a 128-byte nonblank name, a
`passed` or `skipped` result, and at most 4096 bytes of detail. Malformed,
mismatched, oversized or failed-check responses return `422` before ledger
writes. Optional provider diagnostic metadata is redacted before persistence.
The operation exposes a signature reference, not signature bytes or key material.

Receipt, operation, audit and successful replay completion are atomic in the
database. Cancellation or a failed read/write/commit publishes no successful
operation. A retryable provider failure returns `503` without a terminal replay
marker. Completed replay returns the original result without invoking the
signer; different request bytes using that key conflict with `409`.

A completed provider call cannot be rolled back with the database transaction.
After an ambiguous provider failure or database commit failure, another attempt
may invoke the provider again with a fresh request ID/nonce. This is not a claim
of provider-side exactly-once execution. Durable timestamps use UTC microseconds.
Explicit local memory shares canonical hashing and receipt validation, checks
provider status/key binding again after signing, and copies stored checks, but
retains in-process persistence/locking limitations. No executor means new
operation creation is disabled with `400`. A passed operation does not verify
uploaded artifact bytes, release security, key custody or legal compliance.

### Signing-Key Lifecycle Commands

`POST /v1/signing-keys/rotate` accepts only a nonblank `reason` and returns
`201` with public key metadata. `POST /v1/signing-keys/{id}/revoke` returns
`200` and additionally accepts `semantics` and `historical_validity_policy`.
Their defaults remain `ordinary` and `preserve`; ordinary revocation requires
`preserve`. Compromised keys can use `preserve`, `invalidate_from_compromise`
or `invalidate_all`. Existing local Ed25519 formats and signature-validity
rules are unchanged; these commands do not call an external signing provider.

Both profiles reject unknown, duplicate, case-aliased or explicitly null fields,
invalid UTF-8/NUL and over-budget input. The JSON body is capped at 64 KiB;
raw reasons at 4096 bytes, key IDs at 1024 bytes, and policy fields at 64 bytes
before trimming. Unsafe cookie-authenticated requests require same-origin
protection; an explicit bearer credential takes precedence.

In PostgreSQL, focused durable execution checks current tenant-wide
`keys:admin` access before reservation and replay. Human sessions need a current
matching tenant grant. Missing or foreign revocation keys return `404`; denied
authority returns `403`. The common tenant writer fence precedes tenant/key/audit
locks. Revocation replay locks a flat owned key row, without decoding lifecycle
metadata or selecting private bytes. Guard locks remain through the enclosing
transaction, and lifecycle changes, caller audit and successful replay commit
together. Read, write, completion or commit failure publishes no successful
result or partial lifecycle change.

Completed retries return the original public result without generating another
key or repeating revocation. Changed request bytes conflict with `409`.
Replay does not assert current key validity: later key revocation, rotation or
oversized metadata does not rewrite a historical response. Current access and
revocation-target ownership are still required. Explicit local memory uses the
same input rules and current access checks but retains nondurable persistence.

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

#### Security-document uploads

The three security-scan/manual-document upload routes require `security:write`,
not `evidence:write`. In PostgreSQL mode they use focused commands rather than
loading Ledger state. Current product/release ownership and human tenant,
product, or release grants are checked before parsing or staging. An optional
scan artifact also needs current ownership. A scoped human artifact grant
requires an authorized evidence/build association; a build association must
match its digest. Tenant-wide human grants and issued credentials do not need
a narrower association; credentials remain scope-bound. Local-memory mode
keeps its explicit compatibility path.

Requests remain JSON envelopes capped at 64 KiB; there is no native streaming
upload route for these documents. Null metadata/payload, duplicate keys,
unknown envelope fields, and malformed reduced scan documents return `400`.
Coordinate IDs must be NUL-free UTF-8, at most 1024 bytes. Scan categories are
`sast`, `dast`, `secret_scan`, `license_scan`, and `api_security`. The
API-security convenience route fixes `api_security` and rejects a supplied
`category`. Omitted `format` defaults to `generic`; reduced generic mode reads
`findings[].severity`, while reduced SARIF mode reads a non-empty `version` and
`runs[].results[].level`. This is not complete SARIF or native scanner support.
Direct command inputs are capped at 20 MiB, with 100,000 findings, 1 MiB per
summary label, and 8 MiB combined summary labels; overflow fails closed.

Manual document types are `threat_model`, `security_review`, and
`pen_test_report`; sensitivity is `internal`, `confidential`, or `restricted`.
`payload` may be any non-null JSON value. Its exact JSON-encoded bytes are
retained, including quotes for a string value; it is not executed or converted
to plain text. Omitted `media_type` defaults to `application/octet-stream`.

Evidence, accepted document metadata, staged-payload metadata, finalizer job,
two principal-attributed audit entries, and safe replay completion commit in
one transaction. Current grants are rechecked before replay; replay does not
parse, stage, or append duplicate effects. The initial response can include
tenant-scoped `payload_ref` metadata, not a public download URL. The central
privacy policy omits that field from stored/replayed responses while retaining
safe IDs, hashes, counts, flags, and timestamps. A failed command rolls back
document effects but can retain a response-free failed-key record.

Raw payload bytes never appear in these responses. Secret-scan `redacted` and
`quarantined` flags record policy metadata; they do not prove that stored raw
bytes are scrubbed or safe to distribute. Manual evidence needs human review,
and scanner evidence does not establish finding authority, release security,
or legal sufficiency.

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
