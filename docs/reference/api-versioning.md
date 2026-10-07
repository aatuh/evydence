# API Versioning And Deprecation

Evydence exposes its public HTTP contract below `/v1`. This policy makes API
changes reviewable and reversible where possible. It does not assert release
security, legal compliance, certification, complete coverage, or customer
upgrade success without operator review.

The generated [`openapi.yaml`](../../openapi.yaml) is the machine-readable
contract. [API Reference](../api.md) is the integration entry point, while
[Upgrade And Compatibility Policy](upgrade-compatibility-policy.md) is the
operator-facing upgrade policy.

## Compatibility Gate

`make openapi-breaking-check` compares the generated contract with the
selected release artifact in [`openapi-baseline.json`](openapi-baseline.json).
The manifest records the release tag, published asset URL, artifact path, and
SHA-256. The gate verifies that digest before it compares contracts.

The CI workflow downloads the pinned `oasdiff` `v1.29.1` Linux binary, verifies
its published SHA-256, and runs the same command. Local callers provide that
exact executable through `OASDIFF_BIN`:

```sh
OASDIFF_BIN=/path/to/oasdiff make openapi-breaking-check
```

The comparison fails for an operation or path removal, operation-ID change,
new required request fields or parameters, request-shape restriction, changed
scopes or idempotency-key policy, removed response status or required response
field, response type changes, and enum changes. The gate treats additions and
removals in `components.schemas.ErrorCode` as client-visible compatibility
changes because typed SDK switches can be exhaustive.

The gate never fetches a baseline or resolves external OpenAPI references. It
uses only the checked-in release artifact and invokes `oasdiff` with structured
arguments and external-reference loading disabled.

## Unreleased Custom Report Template Boundary

Definition creation and metadata-only materialization now use native durable
PostgreSQL execution. Current tenant-wide report permission and template
ownership precede completed replay without definition reads or output generation.
Template text remains inert; subject labels remain nondereferenced, output
whitespace semantics and hashes are unchanged. New durable timestamps use UTC
microseconds; historical records and schema versions are not rewritten.

Both profiles now reject null/aliased fields/items, raw over-budget or NUL text,
oversized normalized index keys and unsafe cookie origins. See
[Custom Report Templates](../api.md#custom-report-templates). These unreleased
restrictions require compatibility review and are not approved baseline
exceptions or evidence of security/compliance conclusions.

## Unreleased Generic Evidence Creation Boundary

`POST /v1/evidence` now uses native durable PostgreSQL execution and current
parent/subject ownership and grants before completed replay. Original-byte
fingerprints, route/DTO/schema versions, optional coordinates, unknown subject
labels, artifact digest checks on fresh creation and opaque-reference replay
omission remain unchanged. Both profiles now reject null/aliased fields/items,
raw over-budget or NUL text, UTC-out-of-range times and unsafe cookie origins.
See [Generic Evidence Creation](../api.md#generic-evidence-creation).

Numeric metadata is decoded without transport rounding; the existing float64
hash-normalization limitation remains documented and no historical hashes or
records are rewritten. Cancellation and missing-scope checks still precede
generic input validation. These unreleased input/authorization restrictions
are not approved release-baseline exceptions or verification of uploaded bytes,
provenance, security or compliance.

## Unreleased Deployment Creation Boundary

Environment creation and deployment recording now use native PostgreSQL durable
execution. Current tenant/product/release and referenced-resource ownership and
grants are required before completed replay; newer private metadata and clocks
are not replay authority. Routes, schemas, original-byte fingerprints, natural
environment-name reuse, duplicate artifact references and timestamp defaults
remain unchanged. New durable environment timestamps and reuse reads use UTC
microsecond precision to avoid response drift after persistence.

Both profiles now enforce raw byte limits before trimming, exact-case non-null
JSON and same-host HTTPS cookie origins with Bearer precedence. UTC-normalized
deployment timestamps must remain in years 1 through 9999; no timestamp-ordering
rule was added. See [Deployment Environment Creation](../api.md#deployment-environment-creation)
and [Deployment Event Recording](../api.md#deployment-event-recording). Clients
should omit optional fields rather than send null. These restrictions are not
approved release-baseline exceptions. Historical records are not rewritten;
recording is not verification of an actual deployment or runtime security.

## Unreleased Dedicated DSSE Verification Boundary

The dedicated attestation-signature route now uses focused PostgreSQL
execution and checks current parent ownership and resource grants before
returning a replay. Valid tenant/product/project/release grants, receipt
schemas, seven-check offline profiles, and conservative `not_verified`
results are preserved. Both profiles now reject missing bodies, unsafe
cookie origins, malformed/non-object input, and raw IDs beyond the byte
limit documented in [API Reference](../api.md#offline-dsse-attestation-verification).
Inconsistent current parents cannot authorize historical delivery. These are
input/authorization restrictions, not approved release-baseline exceptions.
Historical receipts are not rewritten; no release or provider-runtime
assurance is claimed.

## Unreleased Generic Verification Boundary

`POST /v1/verify` now uses focused PostgreSQL execution and checks current
ownership and grants before completed replay. Its nine subject types, receipt
schemas and existing assurance profiles are preserved. Both profiles now
enforce exact-case, non-null JSON fields, a 64 KiB body limit, raw text byte
limits before trimming, and cookie-origin protection. Missing or inconsistent
current parents cannot authorize historical delivery. Human grants for
tenant-wide audit, checkpoint, backup and artifact-signature profiles cannot
be replaced by a narrower release/product grant. See
[Generic Subject Verification](../api.md#generic-subject-verification) for
the input and replay contract. These are input/authorization restrictions,
not approved release-baseline exceptions; old receipts are not rewritten and
the migration does not claim current trust or provider-runtime assurance.

## Unreleased Artifact-Signature Creation Boundary

Artifact-signature creation now uses native PostgreSQL execution and checks
current artifact ownership and write-grant associations before replay. The
recorded status, signature DTO, request-byte fingerprint and 64 KiB HTTP
limit remain unchanged. Both profiles now enforce exact-case non-null fields,
an optional object-shaped payload, raw byte limits before trimming, and cookie
origins. See [Artifact Signature Recording](../api.md#artifact-signature-recording).
The narrow public replay projector retains a canonical tenant/digest-bound
payload reference, not arbitrary storage locations or raw payloads. Historical
rows are not rewritten. These input/authorization restrictions are not
approved release-baseline exceptions, and recording is not trust verification.

## Unreleased Answer-Library Creation Boundary

Answer-library creation now uses focused PostgreSQL commands. Human
tenant/product/release grants, stored-coordinate citation filtering, sorted
duplicate references/limitations, release-only response omission, the default
human-review warning, schema versions and response fields are preserved.
Different-key duplicate content remains allowed; same-key replay keeps its
body fingerprint and rechecks current root grants and all cited/control parent
ownership. New durable timestamps use UTC microsecond precision.
Creation and inventory handlers require focused ports, without aggregate
fallbacks. PostgreSQL is required for local evaluation; test-only adapters
retain actual guards, isolated writes and detached result/page metadata.

Creation now applies the byte/count/output limits in
[API Reference](../api.md#questionnaire-answer-library-creation), checks current
same-tenant control frameworks and coherent citation parents, and rejects
blank citations, explicit null fields/items, mixed-case aliases, invalid
UTF-8/NUL input and unsafe cookie origins. Clients should omit optional fields
instead of sending null and must stay within the complete 64 KiB HTTP body
limit. Release parents are used for authorization, not to widen raw selection.
These are input/ownership restrictions; historical rows and response schemas
are not rewritten. This note does not approve the outstanding release-baseline
compatibility change set or claim a release, customer-package redaction,
evidence completeness or compliance conclusions.

## Unreleased Candidate Transition Schema Correction

`ReleaseCandidateTransitionRequest.reason` is now required in OpenAPI. Both
promotion and rejection already reject a missing or blank reason with `400`;
this corrects the generated contract, not runtime request acceptance. Clients
generated from an older schema must supply a non-empty `reason` together with
the documented strong `If-Match` revision. The schema correction is a
compatibility-gate change, not an approved exception or evidence of a release.

## Unreleased Candidate Revision Schema Correction

The `ReleaseCandidate` response schema now defines its already-required
`revision` property as a positive `int64` integer. Create, read, list, and
transition responses already return this value; it was previously listed as
required without a property definition. Regenerate affected clients so that
they can read the revision and supply it in the strong `If-Match` header when
promoting or rejecting a candidate. Runtime responses and historical records
are unchanged. This correction does not approve the compatibility change set
or claim a release.

## Unreleased Control Creation Boundary

PostgreSQL manual framework/control creation now requires current tenant-level
`controls:admin` grants for human sessions, consistent with its tenant-wide
inventory boundary. Product/release grants do not authorize these creates.
Issued API-key/collector scopes remain their credential boundary. Clients must
stay within the text/index/list budgets documented in [API Reference](../api.md#controls-reports-packages-and-governance).
Routes, response fields, schema versions, explicit slugs, requirement order,
applicability duplicates, and limitation order are preserved; new durable
creation timestamps use UTC microsecond precision to match reads/replays.

Both runtime profiles now reject explicit null fields/items in these creation
requests. Each evidence requirement must include its non-null `required`
boolean, including an explicit `false` for optional requirements. This aligns
transport validation with the existing non-nullable/required OpenAPI contract;
previous decoder acceptance of null or absent booleans was not a documented
contract. No historical record is rewritten. This note does not approve the
outstanding compatibility change set or claim a release.

Control-template installation uses the same PostgreSQL tenant-level
administration rule and now records the actual human/key/collector audit
principal. The previous API-key-only audit attribution prevented human-session
installation from committing. Framework/control content and schema versions
are unchanged, and historical audits are not rewritten. A different-key
duplicate version still conflicts; only same-key replay returns the original
result. Invalid NUL/UTF-8 or oversized slugs are rejected before replay storage.
The OpenAPI empty-object request body is now optional, matching the existing
blank/absent-body behavior. Both profiles reject malformed/non-object/null or
unknown-field bodies instead of silently ignoring them. Clients should omit
the body or send `{}`. These corrections do not approve the outstanding
compatibility change set or claim a release.

## Prerelease Baseline Reconciliation

The current baseline is the published `v0.1.0-rc.7` OpenAPI asset with digest
`4c4ebb9e25a17f40a77ad206e927660cde68aa63dec45be3982f51c2541a6364`.
The committed prerelease contract contains 135 changes selected by the
compatibility policy. The exact set and its digest are recorded in
[`.github/openapi-breaking-exceptions.json`](../../.github/openapi-breaking-exceptions.json):

- 16 generated Problem Details error-code additions;
- 4 required request-header additions and 6 required request-field additions;
- 9 request requirement/shape restrictions;
- 16 response property removals or type/optionality changes; and
- 84 client-visible response-enum additions.

This repository-controlled prerelease change record is deliberately exact: the
baseline digest, change count, rule summary, and complete normalized change-set
digest must all match. It is not evidence of a published stable release or of
external approval. Any additional or altered breaking change fails until a new
repository-owned prerelease exception, migration note, and Unreleased changelog
entry are reviewed and committed together.

The migration impact is already reflected in the Unreleased changelog: clients
must use the current documented request fields and response envelopes, send
`If-Match` for protected transitions, use cursor pagination, and handle typed
Problem Details codes rather than parsing strings. A client moving from
`v0.1.0-rc.7` should regenerate its client from the current OpenAPI before it
sends writes to an Unreleased build.

### Source Snapshot Schema Reconciliation

The EVY-905 repository-controlled prerelease record retains the preceding 133
changes and adds two schema corrections: `pull_request.title` is required for
GitHub and GitLab source snapshots. Both the legacy and focused commands already
reject missing/blank titles; the schema previously omitted that runtime rule.
The exact 135-change digest is
`c9bf7cc92a54def6cb3bff2dc5bf0329fcec93fd3f51d479a82096e59f5d19d9`.
The prior 133-change record remains available for its exact historical input.
Neither record approves additional changes or claims external review.

Regenerate clients from the current contract and include a title whenever a
pull request is supplied. Commit time remains optional with its existing server
default. In PostgreSQL mode, omit optional source components and fields rather
than sending null, and expect one transaction for all supplied components.
These contracts are documented under
[provider source snapshots](../api.md#provider-source-snapshots). No stored
schema migration is required, and historical source rows remain unchanged.

## Unreleased Product Schema Correction

The `Product` response schema no longer advertises or requires
`schema_version`. Product creation, point reads, and lists already return only
`id`, `tenant_id`, `name`, `slug`, and `created_at`. This corrects the schema,
not the runtime JSON or persisted product records. Clients generated from the
older schema must not require the nonexistent field; regenerate them from the
corrected contract. No database migration is needed. This correction does not
approve additional compatibility changes or supersede the exact prerelease
change record above; the compatibility gate must still pass before closure.

## Unreleased Security-Document Schema Correction

The security upload schemas now describe the existing reduced parsers:
`secret_scan` and `license_scan`, not unsupported `secret`/`license` aliases;
`pen_test_report`, not `pentest_report`; and optional `format`, defaulting to
`generic`. The API-security convenience route uses its own request schema,
because its category is fixed and a supplied `category` is rejected. Manual
payloads accept any non-null JSON value and retain its encoded bytes rather
than decoding strings into plain text. Regenerate clients from the corrected
contract; no historical row or schema version changes.

PostgreSQL mode now uses focused commands with current security-scope grants.
Malformed null/duplicate-key/non-object scan documents and invalid UTF-8 fail
before staging; null finding/run/result entries are rejected by the shared
reduced parser. Initial tenant-scoped payload metadata remains available, but
the existing central replay privacy policy omits `payload_ref` from stored
and replayed responses. See [security-document uploads](../api.md#security-document-uploads)
for limits and secret-scan flag non-claims. These corrections do not approve
the expanded compatibility change set or claim a release; the exact gate must
still pass before ticket closure.

## Unreleased Human Incident Command Boundary

PostgreSQL incident creation, timeline append, and remediation-task creation
now use focused Operations commands with current tenant-owned parent checks
and `incident:write` grants before writes or replay. Route shapes, response
fields, open defaults, append semantics, and schema versions are unchanged.
Release-level incident grants remain sufficient, and separately authorized
incident/remediation release references are not newly coupled to one product.
No historical row is rewritten and no database migration is needed.

New timestamps use UTC microsecond precision, matching PostgreSQL reads and
same-key replay. The durable handlers reject explicit null fields, including
`due_at`, according to the already non-nullable published request schemas;
omit optional fields instead. Invalid NUL/UTF-8 and oversized direct inputs
fail before persistence. Local memory retains the compatibility path. See
[incident commands](../api.md#incident-commands) for bounds and reference
grants. Ownership annotations now identify `operations-incidents`. This note
does not approve the outstanding compatibility change set or claim a release;
the exact gate must still pass before ticket closure.

## Unreleased Signed Incident Webhook Boundary

PostgreSQL receiver creation and public ingress now use focused Operations
commands and bounded point reads. Route shapes, response fields, public
no-bearer/no-HTTP-idempotency semantics, schema versions, Ed25519 framing, and
natural event replay are retained. Re-signed retries return the original
receipt. New timestamps and database replay normalize to UTC microseconds.
Pure base64/signing helpers are shared with explicit local memory. No migration
or historical-row rewrite is needed.

The durable boundary rejects duplicate protocol headers, ambiguous/trailing
JSON, explicit null fields (already non-nullable in the published schema),
unknown fields, invalid UTF-8, NUL, and oversized direct inputs. Event IDs and
encoded key/signature values reject interior CR/LF. Current receiver key/status,
incident parents, and evidence coordinates are checked before replay. Receiver
authority now requires evidence from the incident's product and, if
release-scoped, release; formerly accepted different-product or tenant-only
evidence is rejected. Use a properly incident-scoped evidence reference or
omit the optional link. This closes the legacy stale-parent and broader-evidence
authority gaps; it does not approve the outstanding compatibility change set
or claim a release. The exact compatibility gate still applies before EVY-905
closure. See [signed incident webhooks](../api.md#signed-incident-webhooks)
for byte limits and signing instructions.

## Unreleased Collector Write Boundary

PostgreSQL collector registration, release recording, and commercial
definitions now use focused Integration commands. Route shapes, scopes,
schema versions, response fields, duplicate identities, optional references,
scope sorting/defaults, and the existing presence-based health labels are
retained. Keys still use the existing HMAC format and configured pepper.
Public collector/key metadata now survives durable restart replay, correcting
over-redaction of the key object and its public binding; the secret and hash
are never retained. Generic log and customer-package redaction is unchanged.

Human writes now require a current tenant-wide `collector:admin` grant;
resource-only grants cannot administer tenant credentials. Optional signature,
SBOM and scan references must retain coherent current artifact/evidence parents
and matching parsed/evidence release coordinates before writes or replay.
Previously accepted stale or foreign parent bindings fail closed. Replace
invalid references with correctly scoped evidence or omit the optional link.
Explicit null inputs already excluded by the published schema now return
`400`. UTF-8/NUL checks, direct text/scope/ID/index-key budgets, and UTC
microsecond timestamps are explicit; no migration or historical-row rewrite
is required. See [collector writes](../api.md#collector-writes) for bounds.
This note does not approve outstanding compatibility exceptions or claim a
release; the exact compatibility gate still applies before EVY-905 closure.

## Unreleased API Key Write Boundary

PostgreSQL `POST /v1/api-keys` now uses a focused Identity command and durable
idempotency rather than Ledger credential state. Existing route, scope,
response schema, HMAC format, non-unique key names, scope trimming/sorting,
duplicate/blank/unknown scope compatibility, and explicit `instance:admin`
delegation rules remain. Human sessions require current tenant-wide authority
before writes and replay. The public key DTO now survives restart replay;
the one-time secret and stored hash never do. Generic logging and customer
package redaction is unchanged.

Strict PostgreSQL request decoding rejects explicitly null fields and null
scope items already excluded by the published schema. Direct text, scope,
identity, and serializable-expiry bounds now fail before storage; the shared
input normalization also protects the local Identity facade. New durable
timestamps and expiry values use UTC microseconds. Historical rows need no
migration or rewrite. Past expiry remains accepted but cannot authenticate.
See [API key issuance](../api.md#api-key-issuance) for exact bounds. This is an
unreleased implementation note, not compatibility approval or release proof;
the exact compatibility gate remains required before EVY-905 closure.

## Unreleased Membership Write Boundary

PostgreSQL organization/user creation and user deactivation now use focused
Identity commands with one durable mutation/audit/replay transaction, not Ledger
state. Routes, status codes, response schemas, case-sensitive trimmed slugs and
lowercased trimmed emails remain. A fixed public user DTO now preserves the
required email in authorized restart replay; logging/customer-package redaction
is unchanged. This purpose-limited replay follows existing 24-hour idempotency
expiry; this is not a physical-deletion guarantee.
Human sessions require current tenant-wide `identity:admin` authority, including
replay, and optional organization/user parents must still belong to the tenant.
Committed deactivation invalidates current-user session authentication.

Malformed mailbox strings, display-name wrappers and invalid UTF-8/NUL or
oversized direct inputs now return validation errors before writes. Shared input
normalization also protects local-memory creation. Strict PostgreSQL decoding
rejects malformed UTF-8, null/unknown/duplicate fields and nonempty deactivation objects excluded
by the published schema; omitted deactivation bodies remain compatible. Stored
user metadata above the bounded projection returns `409` rather than truncating
it. No migration or historical-row rewrite is required. See
[organization and user writes](../api.md#organization-and-user-writes) for limits.
This is an unreleased implementation note, not compatibility approval, email
ownership verification or release evidence. Exact compatibility validation
remains required before EVY-905 closure.

## Unreleased Role Binding Write Boundary

PostgreSQL role assignment now uses a focused Identity transaction instead of
Ledger state. Routes, response schemas, five role names, two subject types,
tenant aliases and repeated assignment with a new idempotency key remain.
Current tenant-wide human admin authority and tenant-owned subject/resource
parents are checked before writes and completed replay. A customer package's
optional release must match its product. Foreign or missing scoped targets
return `404`; empty scoped IDs never become tenant-wide grants.

Strict PostgreSQL decoding rejects invalid UTF-8 and null, duplicate, unknown
or trailing fields already excluded by the contract. Shared normalization also
bounds local-memory direct inputs before storage. New timestamps use UTC
microseconds; no migration or historical-row rewrite is required. See
[role binding writes](../api.md#role-binding-writes) for exact limits. This is
an unreleased implementation note, not compatibility approval, provider-side
verification or release evidence. Exact compatibility validation remains
required before EVY-905 closure.

## Unreleased SSO Public Trust Normalization

Provider creation, trust rotation and OIDC discovery now share a stateless
Identity normalization policy. Recognized private/symmetric JOSE members are
rejected instead of retained, even when null. Unsupported root/key extension
metadata is no longer round-tripped; optional public members must have their
documented string or string-array shapes. Supported public RSA/Ed25519 metadata,
existing key/byte limits and RSA certificate normalization remain. Move unrelated
metadata out of JWKS and remove private parameters before submitting public keys.

This is prospective validation, not a historical-row or backup scrub. If private
keys were previously imported, operators must review affected records, retained
replay receipts, exports and backups, rotate the affected provider keys, and
handle retained copies under their security/retention policy. No incident or
cleanup is claimed here.
See [SSO public trust material](../api.md#sso-public-trust-material) for exact
bounds. This unreleased security correction is not compatibility approval or
provider-side verification; exact compatibility validation remains required
before EVY-905 closure.

## Unreleased SSO Provider Registration Boundary

PostgreSQL SSO provider creation now uses focused Identity commands and one
provider/audit/replay transaction. Current tenant-wide administration and input
validation run before reservation or completed replay; scoped, foreign or
removed human grants cannot replay a prior success. Invalid private-material
requests are rejected even if a historical success receipt exists, without
removing that receipt.

Both profiles reject malformed or credential-bearing issuer URLs, fragments,
invalid raw UTF-8, NUL metadata and explicit null fields/items rather than
accepting them or allowing a PostgreSQL failure. Existing issuer paths/query
strings, optional trust material, group/role mappings and new-key repeated
registration remain supported. Public replay now retains harmless group names
containing words such as `token` only within the versioned provider DTO; generic
privacy redaction is unchanged. See [provider registration](../api.md#sso-provider-registration)
for exact limits and migration guidance. Historical rows/backups are not
scrubbed, and registration is not live provider verification. Required exact
compatibility validation and review remain outstanding before EVY-905 closure.

## Unreleased SSO Trust Rotation Boundary

PostgreSQL trust rotation now uses focused Identity commands and one bounded
tenant-owned provider read. Current tenant-wide authority and provider checks
precede reservation or replay. Trust update, canonical-hash audit and replay
receipt commit together. The existing `200` provider DTO, provider-type trust
rules and canonical hash fields remain; new trust timestamps use UTC microseconds.

Both profiles now reject NUL-bearing retained JWK text and explicit null trust
fields/items before lookup or persistence. Missing/foreign providers return
`404`; oversized or ill-typed stored metadata returns `409` rather than loading
or truncating it. Remove null fields and submit only the public trust fields
appropriate to the provider type. Authorized replay preserves normalized public
SAML PEM line breaks and harmless public group names in the versioned provider
DTO; generic privacy redaction is unchanged.

See [SSO trust rotation](../api.md#sso-trust-rotation) for exact limits. This does
not scrub historical material or repair older receipts whose public PEM was
already flattened. It makes no live provider call and is not provider ownership,
key custody, compatibility approval or release evidence. Exact compatibility
validation and review remain required before EVY-905 closure.

## Unreleased OIDC Discovery Boundary

PostgreSQL OIDC discovery refresh now binds focused Identity commands and the
configured hardened discovery adapter through the composition root. Current
tenant-wide authority and bounded provider ownership/type checks precede replay
without provider calls. Conditional trust update, canonical-hash audit and safe
replay completion commit together; completed retries do not refetch keys. The
existing `200` provider DTO, canonical hash fields and issuer trailing-slash
normalization remain. New trust timestamps use UTC microseconds.

Both profiles now validate the optional empty-object body rather than ignoring
arbitrary request content. Omit the body or send `{}`; remove unrelated fields.
OpenAPI marks the body optional to match the existing omission behavior. Unsafe
retained JWK text from discovery is rejected before JSON normalization or
persistence, including NUL and invalid UTF-8; unrecognized extensions remain
omitted. Provider/issuer/key verification failures return `422` without trust
updates or audits; stored oversized/ill-typed providers fail closed with `409`.

See [OIDC discovery refresh](../api.md#oidc-discovery-refresh) for limits and
transaction/timeout behavior. This does not authenticate users, prove provider
ownership/key custody, synchronize groups or scrub historical rows/receipts and
backups. Exact compatibility validation and review remain required before
EVY-905 closure; this note is not approval or release evidence.

## Unreleased SSO Identity Link Boundary

PostgreSQL identity linking now uses a focused transaction with current
tenant-wide authority and locked tenant-owned user/provider/email checks before
reservation or replay. Link, actual-caller audit and safe replay completion
commit together. The `201` versioned DTO and case-sensitive trimmed subject
remain; email is still trimmed/lowercased and must match the current user.
Inactive targets remain linkable metadata, not session or role grants.

Both profiles now reject NUL/invalid UTF-8, ambiguous/null JSON fields,
non-mailbox email and oversized indexed identities before persistence. IDs are
limited to 1 KiB each, tenant/provider/subject together to 2304 UTF-8 bytes, and
tenant/email together to 2304 bytes. OpenAPI now restricts `verified` to `true`,
matching the existing business rule. Clients must not send `false`, null,
duplicate or unknown fields, display-name mailboxes or values above these
limits. Existing tenant/provider/subject identities still conflict with a new
key; no reassignment or silent reuse is introduced.

New versioned link replay receipts preserve the published administration email
and plain email-shaped subjects while excluding unknown data and credential-
like text. Generic log/package redaction is unchanged. Stored historical
receipts, rows and backups are not scrubbed or backfilled; an old receipt that
already omitted email is not repaired by replay. See
[SSO identity linking](../api.md#sso-identity-linking) for the contract and
non-claims. Exact compatibility validation and review remain required before
EVY-905 closure; this note is not approval or release evidence.

## Unreleased SSO Session Issuance Boundary

PostgreSQL administrator-issued SSO sessions now use a focused Identity
transaction with current tenant-wide authority, an active tenant-owned user
and a tenant-owned provider. Session, actual-caller audit and safe replay
completion commit together. New credentials retain the `evysso_` prefix,
32-byte random entropy, 12-character public prefix and peppered HMAC-SHA-256
hash. The first `201` response returns the secret once; restart replay never
returns it or generates another secret. Parent and authority checks still apply
before completed replay. Existing admin issuance does not require a provider
token/assertion, provider activation or identity link, and it adds no roles or
browser cookie. The explicit expiry has no new upper lifetime cap.

Both profiles now reject null/ambiguous JSON, unsafe/oversized identifiers and
invalid timestamps before persistence; IDs are bounded to 1 KiB each. New
timestamps use UTC microseconds. Clients must provide a valid explicit future
expiry for issuance and must not rely on implicit null values, duplicate or
unknown fields, NUL, malformed UTF-8 or IDs above the limits. A saved metadata
replay can outlive its request expiry; it does not make a revoked/expired
credential usable. Historical rows and receipts are not backfilled. See
[administrator-issued SSO sessions](../api.md#administrator-issued-sso-sessions)
for the contract. Exact compatibility validation/review and full closure gates
remain required before EVY-905 completion; this note is not release evidence.

## Unreleased SSO Session Revocation Boundary

PostgreSQL administrator revocation and self logout now use focused Identity
commands. Current authority/session ownership checks precede reservation and
completed replay; one locked, hash-free metadata row, conditional revocation,
actual-caller audit and safe replay share a transaction. An expired session or
inactive/missing user/provider can still be administratively invalidated. A
new command on an already-revoked session conflicts; completed admin replay
returns original safe metadata. A revoked logout credential cannot authenticate
another request or replay its saved receipt.

Both profiles now require an empty body or strict empty JSON object (64 KiB
maximum), and session path IDs must be trimmed, NUL-free UTF-8 at most 1 KiB.
Cookie-only revocation/logout requests must send exactly one HTTPS `Origin`
matching the request `Host`. Reverse proxies must preserve the public `Host`;
bearer requests do not need Origin. Clients must not rely on missing/foreign
cookie origins, ignored nonempty bodies, null, duplicate members or trailing
JSON. These are intentional input/security acceptance restrictions, not new
provider verification or stronger authentication claims.

Durable logout clears its existing secure `/v1` cookie only after successful
commit, never on storage/audit/replay/commit failure. Stored session response
metadata has explicit bounds (1 KiB per identity/prefix/version field, 128 KiB
groups JSON); excess/invalid data returns `409`, never a truncated response.
Immutable session fields and hashes remain unchanged. Historical rows/receipts
are not rewritten. See [revocation and logout](../api.md#sso-session-revocation-and-logout).
Exact compatibility review and full ticket gates remain required before
EVY-905 closure; this note is not release evidence.

## Stable-Line Rule

A stable `/v1` line permits additive fields, endpoints, and optional filters.
It must reject a breaking compatibility result. The only supported exception is
a documented security emergency: the exception must be exact, identify a
security advisory, link a migration note and changelog entry, and be committed
with the affected contract. Routine correctness, product, or implementation
work is not a stable-line exception.

## Unreleased SSO Credential Exchange Boundary

`POST /v1/sso/session-exchanges` now binds focused Identity commands to bounded
PostgreSQL reads without login Ledger inventories or refresh. It preserves the
public response, configured local OIDC/SAML trust, verified-link/active-user/grant
requirements, eight-hour default/twelve-hour maximum lifetime, and secure cookie
attributes. Secret/cookie release follows the verification/session/audit commit;
stale identity snapshots conflict and failed assessments retain safe receipts.

Both profiles now reject explicit null fields, invalid UTF-8/NUL text, provider
IDs above 1 KiB, subject/credential text above 64 KiB, and timestamps outside
years 1–9999. Stored link/user fields and grants are bounded, and more than 256
role bindings or oversized metadata conflicts rather than truncates. Empty
provider trust collections are normalized consistently for snapshot comparison;
historical rows are not rewritten. See [SSO credential exchange](../api.md#sso-credential-exchange)
for exact bounds and outcomes.

The public route remains non-idempotent: repeated valid credentials may issue
new sessions, and no incoming credential or issued secret is replay material.
These input restrictions require release compatibility review; this note is not
an approved exception, publication evidence, or proof of production Ledger
retirement, provider token single-use, or live provider verification.

## Unreleased Provider Verification Receipt Boundary

`POST /v1/provider-verifications` keeps its route, response fields, assurance
profile format and idempotency behavior. The handler requires the focused
Identity receipt command; PostgreSQL binds bounded owned reads and atomic
receipt/audit/replay writes directly, without Ledger state. Metadata-only,
local OIDC/SAML and configured live OIDC assessments remain available, including
assessments of inactive providers. None issues sessions or authorization grants.
PostgreSQL is required for local evaluation; the retired local-memory API path
is not retained as a fallback. Test-only adapters preserve actual read-only
guard policy, isolated writes and complete detached receipt mappings.

New restrictions reject explicit null/non-object input, invalid UTF-8/NUL text,
IDs above 1 KiB, subject/local credentials above 64 KiB and access tokens above
16 KiB before trimming. Metadata labels containing supplied credentials are
rejected. Human callers require tenant-wide authority; cookie-authenticated
requests require a single same-host HTTPS Origin, while bearer credentials
retain precedence. Oversized stored projections conflict rather than truncate.
Provider output lacking named valid-state checks, exceeding the documented
budgets (including after redaction) or containing invalid text becomes a safe failed assessment. Supplied
credentials are redacted from checks/limitations and their assurance profile.

The HTTP create transaction still rolls back a failed assessment's receipt and
audit, with a safe failed-retry marker and no receipt body; direct application
calls persist failed assessments. Provider/link changes before direct-command
commit now conflict, including a previously absent link appearing. See
[provider identity verification receipts](../api.md#provider-identity-verification-receipts)
for exact limits. Historical records are not rewritten. These restrictions
require release compatibility review; this note is not an approved exception,
provider verification evidence or proof of production Ledger retirement.

## Unreleased Public Transparency Metadata Boundary

Log creation and publication now use focused Experimental commands and
bounded PostgreSQL tenant/log/checkpoint/batch projections. They preserve
metadata trimming, canonical entry hash inputs and digest case, configured/
published states, schema versions, audit bindings, and response casing and
omission. Neither operation performs external publication or inclusion
verification. Log public-key metadata is not validated cryptographically.

The API requires current tenant-wide human key administration and
reference ownership before replay, strict exact non-null JSON fields, raw
UTF-8/NUL-free byte bounds, and Origin for cookie mutations. Previously
accepted oversized/ambiguous text, malformed HTTPS URLs, credential-bearing
URLs and fragments now return `400`; product-scoped human grants return `403`.
Publication rejects malformed or oversized persisted Merkle roots. Durable
timestamps use UTC microseconds. Both HTTP handlers use focused commands only;
PostgreSQL is required for local evaluation. Test-only memory adapters retain
actual preflight and isolated replay writes. Historical records are not rewritten.

See [public transparency metadata](../api.md#public-transparency-metadata)
for exact bounds and non-claims. These tightened boundaries require release
compatibility review; this note is not an approved exception. Complete
production Ledger retirement remains migration work.

## Unreleased Public Transparency Proof Boundary

Operator proof verification now binds focused commands to bounded current
PostgreSQL entry/log/checkpoint/batch coordinates. It preserves proof hashing,
empty-proof JSON `null` normalization, digest case, response fields, and `200`
for well-formed passing/failing local assessments. It does not authenticate a
supplied log root. Same-state compare-and-swap now includes previous proof
hash/time and publication coordinates; assessment, audit and replay are atomic.

The API rejects duplicate/unknown/case-aliased fields, null values/items,
omitted required fields, malformed digests, and text exceeding the documented
raw byte bounds with `400`. Product-scoped human authority returns `403`;
missing/foreign/broken current root chains return `404`, including on replay.
The operator request cannot claim fetched provenance. Caller proof slices and
returned local assessments no longer alias stored verification state. Durable
timestamps use UTC microseconds. Historical records are not rewritten.

See [proof verification](../api.md#public-transparency-proof-verification).
These input/authorization restrictions require release compatibility review;
this note is not an approved exception. The handler uses focused commands only;
PostgreSQL is required for local evaluation. Test-only memory adapters retain
actual guards and detached assessments. Remaining aggregate deletion is EVY-906.

## Unreleased Public Transparency Fetch Boundary

Proof fetching now binds focused commands to bounded current PostgreSQL entry/
endpoint projections and the runtime-configured fetcher. It preserves fetched
proof hashes, empty-proof JSON `null` normalization, passing/failing assessment
states, response fields, and omission of untrusted provider diagnostics.
Replays recheck current authority/root ownership and do not contact a provider.
The source is frozen and compared again after fetching, including endpoint
and prior assessment. Assessment, audit and replay commit together.

The API accepts absent/whitespace bodies and exact empty JSON objects,
but no ignored input fields, null/scalar/array values, duplicates or trailing
JSON. The 64 KiB body limit and bounded IDs/endpoints are enforced before
fetching. Human product-only authority returns `403`; missing/foreign/broken
root chains return `404`, including on replay. Unsafe/oversized persisted HTTPS
endpoints return `400`; invalid/unavailable provider input returns safe `422`.
The provider call is capped at 30 seconds (or earlier configured/parent
deadlines), and PostgreSQL retains tenant fences/root locks through the call.
This bounds, but does not eliminate, same-tenant administrative write latency.
Historical audit records are not rewritten. Remote observation cannot be
rolled back, so a failed-commit retry may contact the provider again.

See [proof fetching](../api.md#public-transparency-proof-fetching). These
restrictions require release compatibility review; this note is not an approved
exception or evidence of authenticated public-log trust. The handler uses focused
commands only; PostgreSQL is required for local evaluation. Test-only memory
adapters retain real current guards and fake provider calls, not SQL guarantees
or external provider evidence. Remaining aggregate deletion is EVY-906 work.

## Unreleased Marketplace Collector Boundary

`POST /v1/marketplace-collectors` now binds focused Experimental commands to
tenant/reference ID-only PostgreSQL reads. Metadata trimming, digest hex
case, `registered` state, schema, limitations, response casing/omission and
manifest-hash audit binding remain unchanged. Optional evidence references
remain optional; registration is not package verification or endorsement.

The API enforces tenant-wide human administration and current reference
ownership before replay, strict exact non-null JSON fields, raw UTF-8/NUL-free
byte bounds before trimming, and Origin for cookie mutations. Previously
accepted oversized, ambiguous, NUL-containing or malformed UTF-8 input now
returns `400`; whitespace-only optional references now return `400` rather
than a reference miss. Product-scoped human administration now returns `403`.
Durable timestamps use UTC microseconds. Registration, list and health use
focused ports only, with no aggregate fallback. PostgreSQL is required for
local evaluation; memory adapters are test-only and return detached records.
Historical records are not rewritten.

See [marketplace collector creation](../api.md#marketplace-collector-creation)
for exact limits, duplicate metadata and raw-body replay behavior. These
tightened boundaries require release compatibility review; this note is
not an approved exception or proof of complete production Ledger retirement.

## Unreleased SaaS Profile Boundary

`POST /v1/saas/profiles` now uses focused Experimental commands and a bounded
two-tenant-ID projection in PostgreSQL. Profile ownership, deliberate
instance-admin cross-tenant admin references, raw-value configuration hash
profile, status, schema, limitations, response fields and audit binding remain
unchanged. The HTTP handler uses focused commands only. PostgreSQL is required
for local evaluation; memory adapters are test-only.

The API requires an authenticated exact issued `instance:admin` actor,
current tenant existence before replay, strict exact non-null JSON fields,
raw UTF-8/NUL-free byte bounds before trimming, and Origin for cookie mutations.
Oversized or ambiguous requests that were previously accepted now return `400`;
identity-less direct calls now return unauthorized. Durable timestamps use UTC
microseconds. These tightened boundaries require release compatibility review;
this note is not an approved exception. See [SaaS profile creation](../api.md#saas-profile-creation)
for exact limits, hash compatibility and replay behavior. No deployment is
provisioned or certified, and complete production Ledger retirement remains open.

## Unreleased Signing Operation Boundary

`POST /v1/signing-operations` now binds focused Verification commands to
bounded current-provider and owned-subject reads in PostgreSQL. Canonical
request JSON field order/profile, request and nonce correlation, signature
reference, response field casing/omission, schema version and audit binding
are preserved. The HTTP handler uses focused commands only. PostgreSQL is
required for local evaluation; test-only memory adapters retain actual guards,
canonical hashing/receipt validation and detached checks, not SQL guarantees.

The API requires tenant-wide human administration and current ownership
before replay, strict non-null exact JSON fields, bounded raw UTF-8/NUL-free
input before trimming, and Origin for cookie mutations. Inactive providers
cannot authorize replay. Receipt/check output is bounded, diagnostic metadata
is redacted, and malformed/mismatched/failed-check receipts publish no operation,
including direct calls that previously could persist failed-check records.
Durable timestamps use UTC microseconds. Historical records are not rewritten.

Successful replay does not re-sign; database rollback cannot undo a provider
call, and a fresh attempt may use a new request ID/nonce. See
[signing operation creation](../api.md#signing-operation-creation) for exact
bounds, retry behavior and non-claims. These tightened boundaries require
release compatibility review; this note is not an approved exception, live
provider evidence or proof of complete production Ledger retirement.

## Unreleased Anomaly Report Boundary

`POST /v1/reports/anomaly` now binds focused Experimental commands and bounded
transactional PostgreSQL facts. The route remains experimental. Supported
subject types, response fields, omission of empty signals, signal ordering and
text, schema version and audit type are preserved. The HTTP handler uses focused
commands only; PostgreSQL is required for local evaluation. Test-only memory
adapters retain actual guards, the pure evaluator and detached report slices.

The API rejects malformed, duplicate/unknown/null or mixed-case JSON
fields and overlong or invalid raw UTF-8/NUL text before trimming. Current
ownership/grants are checked before replay; cookie mutations require Origin.
Durable timestamps use UTC microseconds. No historical report is rewritten.
Only releases have checks; `clear` for other roots is not a security conclusion.
PostgreSQL critical-finding handling uses the readiness predicates: decisions
must match the finding's scan and release, with current supersession/expiry
semantics, rather than the legacy finding-ID-only lookup.

See [anomaly report generation](../api.md#anomaly-report-generation) for bounds,
trusted-build/attestation rules, current critical-finding handling and replay.
Tightened inputs need release compatibility review; this note is not an
approved exception or proof of complete production Ledger retirement.

## Unreleased PDF Report Boundary

`POST /v1/reports/pdf` now binds focused Package commands and coordinate-only
PostgreSQL reads. Route, response fields, schema version, audit type and exact
payload bytes/hash for valid single-line titles are preserved. The payload
remains the minimal title-only envelope, not a full report renderer.

The HTTP handler uses focused commands only. PostgreSQL is required for local
evaluation. Test-only adapters retain actual guards, identical payload bytes,
isolated writes and privacy-safe replay, not SQL locking or durability guarantees.

The API rejects malformed, duplicate/unknown/null or mixed-case JSON
fields, invalid UTF-8/NUL IDs, overlong raw input and multiline/control-bearing
titles or report types. Product/release ownership must agree; current grants
and parents are checked before replay. Cookie mutation Origin checks now apply;
bearer precedence is unchanged. Local returned limitations no longer alias the
cached immutable record. Production composition requires transactional object
staging; non-production hash-only mode remains explicit. Durable timestamps
use UTC microseconds. No historical record or payload is rewritten.

See [PDF report packaging](../api.md#pdf-report-packaging) for exact limits,
staging/finalization, rollback and privacy-safe replay semantics. Tightened
inputs require release compatibility review; this is not an approved breaking
exception, PDF-reader certification or proof of production Ledger retirement.

## Unreleased Graph Snapshot Boundary

`POST /v1/evidence-graph-snapshots` now binds focused Package commands in the
PostgreSQL profile. Route, response fields, schema version, normalized-JSON
adjacency hash, node/edge ordering, opaque and digest-only reference behavior,
stored-coordinate selection, and adjacency-only limitation are preserved.
The HTTP handler uses focused commands only, and current root/grant guards
precede replay. PostgreSQL is required for local evaluation. Test-only memory
adapters retain the pure builder, actual guards and isolated replay writes;
they do not prove database locking or durability.

The API rejects case aliases, duplicate/unknown/null fields, malformed
JSON, invalid UTF-8/NUL IDs, and raw IDs above 1024 bytes. Mismatched
product/release ownership and inconsistent selected evidence parents fail
closed; local responses cannot mutate cached immutable snapshots. Cookie
mutations require same-host HTTPS Origin protection. Selected labels, reference
types, reference counts and PostgreSQL metadata now have explicit bounds; the
existing 4096-node, 8192-edge and 4 MiB encoded-adjacency limits remain. Durable
timestamps use UTC microseconds. Existing snapshots are not rewritten.

See [graph snapshot creation](../api.md#graph-snapshot-creation) for exact
selection, privacy-safe replay, hash and size limitations. These restrictions
still require release compatibility review. This note is not an approved
breaking-change exception or proof of complete production Ledger retirement.

## Unreleased Evidence Summary Boundary

`POST /v1/evidence-summaries` now uses focused Package commands in PostgreSQL,
with bounded citation reads and atomic summary/audit/replay writes. The route,
response fields, schema version, citation ordering, assumption/limitation text,
and stored product/project/release selection semantics are preserved. Evidence
and build roots are not exact-single-record/build filters, and customer-package
roots still select current scope rather than a frozen/redacted manifest.

Both HTTP profiles now reject null/malformed/non-object JSON, duplicate/unknown
fields, invalid UTF-8/NUL identifiers, and blank/duplicate-after-trimming IDs.
IDs are limited to 1024 bytes and explicit lists to 512. PostgreSQL additionally
bounds citation title/type/hash text and preflights a 4 MiB metadata budget;
the existing 4 MiB encoded-summary bound remains. Cookie-authenticated writes
require same-host HTTPS Origin protection. Root authorization is current on
replay; no historical summaries are rewritten.

OpenAPI now declares the six already-supported subject types and these input
bounds. `evidence_ids` is optional, correcting the previous schema that marked
it required despite already supporting omission for automatic selection. See
[evidence summary creation](../api.md#evidence-summary-creation). Regenerate
clients and use scoped explicit IDs to avoid oversized automatic reports.
Restrictions still require release compatibility review; this note does not
approve an exception, claim production Ledger retirement, or establish legal
compliance or customer-package redaction.

## Unreleased Questionnaire Draft Boundary

`POST /v1/questionnaire-drafts` now uses focused Package commands in PostgreSQL.
Bounded selector/scope reads replace Ledger maps and full template documents;
draft, caller-attributed audit and successful replay completion are atomic.
Existing response fields, response hash/omitempty semantics, question ordering,
answer specificity/recency/ID ranking, and fallback text remain compatible.

Both HTTP profiles reject null/duplicate/unknown fields, invalid UTF-8/NUL IDs
and raw IDs above 1024 bytes, and require same-host HTTPS Origin protection for
cookie writes. Independent answer grants and citation scope checks now prevent
drafting from bypassing library visibility or following misleading links into
another product/release. PostgreSQL rejects selections above 512 questions,
4096 candidate/citation occurrences, the documented text bounds or 4 MiB
selector/output budgets; it does not return a partial draft on overflow.

Draft replay now binds the caller's canonical scopes and human resource grants
in addition to request bytes. A permission change conflicts (`409`) when current
root access is still allowed; missing current access still fails authorization.
Use a new key to generate a new draft under changed permissions. Unchanged
permissions retain exact successful replay; ordering/duplicates do not matter.
Historical body-only replay fingerprints conflict without rewriting records.
See [questionnaire draft creation](../api.md#questionnaire-draft-creation).
These restrictions require release compatibility review; this note does not
approve an exception, claim production Ledger retirement, establish customer
redaction, or provide compliance conclusions.

## Unreleased Questionnaire Template Boundary

`POST /v1/questionnaire-templates` now uses focused Package commands in
PostgreSQL. Tenant/control/framework identity locks replace aggregate state
access; definition, caller-attributed audit and successful replay completion
are atomic. Routes, response fields, schema versions, question order and
optional-field omission remain unchanged. Allowed-field sorting retains blank
strings and duplicates. New durable timestamps use UTC microsecond precision;
historical rows are not rewritten and no migration is required.
The handler requires focused ports, without an aggregate fallback. PostgreSQL
is required for local evaluation; the legacy input converter is test-only.

Human creation/replay now requires a current tenant-level `package:write`
grant. Product/release grants cannot define tenant-wide templates. Duplicate
trimmed question IDs, missing/foreign controls or mismatched control-framework
ownership now fail closed. Optional control IDs are newly trimmed. Clients
must use coherent tenant-owned controls or omit optional selectors.

Both profiles reject null/duplicate/unknown/mixed-case fields and invalid
UTF-8/NUL; raw text, collection and aggregate/encoded-byte limits are stated
in [template creation](../api.md#questionnaire-template-creation). Cookie
mutations require same-host HTTPS Origin protection, with bearer precedence.
The new bounded input-question schema does not restrict historical response
schemas. Successful replay retains the body-based fingerprint but rechecks
current authority and referenced ownership. These restrictions require release
compatibility review; this note does not approve an exception, claim production
Ledger retirement, or establish compliance conclusions.

## Unreleased Customer Portal Boundary

PostgreSQL portal issuance, revocation and token consumers now use focused
Package services. Existing routes, JSON fields, schema versions, HMAC token
format, NDA/failure-limit behavior and privacy-safe replay projection remain.
The additive `20261003000100_customer_portal_token_lookup` migration indexes
prefix lookup without rewriting records or enforcing a new uniqueness rule.
Token access sees creation/revocation immediately without a Ledger refresh.
All portal handlers and token helpers require focused ports; their aggregate
fallbacks and the obsolete creation input converter are removed. PostgreSQL is
required for local evaluation. Test-only composition uses the actual focused
services and memory transaction repositories, not a supported runtime profile.

Human writes/replay now require matching current package grants, rather than
tenant membership plus a credential scope alone. Ownership must resolve through
current tenant-owned package/product/release records. Cookie writes require
same-host HTTPS Origin protection. JSON aliases, null and malformed/oversized
text fail closed; selected database projections are bounded. New timestamps
use UTC microseconds. Revocation bodies remain ignored. Existing email-bearing
watermarks can still be rejected by ZIP privacy validation; use an explicit
customer-safe watermark. See [portal lifecycle](../api.md#customer-portal-lifecycle).

These authorization/input restrictions need release compatibility review and
the exact project-owned breaking-change gate before ticket closure. No
exception, external review, or production Ledger retirement is claimed here.

## Unreleased Questionnaire Package Boundary

`POST /v1/questionnaire-packages` now binds focused Package commands in
PostgreSQL rather than Ledger maps. Bounded selection/association coordinates
and question selectors replace broad state, prompts and manifest reads.
Package, caller audit and successful idempotency completion are atomic. Existing
response fields, schema version, raw selection coordinates, response ordering,
answer ranking, fallback text and normalized-JSON hash remain unchanged; no
migration or rewrite of historical packages is required.
The handler requires focused command/replay ports, with no aggregate fallback.
PostgreSQL is required for local evaluation. Test-only adapters retain actual
guards, isolated writes, detached responses and the permission fingerprint;
their memory evidence does not establish SQL locking or durability.

Human actors now need a current grant for the selection scope independently of
any associated customer package. Unscoped selection requires tenant-wide
authority. Optional `package_id` remains an association, not a derived filter;
its current parents must agree with explicit selection. Independently scoped
library answers and current citation parents are checked before disclosure.
Null/duplicate/unknown/mixed-case fields, invalid UTF-8/NUL, oversized IDs and
the documented collection/text/output limits fail closed. Cookie writes require
same-host HTTPS Origin protection, with bearer precedence. See
[package creation](../api.md#questionnaire-package-creation).

Replay binds canonical credential scopes and human grants as well as body bytes.
Changed permissions or historical body-only fingerprints conflict (`409`) when
current root/association access still succeeds; missing authority still fails
authorization. Use a new key to generate a new package under current permissions.
These restrictions require release compatibility review; this note does not
approve an exception, claim production Ledger retirement, establish customer
redaction or provide compliance conclusions.

## Unreleased Build Creation Boundary

`POST /v1/builds` now uses native PostgreSQL durable execution rather than
aggregate-backed replay. Routes, response fields, schema versions, immutable
build records and original request-byte fingerprints remain unchanged; no
database migration or historical rewrite is required. Identical authorized
retries return the stored response without recomputing CI identity or
reverifying historical digest metadata. Fresh creation still checks output
digests against current tenant-owned artifacts.

Every replay now requires current tenant/product/project/release ownership
and applicable human parent/output grants, including current artifact
associations. Cookie writes require same-host HTTPS Origin protection, with
Bearer precedence. Both profiles reject null fields/items, case aliases,
unknown/duplicate fields, raw oversized text, negative run attempts and
timestamps outside the supported submitted/UTC year range. Omit optional
`finished_at` instead of sending null. See [build creation](../api.md#build-creation)
for exact bounds and errors.

These input and authorization restrictions require release compatibility
review; this note does not approve an exception or claim that a public release
already includes them. Local memory remains nondurable, submitted provider/OIDC
metadata remains unverified, and production Ledger retirement is not claimed.

## Unreleased Build Attestation Upload Boundary

`POST /v1/builds/{id}/attestations` now uses native PostgreSQL durable replay
and a current ownership/grant guard instead of a Ledger replay/refresh
envelope. The HTTP body limit now matches the application's existing 20 MiB
attestation limit, rather than the unrelated 64 KiB small-JSON cap. Upload
concurrency limits also cover this route. Original request-byte fingerprints,
stored schemas, subject/digest checks and worker ownership remain unchanged;
no database migration or historical rewrite is required.

Both profiles cap raw build IDs before trimming, reject empty/oversized bodies,
require same-host HTTPS Origin for cookie writes and recheck current build,
parent and output authority on completed retries. Fresh HTTP creation now
omits the sensitive optional `payload_ref`, matching the existing centrally
redacted replay contract. Internal storage/worker records retain the reference.
Clients should use the public evidence ID, payload hash and size rather than
depending on storage coordinates. See [attestation upload](../api.md#build-attestation-upload).

These restrictions and the privacy omission require release compatibility
review; this note does not approve an exception or claim a published release
already includes them. Structural acceptance is not signature verification,
and this migration does not retire all production Ledger usage.

## Unreleased Catalog Creation Boundary

Product, project and release creation now use native PostgreSQL durable
execution instead of Ledger replay/refresh. Routes, response fields, stored
schemas, request-byte fingerprints, product-slug and release-version uniqueness,
project-name non-uniqueness and new release draft/revision semantics remain.
No database migration or historical rewrite is required.

Completed retries now require current tenant/product creation authority.
Strict JSON rejects case aliases, null, unknown/duplicate fields and malformed
UTF-8. Raw names/slugs/versions are capped at 64 KiB before trimming; normalized
slugs keep the existing 1024-byte limit. Raw parent IDs are capped at 1024 bytes.
Cookie writes require same-host HTTPS Origin with Bearer precedence. A submitted
release version outside PostgreSQL's encoded index capacity now returns `400`,
not an internal server failure. See [catalog creation](../api.md#1-create-product-project-and-release).

These input and authority restrictions require release compatibility review;
this note does not approve an exception or claim publication. Local memory
remains nondurable; production Ledger retirement is not yet established.

## Unreleased Artifact And Container Image Registration Boundary

Artifact and container-image registration now use native PostgreSQL durable
HTTP execution instead of Ledger cloning/replay/refresh. Routes, response
fields, request-byte fingerprints, stored schemas, optional artifact/size
defaults and immutable natural-key reuse remain unchanged; no migration or
historical rewrite is required. Completed retries check current tenant and
applicable existing/submitted artifact ownership and grants without private
metadata or image digest revalidation. Fresh image creation retains digest
checks. Exact JSON integer sizes are preserved on replay.

Both profiles now reject null, unknown, duplicate, case-aliased and malformed
JSON fields, including optional fields explicitly set to null. NUL-free UTF-8
raw names/media types and repository/tag/platform text are limited to 64 KiB
before trimming, digest text to 128 bytes and artifact IDs to 1024 bytes; the
whole body remains limited to 64 KiB. Cookie writes require same-host HTTPS
Origin with Bearer precedence. An indexed repository exceeding PostgreSQL's
encoded tuple capacity returns safe `400` rather than `500`.

These authority and input restrictions require release compatibility review;
this note does not approve an exception or claim publication. Local memory is
nondurable, broader Ledger retirement remains incomplete, and registration
does not verify artifact bytes or registry images. See
[registration behavior](../api.md#container-image-registration).

## Unreleased Release Candidate Creation Boundary

Candidate creation now uses native PostgreSQL durable HTTP execution instead of
Ledger cloning/replay/refresh. Routes, public DTOs, byte fingerprints, schema,
open/revision-1 initialization, snapshot hash profile, and sorted references
with intentional duplicates remain. Different keys still create distinct
snapshots; names are not reuse keys. No migration or historical rewrite is
required. Current parent/reference ownership, source coherence and human grants
are now checked before every replay without reading stored candidate documents.

Both profiles now reject explicit null fields/items, unknown/duplicate fields,
case aliases and malformed JSON. NUL-free UTF-8 raw names are capped at 64 KiB,
parent/reference IDs at 1024 bytes before trimming. The seven reference arrays
share 4096-entry and 64 KiB raw-identifier-byte limits. The complete JSON body
remains capped at 64 KiB. Cookie writes require same-host HTTPS Origin with
Bearer precedence. These input and replay-authority restrictions require
release compatibility review; this note does not approve an exception or claim
publication. Local memory is nondurable, broader startup composition remains
transitional, and a snapshot is not a release-safety or compliance conclusion.

## Unreleased Conditional Transition Boundary

Release freeze/approval and candidate promotion/rejection now use native
PostgreSQL durable execution instead of Ledger cloning/replay/refresh. Routes,
response fields, schemas, timestamps, immutable snapshot fields, state/revision
rules and the existing `conditional-action-v1` fingerprint remain. The canonical
strong `If-Match` revision and original body bytes still identify replay intent.
No migration or historical rewrite is required. Completed retry checks current
tenant/subject/parent ownership and grants, not current lifecycle or private
metadata; fresh execution retains bounded state/revision checks.

Both profiles require NUL-free UTF-8 raw IDs within 1024 bytes and candidate
reason text within 64 KiB before trimming. Strict candidate JSON rejects null,
unknown, duplicate and case-aliased fields. Freeze/approval now reject nonempty
non-object and unknown-field bodies; legacy absent/blank bodies remain accepted.
Cookie writes require same-host HTTPS Origin with Bearer precedence. These input
and replay-authority restrictions require release compatibility review; this
note does not approve an exception or claim publication. Local memory remains
nondurable and broader production composition is unfinished. See
[conditional transitions](../api.md#conditional-release-transitions).

## Deprecation Lifecycle

No operation is currently marked deprecated. When one is, the operation must
remain available until its advertised removal version and include all of the
following in the generated OpenAPI:

- `deprecated: true` and the matching `x-sunset` HTTP-date;
- `x-evydence-deprecation` with a distinct `replacement_operation_id`, a
  `removal_version`, RFC 3339 `deprecated_at`, `minimum_notice_days` of at
  least 180, the matching HTTP-date sunset, and a repository migration-guide
  link; and
- documented `Deprecation`, `Sunset`, and `Link` response headers on every
  declared response. `Link` identifies the replacement or migration guide
  using `rel="successor-version"` or `rel="deprecation"` as appropriate.

The route implementation must emit those headers on every successful and
Problem Details response for the deprecated operation. The OpenAPI gate rejects
incomplete deprecation metadata before a change can enter CI; route tests must
verify the runtime headers when a route is first deprecated. Removal requires
the documented removal version, a current migration guide, a changelog entry,
and a compatibility exception if the selected baseline still contains the
operation.
