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

## Stable-Line Rule

A stable `/v1` line permits additive fields, endpoints, and optional filters.
It must reject a breaking compatibility result. The only supported exception is
a documented security emergency: the exception must be exact, identify a
security advisory, link a migration note and changelog entry, and be committed
with the affected contract. Routine correctness, product, or implementation
work is not a stable-line exception.

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
