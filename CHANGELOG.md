# Changelog

All notable public release changes for Evydence are recorded here.

Release notes must distinguish implemented behavior from future intent and must
preserve Evydence’s non-claims: no legal compliance conclusions, no
certification, no complete-SBOM guarantee, no authoritative vulnerability
results, no secure-release guarantee, and no regulator or auditor acceptance.

## Unreleased

This section records source changes after the current public release candidate.
It does not mean a new release has been cut or that those changes have public
release artifacts.

Current source retires the `local_memory` API profile. Local evaluation now
requires `EVYDENCE_RUNTIME_PROFILE=postgres` and `EVYDENCE_DATABASE_URL`.
Startup rejects the retired profile before resources or credentials are opened,
and no longer constructs Ledger or `app.Config`. Existing payload files are not
deleted or imported. Fast in-memory unit-test fakes remain supported; the local
CI simulation uses an owned disposable PostgreSQL schema. See the
[configuration migration note](docs/reference/configuration.md#retired-local-memory-profile-unreleased).
Older published release binaries are not changed by this source update.

The GitHub Actions upload CLI now omits `finished_at` when it is not supplied,
matching the native API's existing non-nullable optional-field contract. Supplied
timestamps retain their precision and offset; the API schema is unchanged.

Completed vulnerability scans with no findings now persist and return `[]`
instead of `null`, preserving the distinction from pending worker projections.
Verified worker replay also normalizes empty findings and remains idempotent.
Existing completed `null` projections are not automatically backfilled or
re-enqueued; strict readiness/package readers continue rejecting them until
their original payload is successfully replayed.

Removed three redundant Ledger-backed service shells and their forwarding
methods without changing API, portal access, export or report behavior.
Remaining Ledger retirement is in progress; this is not a production
readiness or release-publication claim.

Ledger-accepting HTTP server constructors and their aggregate replay binders
are removed from production source. Explicit test-only setup retains the local
fixture's cancellation, authentication override, transaction and replay checks
without adding a supported backend. The unused non-context `app.NewLedger`
factory is removed. HTTP response contracts remain unchanged; legacy handler
and aggregate deletion remain unfinished under EVY-906.

Product, project, release, artifact, container-image, build and candidate
creation no longer contain legacy HTTP command fallbacks. Their existing
native validation, authorization, replay and response contracts are unchanged.
The remaining release-catalog lifecycle, attestation and query fallbacks are
also removed, together with the broad Server field and transport interface.
Conditional replay fingerprints, cursor binding and attestation redaction are
preserved. Remaining aggregate retirement is still in progress.

API-key and role-binding metadata lists no longer fall back to broad aggregate
inventory reads. Existing native pagination, authorization and public-metadata
contracts are unchanged. API-key creation's broad identity fallback is also
removed; existing native credential validation, authorization, atomic replay
and one-time-secret contracts are unchanged. Other identity writes, sessions
and aggregate retirement remain unfinished.

Deployment environment/event creation, list and event point handlers now use
only focused Operations ports. Their broad local transport dependency and
interface are deleted. Native authorization, cookie-origin protection,
transactional replay, pagination and response contracts are unchanged.

Collector, commercial-collector and source repository/commit/branch/pull-request/
snapshot handlers now require focused Integration ports. Twelve handler
fallbacks across thirteen routes and four aggregate-only input mappers are
removed. Native ownership/grant guards, private credential issuance, cookie
Origin rules, input limits and replay contracts are unchanged. Test-only
fixtures retain isolated real writes and add full-state rollback/replay,
tenant/grant-filtered read and metadata-detachment regressions. Affected source
API/reference descriptions now require PostgreSQL for local evaluation; schemas
are unchanged. Other aggregate dependencies remain unfinished.

Incident, signed-webhook, incident-report and retention-marker/report handlers
now require focused ports. Eight handler fallbacks across nine routes are
removed. Native authorization, signed callback/replay protocols, cookie Origin,
input limits and atomic PostgreSQL commands are unchanged. Test-only fixtures
use focused transaction ownership readers for real preflight, preserve isolated
historical writes and add full-state rollback, callback recovery/replay, current
grant/tenant and read-only DTO/metadata-detachment regressions. The affected
API/architecture references no longer advertise a local-memory runtime.
Remaining aggregate retirement is still in progress under EVY-906.

Generic evidence creation, supersession, linking and lifecycle-event handlers
now use only focused Evidence ports. Their two broad local dependencies and
interfaces are deleted. Native validation, authorization, append-only effects,
exact-number handling, cookie-origin checks and replay contracts are unchanged.
Evidence list/search and point reads, lifecycle pages, SBOM documents/components,
scan/contract points, VEX documents/reports and both VEX previews also now use
only focused queries. Twelve transport fallback branches and sixteen obsolete
interface methods are removed. Native filtering, cursor validation, error/DTO
mapping, lifecycle redaction and preview validation remain unchanged. Test-only
fixtures retain real ownership/grant checks, complete fixture-page assertions,
read-only state and detached metadata.
All document uploads and both diffs now also require focused Evidence commands.
Eleven transport fallbacks, the fifteen-method broad interface, Server binding
and obsolete aggregate streaming wrapper are removed. Native input limits,
fingerprints, current authorization and atomic PostgreSQL writes are retained.
Test-only adapters retain real preflight authorization and isolated legacy
commands; eleven rollback/replay cases check all repository effects.

Fixed VEX upload replay changing a published author email to `[REDACTED]`.
Only a plain mailbox in the validated, closed public VEX DTO is preserved;
generic secret/PII redaction remains unchanged. Existing already-redacted
receipts are not reconstructed. The memory test adapter now accepts valid
zero-finding security scans without weakening required metadata checks.
Direct context Ledger calls and aggregate retirement remain unfinished.

Report-template creation/rendering and portable bundle import/export handlers
now use only focused Package ports. Three broad local bindings and interfaces
are removed. Native input limits, field whitelists, cookie-origin protection,
receipts, signing and replay contracts are unchanged. Export replay still
reauthorizes the saved evidence selection without rebuilding or signing it.
Release/customer creation, redaction-profile creation, audited package access
and download, security-review, HTML and readiness-report fallbacks are also
removed, together with the ten-method broad Package interface and Server
binding. The release-bundle request description now accurately requires
PostgreSQL for local evaluation; its schema and response contracts are unchanged.
Other direct Package-context Ledger calls and aggregate retirement remain unfinished.

Signing-key and audit-log pages, custody reports, and audit-chain/Merkle/backup
verification handlers now use only focused Verification ports. Six broad
read/report branches and four obsolete interface methods are removed. Native
tenant checks, key privacy, pagination, assurance-profile and failed-result
contracts are unchanged. Signing-key rotation/revocation and signing-provider/
DSSE trust-root creation also use only focused commands, removing four fallback
branches and five broad-interface methods. Tenant administration, key ownership,
private-key omission and atomic lifecycle/metadata/audit/replay contracts remain
unchanged. Their four request descriptions now require PostgreSQL for local
evaluation without schema changes. The remaining nine Verification fallback
paths are also removed, along with the ten-method broad interface and Server
binding. Subject, release-bundle, DSSE and Cosign verification, backup generation,
Merkle creation, checkpoint recording and retention commands retain their native
guards, bounded snapshots, assurance metadata and atomic receipt/audit/job/replay
behavior. Seven affected descriptions now require PostgreSQL without schema
changes. Direct context-to-Ledger calls and aggregate retirement remain unfinished.

Vulnerability-decision and exception pages and the customer-safe decision
summary now use only focused Risk queries. Three broad transport branches and
interface methods are removed. Native tenant/resource grants, pagination,
active-history filtering, private-note omission and response contracts are
unchanged.

The explicit in-memory test adapter now supports focused waiver/exception/
approval ownership and transition reads. Real native guard/command tests cover
current and removed grants, foreign/broken parents, ambiguous findings,
read-only state, detached metadata and audited fresh mutations without Ledger.
Waiver/exception creation and approval and approval-record creation now use
only focused commands: five transport fallbacks and broad-interface methods
are removed. Native callbacks and public schemas remain unchanged. Explicit
governance HTTP fixtures preserve actual authority checks, isolated writes,
complete rollback and current-grant replay without reapplying transitions.
These are test-only adapters, not a new API runtime or SQL-locking proof.
The last two Risk decision/evaluation transport fallbacks, broad interface and
Server binding are also removed. Native validation, current ownership/grants,
private-note omission, append-only history and atomic audit/replay behavior are
unchanged. Regression tests preserve byte-for-byte replay, rollback all effects,
retain synchronous VEX/manual-link assertions and cover queued-document links.
Direct context-to-Ledger calls and aggregate retirement remain unfinished.

Candidate transition requests now mark `reason` required in OpenAPI, matching
the existing promotion/rejection validation. See the
[migration note](docs/reference/api-versioning.md#unreleased-candidate-transition-schema-correction).

The candidate response schema now defines the already-required positive
`revision` integer returned by the API. See the
[client migration note](docs/reference/api-versioning.md#unreleased-candidate-revision-schema-correction).

PostgreSQL manual framework/control creation now uses focused durable commands
with tenant-wide human administration grants and atomic audits. Creation also
rejects null fields/items and missing requirement booleans in both profiles,
matching the published contract. See the
[migration note](docs/reference/api-versioning.md#unreleased-control-creation-boundary).

Control-template installation now uses focused PostgreSQL transactions and
records the actual installer principal, allowing authorized human sessions to
commit. Invalid slugs are rejected before durable replay storage; empty-object
body validation and optional-body OpenAPI now match the documented contract.
See the same [migration note](docs/reference/api-versioning.md#unreleased-control-creation-boundary).

### Added

- Added a read-only Go AST source inspector for architecture enforcement. It
  includes build-tagged imports, identifies generated source and public
  interface declarations, and rejects source symlinks and oversized files.
  `make architecture-check` now rejects import cycles and direct/indirect
  inward-boundary violations and flags non-generated files/interfaces for
  architectural review. Import remediation now passes without boundary
  exemptions and joins `fast-check`/`finalize`; legacy aggregate removal and
  EVY-906 closure validation remain unfinished.

- Release-readiness facts and their pure policy evaluator now belong to the
  Risk domain. Package reporting no longer imports the Risk application
  service; full-result compatibility vectors and wrong-tenant/grant tests
  preserve existing policy output and access behavior.

- OpenAPI generation now uses shared, validated route contracts without
  constructing Ledger or runtime services. Generated specification bytes and
  native server dependency requirements are unchanged.

- Removed obsolete worker whole-state read, snapshot-publication and unfenced
  mutation fallbacks. Parser writes require claim-fenced row mutations; existing
  parser, replay, tenant and failure assertions remain on focused test fixtures.

- The native HTTP composition helper no longer accepts, constructs or binds
  Ledger or selects a local compatibility path. Existing local constructor
  behavior, explicit authentication overrides and API contracts are preserved;
  physical aggregate retirement remains in progress.

- DSSE ingestion and offline root-policy verification now enter the legacy
  application through explicit ports constructed by outer wiring. Test-only
  defaults preserve existing fixture assertions; clones retain the configured
  ports. Signature checks, complete-policy isolation, conservative results and
  bounded native object bindings are unchanged.

- PostgreSQL SSO session revocation/logout now use focused, hash-free locked
  metadata and an atomic lifecycle/audit/replay transaction. Cookie-only
  mutations require a matching HTTPS Origin in both profiles; durable logout
  clears the cookie only after successful commit. Strict body/path rules and
  stored metadata bounds are documented in the
  [compatibility note](docs/reference/api-versioning.md#unreleased-sso-session-revocation-boundary).

- PostgreSQL administrator-issued SSO sessions now use focused Identity
  commands with current tenant-wide authority, an active tenant-owned user
  and a tenant-owned provider. Session, actual-caller audit and safe replay
  commit together; the compatible bearer secret is returned only once. Strict
  body/ID/time rules apply to both profiles. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-sso-session-issuance-boundary).
- PostgreSQL SSO identity linking now uses focused Identity commands with
  current tenant-wide authority and tenant-owned user/provider/email checks.
  Link, actual-caller audit and safe replay commit together; restart replay
  retains only published administration metadata. Both profiles reject unsafe
  text/JSON and oversized identities before storage. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-sso-identity-link-boundary).
- SSO credential-exchange snapshot validation now takes the shared mutation
  fence before identity-table locks, matching focused identity writes and
  avoiding inverted transaction lock ordering.
- PostgreSQL role assignment now uses focused Identity commands with current
  tenant-wide human authority, tenant-owned subject/resource parents, and atomic
  binding, audit, and replay effects. Valid grant forms and repeated assignments
  remain; strict input bounds fail before storage. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-role-binding-write-boundary).
- Security-scan and manual-document uploads now use focused PostgreSQL commands
  with current security-scope grants and atomic evidence, document, payload,
  audit, finalizer, and safe replay effects. Their OpenAPI schemas now match
  the reduced parser enums, optional format, fixed API-security category, and
  opaque manual JSON payload. See the
  [migration note](docs/reference/api-versioning.md#unreleased-security-document-schema-correction).

- Production control coverage and CRA readiness reports now use bounded, tenant-scoped PostgreSQL snapshots with current-subject validation, actual subject timestamps for freshness, and fail-closed capacity limits. Local-memory mode retains its compatibility report path.

- PostgreSQL-backed customer-portal access listing now pages within current tenant and resource grants without selecting token hashes; local-memory listing also enforces resource grants.

- Added a versioned parser conformance corpus manifest and gate that records
  fixture provenance, redistribution rights, hashes, bounded limits, and
  expected normalized summaries for supported parser formats.

- Added a canonical evidence-format compatibility matrix that distinguishes tested reduced CycloneDX, SPDX, OpenVEX, CycloneDX VEX, DSSE/in-toto, and scanner JSON contracts from incidental parser acceptance, with parser identities, effective limits, fixture evidence, and unsupported-format guidance.
- Recovery tooling now pairs PostgreSQL and object-store backup generations with deterministic preflight manifests, native `pg_dump`/`pg_restore` rehearsal, mismatch detection before normal startup, and crash-boundary recovery tests.
- Object payload reconciliation now provides a tenant-scoped, resumable worker
  command with dry-run reporting, conservative lifecycle quarantine/recovery,
  auditable receipts, and bounded reconciliation metrics. Provider-only objects
  are advisory candidates and are never deleted merely because a listing
  reports them; apply mode requires an explicit abandoned-staging age threshold.
- API build identity now records version, commit, build time, dirty state, Go
  version, and a pre-build release-input-manifest digest. Runtime liveness,
  dependency-backed readiness, and instance-admin readiness diagnostics are
  separate surfaces; public readiness omits dependency errors and returns 503
  for required unavailable dependencies.
- Verification responses now use a versioned, conservative assurance-result
  taxonomy and record profile scope, non-secret trust-material identifiers,
  required checks, and limitations. Customer packages include release-scoped
  verification profile summaries when available.
- Customer package reviewer materials now include a proof summary, dossier,
  proof checklist, customer-safe vulnerability-decision context, and a
  token-scoped portal review path.
- VEX import preview and parser-report workflows, decision history, and
  customer-safe decision summaries improve review of vulnerability evidence.
- Rendered API reference, client quickstarts, CI handoff templates, and
  production deployment/HA/operator guidance broaden the evaluation material.
- CI preflight, one-shot release-evidence upload, release-evidence workflow,
  and release security-summary paths add reproducible release-ledger inputs.
- Provider validation, transparency-proof, and cloud-KMS signing gateways add
  explicit integration points without treating provider metadata as trust by
  itself.

### Changed

- Native PostgreSQL API and worker startup now share validated runtime profiles
  and focused durable ports instead of reconstructing the production Ledger.
  Reads use bounded, tenant-scoped database projections; worker writes remain
  claim-fenced. Explicit local-memory API mode stays nondurable and unavailable
  for production or workers. The single-API-writer profile is unchanged.

- Release evidence-flow planning now advertises its existing read-only POST
  behavior consistently: `Idempotency-Key` is not required. Bearer authentication,
  `release:read`, the route, and the response remain unchanged. OpenAPI, SDK route
  metadata, and generated API references agree with the existing handler.

- Corrected the `Product` OpenAPI response schema to omit the unsupported
  `schema_version` field. Create, read, and list JSON and stored product records
  are unchanged; clients must not require a field the server never returned.
  See [the migration note](docs/reference/api-versioning.md#unreleased-product-schema-correction).

- PostgreSQL GitHub/GitLab source snapshots now compose focused Integration
  commands in one transaction, including audit and idempotency state. Late
  failures roll back earlier inserts and branch updates, and repository reuse
  returns UTC timestamps consistently. Optional components/fields must be
  omitted rather than null. The request schema now reflects the existing
  optional commit-time default and required pull-request title. The exact
  prerelease compatibility record adds only the two title-schema corrections;
  see [the migration note](docs/reference/api-versioning.md#source-snapshot-schema-reconciliation).

- PostgreSQL-backed CRA vulnerability-handling and security-update evidence
  reports now read bounded, tenant- and release-scoped snapshots instead of
  Ledger maps. They omit private decision notes, reject inconsistent evidence
  references and oversized reports rather than returning partial results, and
  require valid singleton product/release filters. CRA scan counts are
  aggregated in PostgreSQL without transferring raw findings to the API.
  These reports organize recorded evidence; they do not prove legal compliance,
  complete detection, scanner authority, or release security.

- PostgreSQL-backed exception lists now resolve current release ownership and
  `verify:read` grants before bounded keyset pagination. Unknown filtered
  releases remain `404`; existing releases outside the actor's grants remain
  `403`. Local-memory mode retains the compatibility reader.

- PostgreSQL-backed lifecycle-event lists for ordinary evidence now page from
  one tenant-scoped snapshot instead of materializing all events through the
  Ledger. Worker-owned evidence retains its validated projection fallback;
  response details continue to remove sensitive and internal fields.

- PostgreSQL-backed SBOM point reads now verify source evidence, release, and
  artifact parentage and source artifact references under one tenant before applying current `evidence:read`
  resource grants. The response still contains the stored component array;
  inconsistently linked historical rows are no longer returned.

- PostgreSQL-backed SBOM component lists now apply current tenant and resource
  grants before bounded keyset pagination, allowing clients to continue beyond
  the former 500-result preselection cap. The local-memory profile retains that
  cap; PostgreSQL still expands JSONB component arrays rather than using a
  dedicated component search index. The list now excludes rows whose source
  evidence type, release, artifact subject, or build/deployment parents disagree
  with the stored SBOM, matching the SBOM point-read safety checks.

- PostgreSQL-backed OpenAPI-contract point reads now verify current tenant,
  source-evidence, product, and optional release relationships in one query
  before applying human `evidence:read` resource grants. Response fields are
  unchanged; inconsistent historical parent links are no longer returned.

- Vulnerability-posture reports now aggregate stored scan findings inside
  PostgreSQL without loading raw findings into the API. Tenant-wide reports
  require a tenant-level human grant; release-filtered reports accept matching
  product or release grants. Duplicate, blank, and unknown query parameters
  are rejected, and the report documentation now states that decisions and
  VEX records are not included.

- The instance-admin snapshot now counts current PostgreSQL records in one
  aggregate read instead of relying on the in-process Ledger projection.
  The explicit `instance:admin` requirement and counts-only response remain.

- Collector health reports now read one tenant-owned collector plus its latest
  and pinned release through a bounded, consistent PostgreSQL snapshot.
  Human sessions need a current tenant-level `collector:read` grant in both
  PostgreSQL and local-memory modes; recorded evidence is not proof of runtime
  integrity or vulnerability absence.

- Marketplace collector lists and health reads now use bounded, tenant-filtered
  PostgreSQL queries. Human sessions need a current tenant-level `collector:read`
  grant in both PostgreSQL and local-memory modes; health reference presence
  remains limited evidence, not a trust or safety conclusion.

- PostgreSQL-backed control-evidence lists now apply current tenant and resource
  grants before keyset pagination. Links with missing or cross-tenant controls,
  frameworks, subject records, or mismatched product/release ownership are
  excluded. Local-memory mode retains the Ledger compatibility reader.

- Commercial collector-definition lists now use tenant-filtered PostgreSQL
  keyset pagination. Human sessions require a current tenant-level
  `collector:read` grant in both PostgreSQL and local-memory modes.

- Signing-key lists now use tenant-filtered, keyset-paginated PostgreSQL reads
  that never select encrypted private key material; local-memory mode retains
  its compatibility list.

- PostgreSQL-backed release-bundle and manifest reads now resolve the current
  tenant-owned release before enforcing human `bundle:read` resource grants.
  Their response shapes remain unchanged.
- PostgreSQL-backed artifact-signature reads now require the current
  tenant-owned artifact and matching digest. Scoped human sessions need a
  current evidence or build association covered by their `evidence:read`
  grant; the response shape is unchanged.
- PostgreSQL-backed artifact point reads now use one tenant-filtered database
  statement. Scoped human sessions need a current, consistent evidence or
  digest-matching build association covered by their `evidence:read` grant;
  the response shape is unchanged.
- Questionnaire answer-library lists now enforce current human resource grants
  for every draft, including unfiltered reads. Creating a tenant-wide draft
  with only a product or release grant is now forbidden. PostgreSQL-backed list
  requests apply tenant, current-parent, linked-reference, and grant filters
  before pagination; mismatched product/release filters are rejected.
- The `/v1` OpenAPI contract is now compared against a checksum-verified
  release-artifact baseline in CI. Unapproved breaking changes fail; the
  current pre-release reconciliation is exact and documented in
  `docs/reference/api-versioning.md`. Stable-line breaks require a documented
  security emergency, migration note, and changelog entry.
- The release-evidence, SDK route catalog, API contract matrix, and public API
  operations now record explicit stability classifications for evaluation and
  implementation planning.
- Corrected the prerelease release and artifact contracts to match the server:
  `POST /v1/releases` no longer accepts `project_id`; `POST /v1/artifacts` no
  longer accepts `release_id` or `subject_ref`; and artifact `media_type` is
  required. Clients that sent those removed fields must omit them and link
  artifacts to releases through the documented evidence, build, or
  release-candidate flows instead.
- Corrected the prerelease build helper to use `finished_at` and
  `provider_metadata` plus the documented CI identity fields. The obsolete
  `completed_at` and `github` fields are removed from the OpenAPI and typed SDK
  contract.
- The repository now tracks a scorecard and execution backlog with evidence
  links and external-evidence blockers; these are implementation-tracking
  records, not production or compliance claims.
- Release packaging, black-box artifact checks, source-backed persistence
  inventory, and production-like deployment configuration have been expanded
  for controlled operator evaluation.

### Fixed

- PostgreSQL OIDC discovery refresh now uses focused Identity commands and the
  configured hardened network adapter, with bounded current-provider checks and
  atomic trust/audit/replay effects. Completed retries do not refetch keys.
  Strict optional empty-object bodies and unsafe discovered public text are
  validated in both profiles; no historical scrub is claimed. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-oidc-discovery-boundary).
- PostgreSQL SSO trust rotation now uses a bounded tenant-owned provider read
  and atomic update/audit/replay commands without Ledger reloads. Strict decoding
  rejects null trust fields/items and NUL-bearing public-key text. Authorized
  replay preserves normalized public SAML PEM and harmless group names without
  weakening generic redaction; old receipts are not repaired. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-sso-trust-rotation-boundary).
- PostgreSQL SSO provider registration now uses focused Identity commands with
  atomic provider/audit/replay writes and current tenant-wide checks before
  replay. Both profiles reject unsafe issuer URLs, NUL metadata and null
  fields/items. Harmless public group names are preserved on replay without
  weakening generic privacy redaction. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-sso-provider-registration-boundary).
- SSO trust imports now reject private/symmetric JOSE members and retain only
  supported public JWK fields. Shared normalization lives in stateless Identity
  code; valid public-key and certificate formats remain. Historical rows and
  backups are not scrubbed. See the
  [compatibility note](docs/reference/api-versioning.md#unreleased-sso-public-trust-normalization).
- Artifact registration now rejects a missing or whitespace-only `media_type`
  before persistence, so in-memory and PostgreSQL-backed deployments apply the
  same request contract.
- Object payload storage now enforces the versioned canonical tenant/digest key layout, confines filesystem operations beneath the configured root even across symlinks, and verifies tenant, digest bytes, byte count, and media type before filesystem or S3 content is trusted. S3 public/custom remote endpoints require TLS and AWS S3 endpoints require an explicit region.
- Object-retention verification no longer treats a local policy record as
  provider enforcement. Positive results now retain bounded provider-observation
  metadata; unavailable, incomplete, failed, and stale observations remain
  distinguishable.
- Updated the indirect `golang.org/x/text` dependency to v0.39.0 to remediate
  the reachable invalid-input infinite-loop advisory reported by `make vuln`.
- Cosign metadata assessment can no longer report `passed` from a non-empty
  signature string. The deprecated compatibility route now reports `limited`
  unless stored digest or signature material is missing, and explicitly rejects
  full-verification requests until a verifier and trust policy are configured.
- Customer-package archive and manifest validation rejects unsafe entries and
  duplicate JSON keys before package contents are trusted.
- Customer package reports include a Content Security Policy, and archive
  manifest comparison is validated before comparison results are reported.

## v0.1.0-rc.6 - historical local tag record (2026-06-01)

The local Git checkout contains annotated tag `v0.1.0-rc.6` (tag object
`742703baccad1726d2ca939b0ec7119c28cba3d4`) pointing to commit
`d4155b4007a4daf8ed0bd908e90792c69ade188e`. The repository does not contain
enough checked public-release evidence to state whether that tag was published
or withdrawn. It is retained here as local history only; use `v0.1.0-rc.7` for
the current public release candidate.

## v0.1.0-rc.7 - 2026-06-01

Release status: controlled self-hosted production candidate. This prerelease is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status.

### Fixed

- Release artifact publication now uses the dedicated release publication token
  path after signed release evidence is generated.
- The release-candidate evidence package includes signed archives, checksums,
  OpenAPI and migration checksums, coverage output, production-check summary,
  SBOM/provenance metadata, release notes, and a signed release manifest.

### Known Limits

- No tag-specific project-owned container image evidence is asserted for this
  prerelease in the repository metadata; operators must verify a separately
  published image digest or build/sign their own image for container
  deployments.
- Multi-writer API HA remains outside the supported production profile; use one
  API writer replica and scale workers through PostgreSQL outbox locking.

## v0.1.0-rc.5 - 2026-06-01

Release status: controlled self-hosted production candidate. This prerelease is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status.

### Added

- Public release verification helper for downloading `v0.1.0-rc.5` from
  GitHub Releases into a clean temporary directory, checking release checksums,
  validating in-toto provenance metadata shape, and verifying the signed
  release manifest with the released Linux amd64 CLI.
- Container image workflow evidence for
  `ghcr.io/aatuh/evydence:v0.1.0-rc.5@sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888`,
  including release-attached image manifest and cosign verification output.
- Repository-owned restore rehearsal target for app-layer and live PostgreSQL
  backup/restore mechanics.
- Static package-viewer preview asset for public docs.

### Changed

- Dependency maintenance updates for pinned GitHub Actions, the Docker build
  and runtime base images, and `kin-openapi`.

### Fixed

- PostgreSQL release-evidence persistence now normalizes empty string slices to
  empty `text[]` values for non-null array columns, including VEX import
  reports and vulnerability decision evidence IDs.

### Known Limits

- Operators remain responsible for PostgreSQL, object storage, TLS, external
  signing or KMS/HSM custody, WORM/object-lock policy where required, backups,
  restore rehearsals, monitoring, provider validation, and incident response.
- Multi-writer API HA remains outside the supported production profile; use one
  API writer replica and scale workers through PostgreSQL outbox locking.

## v0.1.0-rc.4 - 2026-05-31

Release status: controlled self-hosted production candidate. This prerelease is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status.

### Added

- Public GitHub prerelease at
  <https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.4>.
- Release archives for Linux, macOS, and Windows.
- `SHA256SUMS`, `openapi.sha256`, and `migrations.sha256`.
- Release coverage output and production-check summary.
- Release SBOM metadata and Evydence release provenance metadata.
- Scorecard-compatible in-toto provenance metadata.
- Signed release manifest plus `.sig.json` verifier input and `.sig` release
  asset alias.
- Release notes attached to the public prerelease.

### Known Limits

- Public release archives and release evidence are published, but no
  container image should be treated as deployable release evidence unless the
  maintainer image workflow has produced an immutable digest and cosign evidence
  for the tag.
- Operators remain responsible for PostgreSQL, object storage, TLS, external
  signing or KMS/HSM custody, WORM/object-lock policy where required, backups,
  restore rehearsals, monitoring, provider validation, and incident response.
- Multi-writer API HA remains outside the supported production profile; use one
  API writer replica and scale workers through PostgreSQL outbox locking.

## v0.1.0-rc.3 - 2026-05-31

Release status: controlled self-hosted production candidate. This build is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status. The local
release-candidate package for this tag was generated with
`make release-candidate-check TAG=v0.1.0-rc.3`.

### Added

- Direct GCP Cloud KMS and Azure Key Vault signing executors for signing stored
  SHA-256 payload hashes without sending raw evidence payload bytes.
- Operator-controlled provider validation gateway that records non-secret
  validation metadata without forwarding supplied access tokens.
- Operator-controlled transparency proof gateway before local proof
  verification.
- Release-candidate SBOM metadata and release provenance metadata generation.
- OpenSSF Scorecard workflow, Dependabot configuration, issue templates, code
  of conduct, and production-like Compose rehearsal.

### Changed

- README positioning now leads with the release-evidence user problem, current
  limitations, fastest proof path, and differentiation from adjacent tools.
- Security reporting guidance no longer depends on LinkedIn as the first
  recommended path and calls out external repository settings that operators
  must verify.

### Known Limits

- Public GitHub release publication, branch protection, public CI status,
  private vulnerability-reporting settings, and public adoption evidence remain
  external repository/operator proof.
- High-scale multi-writer API HA, native PKCS#11/HSM module handling, direct
  provider management API/group synchronization, broad WORM/object-lock proof,
  and final production exit review remain hardening work or deployment-specific
  review items.

## v0.1.0-rc.2 - 2026-05-31

Release status: controlled self-hosted production candidate. This build is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status. The local
release-candidate package for this tag was generated with
`make release-candidate-check TAG=v0.1.0-rc.2`.

### Added

- Root legal, governance, security, support, trademark, commercial licensing,
  release-evidence, and changelog metadata.
- Production-readiness profile, production gate, and coverage-threshold gate.
- Release-candidate checklist requiring production-check evidence, checksums,
  signed artifact manifests, release notes, and documented limitations.
- Release-candidate package gate for controlled release-candidate artifacts, checksums,
  OpenAPI and migration checksums, checked release notes, signed release
  manifest, and manifest signature.
- Local `v0.1.0-rc.2` annotated release-candidate tag and signed evidence
  package generated under ignored `dist/v0.1.0-rc.2/`.
- Focused PostgreSQL critical mutations for tenants, credential hashes,
  idempotency records, audit-chain entries, release bundles, signatures,
  verification results, provider verification receipts, vulnerability
  decisions, and outbox jobs.
- Focused PostgreSQL release-ledger mutations for products, projects, releases,
  artifacts, evidence items, evidence lifecycle events, SBOMs, vulnerability
  scans, OpenAPI contracts, VEX documents, audit-chain entries, and parser
  outbox jobs.
- Relational PostgreSQL state synchronization for remaining aggregate
  persistence calls without writing the compatibility `ledger_state` snapshot.
- AWS KMS signing executor for signing provider operations over stored
  SHA-256 payload hashes without sending raw evidence payload bytes.
- Optional OIDC UserInfo live provider validation for
  `POST /v1/provider-verifications` using a supplied access token that is not
  persisted.
- Object-retention policies can require sample-object legal hold verification
  with S3/MinIO providers that expose object legal-hold status.
- Production API startup takes a PostgreSQL advisory writer lease so accidental
  second API writers fail closed under the supported single-writer profile.

### Known Limits

- Evydence supports compliance readiness and technical evidence organization.
- Operators remain responsible for production PostgreSQL, object storage,
  network policy, TLS, backups, monitoring, external signing, and incident
  response.
- Service decomposition, HA/multi-writer operation, non-AWS KMS/HSM SDK
  adapters, provider-specific management API/group synchronization, broader
  object-lock proof beyond configured bucket/sample-object checks, and final
  exit review remain production-hardening work after the release-candidate
  gate.
