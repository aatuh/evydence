# Architecture

Evydence follows a ports-and-adapters shape:

- `internal/{identity,release,evidence,risk,package,verification,operations,integration,experimental}/domain` contains the context-owned core models and schema constants.
- `internal/{identity,release,evidence}/app` owns the focused Identity, Release, and Evidence command services implemented by EVY-903.
- `internal/domain` supplies compatibility DTOs at HTTP, persistence, and legacy-facade boundaries while callers migrate.
- `internal/app` is the deprecated Ledger compatibility facade, the shared transaction and storage port surface, and the temporary home of contexts not yet migrated.
- `internal/adapters/httpapi` adapts application services to HTTP and OpenAPI; migrated Identity, Release, Evidence, Decision, Package, and Verification handlers depend on context-specific interfaces.
- `internal/adapters/postgres` provides the durable ledger-state store, migration runner, tenant-scoped relational resource projection, and persisted outbox.
- `internal/platform/wiring` validates the explicit API/worker runtime profile, opens PostgreSQL and object-store adapters, and composes the API's focused durable authentication/query ports from that runtime. Local-memory mode deliberately has no durable query ports and retains the compatibility Ledger path.
- `internal/adapters/objectstore/filesystem` stores raw uploaded payload bytes under tenant-prefixed object keys for local and self-hosted deployments.
- `internal/adapters/objectstore/s3` stores the same tenant-prefixed object keys in S3/MinIO-compatible buckets.
- `cmd/*` contains process entry points.

Core logic does not depend on HTTP routers, SQL drivers, object storage SDKs, queues, KMS providers, provider clients, or UI frameworks. PostgreSQL persistence currently stores a versioned ledger snapshot and rebuilds tenant-scoped relational projection rows plus forward-compatible per-resource tables for implemented release, evidence, source, deployment, and control resources. Identity, idempotency, and customer portal token records are synchronized into relational rows with non-secret hashes and tenant-scoped constraints. Release-ledger core rows are also synchronized for products, projects, releases, artifacts, evidence, audit-chain entries, signing keys, signatures, SBOMs, vulnerability scans, OpenAPI contracts, policy evaluations, release bundles, and verification receipts. Collector/build provenance, source/deployment, incident, security evidence, SBOM diff, vulnerability workflow, contract diff, custom policy, waiver, approval, DSSE trust-root, collector release, Cosign verification, signing provider, Merkle batch, transparency checkpoint, evidence lifecycle, release candidate, VEX/risk decision, control, package, report, retention, provider verification, signing operation, and future-extension records are synchronized into their migration-backed relational tables. Production API and worker startup defaults to relational-only reconstruction and disables compatibility snapshot writes; local development defaults to snapshot-preferred compatibility. In production, API startup also takes a PostgreSQL advisory writer lease so an accidental second API writer fails closed while the supported profile remains single-writer. The accepted [database-authoritative command-transaction decision](adr/0001-database-authoritative-transactions.md) requires a command to commit its domain, audit, idempotency, and outbox effects before publication, and defines staged/finalized object-storage handling. Existing focused and broad call sites remain tracked in the generated [persistence decomposition inventory](reference/persistence-decomposition.md); this is production hardening work, not a completed maturity claim.

The PostgreSQL-profile missing-evidence report reads release-readiness facts in a tenant-scoped, repeatable-read transaction and evaluates them without writing a policy receipt. The release security summary uses that same bounded readiness projection together with release workflow, finding, decision, approval, and exception facts in one committed view. The release-readiness report gathers canonical readiness facts, unhandled critical findings, approved unexpired exceptions, and decision/package counters in one read-only transaction, then uses the shared policy evaluator and report renderer. It requires `verify:read` (or admin scope) and matching tenant, product, or release grants for human actors; projections above 4096 combined detail rows and policy identifiers, or oversized selected text fields, fail closed rather than truncate evidence. Explicit policy-evaluation commands still persist their own evaluation and audit records. Local-memory mode retains its compatibility report paths while EVY-905 completes the remaining query migration.

PostgreSQL-profile customer-package reads and security-review package reports use a focused package-access command. It locks one tenant-owned package row, resolves its current product/release ownership, checks `package:read` and human resource grants, and checks expiry after acquiring the lock. The access count and `customer_package.accessed` audit entry commit atomically; report rendering does not persist a separate report record. Stored manifests are limited to 8 MiB before transfer, identifiers to 1 KiB, titles to 4 KiB, and state strings to 64 bytes. Security-review reports preserve the frozen manifest's evidence-ID order and reject malformed, duplicate, or more than 4096 IDs before recording access. The remaining compatibility download path also reads the current durable package counter rather than trusting its cached copy. Local-memory access uses the same orchestration through its explicit compatibility transaction adapter.

CRA readiness HTML generation uses the bounded control-coverage query with the requesting actor's real grants. The focused HTML-report command escapes the result and limitations, limits the generated body to 4 MiB, hashes its exact bytes, and commits the persisted report with its `html_report.generated` audit entry in one unit of work. This GET route retains its documented report-persistence side effect; it is not a read-only query. Product and optional release ownership are rechecked at insertion after the committed query view. HTTP responses retain the existing JSON field names. Local-memory generation shares the same renderer and orchestration through explicit compatibility ports. These reports organize readiness evidence, not legal compliance conclusions.

PostgreSQL-profile custom-template creation and rendering use focused template commands. Rendering reads and share-locks one tenant-owned definition, then commits the materialized output and audit entry in the same transaction. Stored template metadata, field names, and text have an 8 MiB combined read budget; oversized or malformed definitions fail closed before rendering. Human actors require a tenant-wide `report:read` grant, not just a product or release grant. Template text is inert: output selects only `subject_type`, `subject_id`, and `generated_at` when named in `allowed_fields`. Other field names add no output, and subject labels do not dereference resources or prove their existence. JSON fields, normalized-JSON hashing, and idempotent HTTP response replay remain compatible. Local-memory mode delegates to the same command orchestration.

PostgreSQL-profile evidence-bundle imports use a focused command that validates the portable manifest and atomically inserts a target-tenant receipt and audit entry. It needs no Ledger, evidence projection, signing provider, or resource lookup. Human actors require tenant-wide `bundle:write` permission; source labels never grant target-tenant access. Local-memory mode shares the orchestration through an explicit transaction adapter. An accepted receipt is not signature verification or evidence ingestion; see the [import receipt and hash compatibility limits](reference/evidence-format-compatibility.md#portable-evidence-bundle-import-receipts).

The release-bundle snapshot adapter reads current tenant-owned release metadata, evidence IDs, audit head, and retention-observation proofs in one read-only PostgreSQL repeatable-read transaction. It rejects more than 4096 combined evidence IDs and retention policies, more than 4096 total verification checks and limitation strings, or more than 8 MiB of selected retention metadata, without truncating manifest facts. Identifiers are limited to 1 KiB, release versions and policy names to 4 KiB, and state/provider/mode labels to 64 bytes. Raw evidence, signing material, object paths, and provider bucket names are not selected. A shared verification-context renderer preserves existing proof fields and marks expired observations stale.

PostgreSQL-profile release-bundle creation now uses that snapshot reader and a focused command, without Ledger, a projection refresh, or a local cache. The signing adapter selects one tenant's highest-version active local Ed25519 key (ID ascending breaks ties), bounds its fields and private material, and signs the existing normalized manifest hash. Private bytes are cleared and never cross its port. The write transaction share-locks the release's current tenant-owned parent, rechecks `bundle:write` grants, and share-locks the signing key's public lifecycle fields. It rejects revoked, compromised, not-yet-valid, expired, or mismatched keys and verifies the staged signature before atomically inserting the signature, bundle, signature-linked audit entry, and `sign_bundle` job. The manifest is the earlier committed snapshot, not a claim that no later release facts exist. Existing response fields and idempotent replay are preserved; local-memory mode uses explicit adapters to the same orchestration. This remains the existing local Ed25519 package-signature path, not a new external-provider custody or encryption claim. Other package generation and runtime Ledger retirement remain EVY-905 work.

Evidence-bundle export (`POST /v1/evidence-bundles`) also uses focused durable commands in the PostgreSQL profile. Its read-only repeatable-read snapshot selects evidence IDs and validated tenant-owned product/project/release/build/deployment coordinates, the indexed audit head, and public object-lock proof metadata, never raw evidence payloads or provider locations. The same 4096 combined evidence/proof-row and 8 MiB proof-metadata limits apply. Automatic selection omits only authorization denials; explicit unauthorized IDs and inconsistent stored parents fail closed. A release-scoped export requires a matching release-root grant as well as authorization for selected evidence. Before persistence, selected rows and their parents are share-locked and their resolved coordinates must still match the earlier snapshot. The staged signature is cryptographically verified against the current signing-key lifecycle, then bundle, signature and signature-linked audit entry commit atomically; export adds no worker job. The bundle describes its earlier committed view, not necessarily the newest state. Existing schema versions, normalized-JSON hashing, response fields and replay remain unchanged. Explicit JSON `null` export fields are rejected according to the non-nullable API schema; omitted filters remain valid. Local-memory mode delegates to the same orchestration through compatibility ports. Neither path proves evidence completeness, external key custody, legal compliance or complete provider WORM enforcement.

## Bounded-context transition

Evidence-item requests to `POST /v1/verify` use a focused durable command in the PostgreSQL profile. It resolves and share-locks tenant-owned evidence and parent coordinates, then checks `verify:read` and human tenant/product/project/release grants before selecting hash inputs. An 8 MiB combined JSON budget covers the selected evidence, authoritative legacy origins and related parser/audit facts; origin and parsed-record reads each stop at 4096 rows and reject overflow rather than truncate. The reader selects payload references only as canonical hash inputs, never downloads payload bytes and never exposes those references in receipts. Shared evidence-domain rules preserve v2 immutable subjects while excluding mutable relationship projections, and reconstruct legacy relationships only from matching v2 lifecycle origins. Authoritative origin publication takes an evidence-row lock, including when the origin set was previously empty. Selected SBOM, scan, OpenAPI, VEX and build-attestation projections retain shared shape and source-relationship checks; queued uploads need not have parsed records yet. Parser-normalization markers additionally bind their source evidence and linked audit fact, with a bounded predecessor-integrity check. This is not full audit-chain verification or a payload-origin/completeness proof. Receipt, audit and outbox effects commit together; successful idempotent POST replay creates no extra receipt, and a failed POST rolls back its enclosing transaction. Local-memory verification shares canonical inspection through its compatibility adapter. Other verification subjects and startup Ledger retirement remain EVY-905 work.

Release-bundle verification in the PostgreSQL profile uses a focused transaction, not Ledger maps, for both `GET /v1/release-bundles/{id}/verify` and release-bundle requests to `POST /v1/verify`. It locks tenant-owned bundle/release/product coordinates and checks `verify:read` grants before loading the manifest. Bundle, signature and public signing-key rows remain share-locked through receipt persistence, preventing reparenting, byte changes or key revocation from racing a successful commit. The reader accepts at most 4096 signature references and an 8 MiB combined manifest/reference/signature/public-key text budget; oversized or malformed stored projections fail closed, without truncation. Private key material and provider locations are not selected. Shared verification-context inspection preserves normalized-JSON manifest hashing, exact signature subject binding and historical key-validity policy. The command commits its verification receipt, audit and `verify_subject` job together. GET/direct verification records failed checks and returns the existing result contract; a failed idempotent POST retains its Problem Details response and rolls back the enclosing command transaction. Successful POST replay adds no duplicate receipt. Local-memory inspection shares the same policy through its explicit compatibility adapter. This verifies the local manifest/signature profile, not external publication, provider custody, evidence completeness or legal sufficiency. Other subject types and startup Ledger retirement remain EVY-905 work.

PostgreSQL-profile signing-key rotation and revocation use focused commands rather than Ledger key maps. Both lock the tenant before signing-key rows, so concurrent rotations serialize even when the tenant has no existing local keys. Rotation reads at most 4096 local-key metadata rows and 8 MiB of selected text, calculates the next database-backed version, retires active local keys, and inserts the new key and audit entry atomically. External-provider keys do not influence local versions or get retired. Version exhaustion at the PostgreSQL integer limit fails closed. Revocation locks one tenant-owned key and preserves the ordinary/compromise and historical-validity policies; lifecycle changes and audit commit together. Metadata reads never select private material and reject oversized fields: identifiers/fingerprints are limited to 1 KiB, provider/status/algorithm/policy labels to 64 bytes, public-key text to 16 KiB, and stored revocation reasons to 4 KiB. The local cryptographic adapter preserves Ed25519, raw-base64 public keys, SHA-256 fingerprints and versioned KIDs. Transient generated private bytes are cleared on every command exit; persisted material retains the existing local storage/custody model, not a new encryption-at-rest or HSM claim. Human actors require tenant-wide `keys:admin` (or admin) grants. HTTP response fields and replay remain compatible; explicit `null` revocation policy fields are rejected according to the existing non-nullable schema. Key identifiers and operator reasons must be valid UTF-8 without NUL bytes; invalid database text fails validation before persistence. Local-memory mode shares the orchestration through its locked compatibility transaction. Remaining verification workflows and startup Ledger retirement remain EVY-905 work.

The PostgreSQL-profile signing-custody review uses a focused verification query,
not Ledger state. Tenant-wide `keys:admin` (or admin) authorization runs before
selection. One SQL statement reads only that tenant's signing-provider metadata
and retention-policy receipts from the same committed snapshot, with a combined
4096-record and 8 MiB serialized-data budget. Oversized or malformed projections
fail closed without a partial report. Signing-key tables and uploaded objects
are not read. The shared verification policy sorts recorded inventories and
renders expired observations as stale without changing their stored history or
creating receipts, audit entries, or jobs. Existing response fields, including
operator-supplied key references, remain available to authorized reviewers;
explicit local-memory wiring retains the compatibility path. A recorded provider
is not proof of HSM custody, and this report does not establish WORM enforcement,
deployment security, or legal compliance. Other verification workflows and the
broad startup Ledger load remain EVY-905 work.

PostgreSQL-profile retention-policy creation and verification use focused
commands, not Ledger maps. Tenant-wide `admin` creation and `verify:read`
verification authorization precede metadata reads and provider calls. Verification
reads one tenant-owned policy with an 8 MiB serialized projection limit. Provider
observations are limited to 4 MiB of serialized data and 4096 combined checks and
limitations; malformed or unavailable observations produce conservative
`not_verified` receipts without exposing provider errors. The provider call
precedes the policy row lock and receipt mutation; HTTP idempotency may already
hold its enclosing command transaction. Before saving, the command locks and
compares every projected policy field with the earlier snapshot. A competing
receipt, even with the same status, causes conflict rather than overwrite.
Creation or receipt changes and their audit entry commit together, including
the HTTP replay record when applicable. No worker job is added. Runtime wiring
uses the configured object store's retention-verifier capability; without it,
the receipt describes local intent only. Existing policy schemas, normalized-JSON
hashing, observation-expiry policy, response fields and replay remain compatible.
Explicit JSON `null` creation fields, an explicitly zero observation age, and
non-empty verification objects are rejected according to the published schema.
Names, prefixes and sample keys are bounded to 4 KiB of valid UTF-8 without NUL;
retention duration must fit a positive PostgreSQL integer. These observations
describe the configured bucket and sample, not general WORM enforcement, storage
completeness, external key custody, or legal compliance. Local-memory mode shares
the command orchestration through explicit compatibility ports.

The current `internal/domain` package and `internal/app.Ledger` are transition
paths, not the intended permanent architecture. The accepted
[bounded-context ownership decision](adr/0003-bounded-contexts.md) assigns all
current domain types, public operations, repository ports, migrations, and
worker jobs to identity/access, release catalog, evidence ingestion,
vulnerability decisions/governance, package/reporting, verification/signing,
operations/incidents, integration ingestion, or explicitly experimental
peripherals. It also defines allowed dependency direction, the post-commit
event rule, and the staged retirement of legacy package paths. The generated
API inventory remains the authoritative operation-level map during that
transition.

The context-owned model layer is implemented under
`internal/{identity,release,evidence,risk,package,verification,operations,integration,experimental}/domain`.
Those packages contain tag-free core models, context schema constants, and the
validated lifecycle and verification behavior moved by EVY-902. The legacy
`internal/domain` package remains the JSON and persistence compatibility
boundary through explicit aliases and copying mappers.

EVY-903 implemented transport-neutral command services under
`internal/{identity,release,evidence}/app`. EVY-904 added focused
`internal/{risk,package,verification}/app` services for decision lifecycle,
policy readiness, redaction, package and bundle generation, persisted CRA HTML
and custom report rendering, signing-key lifecycle, and verification workflows.
Migrated HTTP operations enter through
context-specific handler interfaces. The deprecated Ledger facade forwards
these commands and maps their models to compatibility DTOs while idempotency,
specialized report/query paths, and most service composition still use the
legacy application boundary. A repository-scoped idempotency executor now
owns the atomic reservation, command, and redacted replay protocol without
loading Ledger state; the current HTTP compatibility adapter uses that same
protocol but still clones and reloads Ledger state for its command view.
Migrating the HTTP command bindings to focused services remains EVY-905 work.
The release context now has standalone product-, project-, and release-create
commands with narrow tenant-scoped repositories and audit transactions.
Project and release creation check the parent product both before and inside
the write transaction; release versions remain unique per product. Their
database adapters and the idempotency executor have been exercised together
without constructing a Ledger. Production HTTP still uses the compatibility
command binding because later Ledger-backed commands must be migrated to
current database reads before they can safely consume products, projects, and
releases created outside its cache.
Standalone release freeze and approval commands read current tenant-owned
release and product coordinates, recheck the expected revision under a
PostgreSQL row lock, and commit the transition with its audit entry. Live
composition tests exercise those commands inside durable idempotency
transactions; production HTTP still uses the compatibility command binding.
The transactional catalog repositories now expose tenant-filtered project and
release point reads that verify the parent product in the same read and lock
the selected rows. Standalone artifact registration now looks up digests in
current tenant-scoped rows, authorizes reuse of an existing artifact, and
recovers from concurrent digest inserts without a duplicate audit entry. A
standalone build-create command uses the project and release points and
rechecks output artifact digests in the write transaction. Human output grants
are checked against current tenant-valid evidence or build associations, not
the Ledger's cached artifact links. CI-provided source metadata remains
unverified metadata. Production HTTP still uses the compatibility command
binding until downstream consumers can read these durable builds.
API-key and SSO-session verification now has a
standalone identity application service with narrow credential-read and
activity-write ports. The PostgreSQL profile binds those ports to current
credential, session, user, role-binding, and provider rows; API-key and collector
activity updates commit atomically. Local-memory mode retains the Ledger-backed
adapter. Production API-key inventory pages read public metadata from tenant-
filtered PostgreSQL rows without selecting credential hashes. Role-binding
inventory also pages current tenant rows in PostgreSQL instead of reading
the startup Ledger snapshot. Local memory retains the Ledger-backed
inventories. API and worker runtime commands,
including reconciliation and parser replay, now share a composition root for
profile/load-mode validation, PostgreSQL migrations, object-store selection,
and the production API writer lease.
The production outbox diagnostics route reads the existing payload-free
PostgreSQL aggregate through a focused operations query that requires explicit
instance-admin scope before querying. It does not load outbox jobs or tenant
labels into the API; local-memory mode retains the Ledger operator adapter.
Production terminal-job replay now uses a focused operations command. It
checks explicit instance-admin authority before idempotency lookup, then
requeues the locked job and appends its audit entry in the same PostgreSQL
transaction as the safe replay response. Local-memory mode retains the
compatibility operator path.
Production public readiness and instance-admin diagnostics now use a focused
operations probe service, not Ledger state. The composition root requires
PostgreSQL and migration probes, plus writer-lease and signing-configuration
probes in production; raw probe errors never enter either response, and safe
failure details appear only for an explicitly authorized instance admin.
The production metrics route uses a repeatable-read PostgreSQL projection for
tenant resource, portal, and reconciliation counters. Global outbox counters
are read in the same snapshot only for explicit instance administrators. The
route keeps its existing JSON and Prometheus response shapes; local-memory
mode retains the Ledger-backed metrics path.
EVY-905 also routes production product-list pages and product, project,
release, and build point reads through focused release query services with
tenant-bound PostgreSQL queries. Their actor-scope and catalog-grant checks
no longer read the Ledger's product, project, release, or build maps. The
build query joins its project, release, and product in one statement before
the service applies resource grants.
The built-in control-template catalog is owned by the risk context and read
without the Ledger in the PostgreSQL profile. It contains static starter
definitions, not tenant state; installation still uses the transactional
compatibility command path. Local-memory mode retains the Ledger list path.
The read-only release evidence-flow plan also uses a focused service in the
PostgreSQL profile: one tenant-filtered SQL statement collects nine release
counts from a consistent snapshot, then current resource grants are checked
before the response is returned. The local-memory profile keeps the Ledger
count path. The counts describe recorded evidence, not its completeness or
security assurance.
The production process still reconstructs broad Ledger state at startup for
remaining compatibility operations; removing that startup load and migrating
other reads remain open EVY-905 work. Evidence list and search pages now use
bounded PostgreSQL keyset batches under one read-only snapshot for restricted
human grants, with grant checks before pagination. The compatibility Ledger
still holds authorization relationships and parser-normalization validation
state; removing its full startup load remains open.

Evidence point reads and lifecycle pages in the PostgreSQL profile also use
focused queries, including parser-owned items and replay markers; neither
handler falls back to the Ledger when the focused query rejects a projection.
Each repeatable-read snapshot resolves tenant-owned parent coordinates and
applies current resource grants before loading metadata or selected worker
facts. The shared provenance reader enforces an 8 MiB combined item/fact
budget and a 4096-row parser-fact limit; replay markers additionally validate
their source and linked audit facts. Lifecycle pages have a separate 8 MiB
serialized-event budget, including all text/details and the lookahead row.
Oversized or malformed stored data fails closed without a partial page.
Selected provenance rows are share-locked; these logically read-only
transactions always roll back and create no receipts, audit entries, or jobs.
Existing response fields and lifecycle redaction remain unchanged. Explicit
local-memory wiring retains the compatibility path. These reads do not verify
uploaded payload bytes, scanner completeness, or the complete audit chain.

A focused PostgreSQL
vulnerability-scan point read now checks source evidence and current parent
ownership in a repeatable-read snapshot before grant authorization; it does
not independently verify scanner coverage. VEX document and import-report
points similarly validate current source, release, artifact, and report links
before returning metadata. Admin audit-log pages use
tenant-filtered PostgreSQL keyset queries in the durable profile, while local
memory mode retains its in-process chain reader. The audit-log response shape
remains unchanged, and both modes require a tenant-wide human admin grant;
durable paging is no longer limited to the
newest 500 entries before pagination. `make domain-context-check`
prevents model ownership, field compatibility, schema ownership, import, and
transport-tag drift during the remaining transition.
Vulnerability-decision history also uses a risk-owned PostgreSQL page query:
one read snapshot validates filter coordinates and applies current
tenant/product/release grants before the keyset limit. Internal notes are not
selected or serialized. Its customer-safe summary report reads only active,
visible decisions for one release under the current `report:read` grant, using
the same versioned wording as local-memory mode. Local memory retains the
Ledger readers.

## Tenant And Auth Boundaries

Tenant isolation is enforced in application methods before reads and writes return data. API keys are scoped, revocable, and stored as HMAC-SHA256 hashes with `EVYDENCE_API_KEY_PEPPER`.

Human SSO session tokens and customer portal package tokens are also stored as hashes and returned only once. Human actors derive scopes from tenant role bindings. Collector identity is server-derived from the API key binding and is not trusted from build upload request bodies.

Instance diagnostics require explicit `instance:admin` scope. Tenant admin and ordinary wildcard tenant keys do not satisfy that instance-wide scope by themselves.

## Storage And Append-Only Behavior

With `EVYDENCE_RUNTIME_PROFILE=postgres` and `EVYDENCE_DATABASE_URL` set, mutations are saved to PostgreSQL before successful responses return. When object storage is configured, upload payload bytes, including raw SBOM, vulnerability scan, OpenAPI, OpenVEX, CycloneDX VEX, and DSSE build-attestation payloads, are written with tenant-prefixed keys and SHA-256 digest checks before metadata is accepted.

Managed payload identity uses the versioned `evydence-object-key.v1` layout. Canonical SHA-256 digests are lowercase `sha256:<64 hex>` values; staging and finalized payload keys are exactly `tenants/<tenant>/staging/sha256/<hex>` and `tenants/<tenant>/payloads/sha256/<hex>`. Tenant identifiers and logical object keys reject traversal, path separators inside tenant IDs, control characters, empty/dot path components, and cross-tenant ownership. Filesystem operations are rooted beneath `EVYDENCE_OBJECT_DIR` without following symlinks outside that root. S3/MinIO reads validate tenant metadata, provider byte count, media type syntax, and the SHA-256 digest against the returned bytes before content is trusted.

Evidence, evidence lifecycle events, incidents, remediation tasks, security scans, manual security documents, SBOM diffs, VEX documents, vulnerability decisions/workflow records, organizations, users, role bindings, SSO providers, SSO sessions, legal holds, retention overrides, customer portal access records, questionnaire packages and drafts, evidence summaries, evidence graph snapshots, commercial and marketplace collector definitions, waivers, approvals, customer packages, report templates, evidence bundles, exceptions, build runs, build attestations, release candidates, artifact signatures, source-control records, deployment events, contract diffs, custom policy evaluations, provider verifications, signing operations, control evidence links, public transparency log entries, and release bundle records are append-only in behavior. Changes are represented by supersession, lifecycle events, approval transitions, session revocation, package access records, links, verification receipts, rollback-as-new-event records, or new audit-chain entries.

Outbox jobs are persisted in PostgreSQL and claimed by workers with `FOR UPDATE SKIP LOCKED`. Parser jobs re-read tenant-prefixed object-store payloads, verify size and digest, validate durable state, persist missing parser-derived normalized fields, and fail closed on mismatches. With `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`, non-VEX parser-backed uploads store accepted records and workers populate normalized document fields from replayed payloads. VEX uploads always store their verified normalized document, an accepted import report, and a bounded versioned decision request in the upload transaction. The `parse_vex` worker creates vulnerability decisions idempotently after commit and completes the report; it verifies the request against replayed raw bytes when available and otherwise consumes the normalized request directly. A tenant-scoped PostgreSQL projection repository refreshes worker-owned records for the compatibility read model. It is bound to the active command transaction when one exists, and a per-tenant shared/exclusive advisory fence keeps projection reads, worker mutations, and audit appends from interleaving inconsistently. The exact behavior and compatibility limit are documented in the [worker outbox contract](reference/worker-outbox.md).

## Verification And Trust

Release readiness is deterministic and evidence-scoped. Open critical vulnerability findings block readiness unless the latest decision marks the finding `not_affected` or `fixed`, or an approved unexpired exception applies to the release or finding. Passed build provenance and a structurally valid build attestation must link to release artifact digests.

DSSE attestation signatures can be verified against configured Ed25519 trust roots when raw attestation bytes are available. The Cosign route verifies a finalized stored offline Sigstore bundle with operator-configured Fulcio/public-key trust material, the artifact digest, signature bytes, keyless caller-supplied identity/issuer policy when applicable, and an embedded Rekor inclusion proof. It records a safe library and trust-root version receipt, never raw trust material or bundle bytes. Requests requiring online verification fail rather than downgrading; missing trust material returns `COSIGN_FULL_VERIFICATION_UNAVAILABLE`. Signing keys support revocation and valid-at-signing semantics for historical signatures.

Merkle batches, signed checkpoints, optional transparency checkpoint/public transparency records with operator-supplied or fetched inclusion proof verification, backup manifests, object-retention policy records with verification hashes, legal holds, retention overrides, readiness, metrics, instance admin diagnostics, external signing gateway/AWS KMS signing receipts, and admin audit queries provide operational integrity and review surfaces. The production retention report reads tenant-filtered legal holds and overrides from one PostgreSQL snapshot; it describes Evydence records and does not verify external storage lifecycle enforcement. The production incident report reads one tenant-owned incident, its timeline, and its remediation tasks from one PostgreSQL snapshot. It rejects rather than truncates reports with more than 4096 combined timeline events and tasks; evidence links organize recorded references without proving root-cause or remediation completeness.

## Reports And Customer-Facing Packages

Control coverage and CRA-readiness reports use versioned tenant-created controls, explicit evidence links, approved unexpired control exceptions, and built-in starter packs for CRA-readiness, NIST SSDF-lite, SOC 2-style technical evidence, and ISO 27001-style technical evidence.

In the PostgreSQL profile, these reports read controls, current tenant-owned evidence subjects, and active exceptions from one repeatable-read snapshot. Subject scope and observed time are resolved from durable records before freshness is evaluated; stored link coordinates alone do not grant report inclusion. The reader rejects reports above 4096 combined controls, links, and exceptions or 8 MiB of selected text rather than silently truncating them; SQL preflight bounds individual control, link, and exception rows before transfer. An empty framework yields unknown coverage, and broad reports do not apply release-specific waivers. Local-memory mode retains the compatibility Ledger report path. These reports organize recorded technical evidence; they do not determine legal compliance.

The production security-update evidence report reads fixed decisions, scans, incidents, and remediation tasks for one tenant-owned release from a repeatable-read PostgreSQL snapshot. It omits private decision notes, verifies linked evidence remains in the tenant and report scope, and rejects rather than truncates reports above 4096 source rows or linked evidence identifiers. It organizes recorded evidence only; it does not prove legal sufficiency, notification completeness, or release security. Local-memory mode retains the Ledger report path.

The production CRA vulnerability-handling report uses the same tenant/release snapshot and evidence-scope discipline. PostgreSQL aggregates scan finding counts without loading raw finding arrays into the API, then projects active decisions and approved unexpired exceptions with a 4096-row/evidence-ID cap. It excludes private decision notes and does not claim complete detection, scanner authority, legal compliance, or release security. Local-memory mode retains the Ledger report path.

Source snapshots, deployment records, signed incident webhook events, incident packages, security scans, manual reviews, SBOM diffs, contract diffs, API security checks, customer packages, customer portal package access, questionnaire packages, evidence bundles, and custom policies add traceability and reproducible decisions. Reports include gaps, assumptions, and limitations.

Evidence summaries, questionnaire drafts, graph snapshots, PDF packages, and anomaly reports are generated from stored records with citations, assumptions, and limitations. Customer-facing packages require explicit package scope, redaction profile, expiry, and access auditing. Customer package JSON and ZIP download paths return scoped manifest metadata and verification guidance; raw tenant evidence payload bytes are not returned.

## Provider And Deployment Boundaries

GitHub OIDC subject metadata can be captured, and stored OIDC/SAML identity links can be verified against tenant metadata. OIDC provider records can include public JWKS material for local EdDSA or RS256 ID-token signature and claim verification, and SAML provider records can include PEM signing certificates for local assertion signature and claim verification. Trust material can be rotated without recreating the provider, and OIDC public JWKS can be refreshed from discovery metadata. SSO credential exchange can issue bearer session secrets plus HttpOnly cookies for browser clients after local OIDC/SAML verification. Live provider management API verification, browser redirect/callback orchestration, and external group synchronization remain trust boundaries outside those records. Collector supply-chain records track pinned collector versions with signature, SBOM, and scan evidence where available; commercial and marketplace collector definitions add extension metadata without granting provider trust.

Air-gapped import-bundle workflows preserve the same tenant-scoped import path after controlled transfer. Object-retention policy APIs record tenant-scoped retention intent and, when the S3/MinIO object-store adapter is configured, verify bucket versioning plus default object-lock mode and duration. Policies can also name a tenant-prefixed sample object key for object-level retention and optional legal-hold checks where the provider supports them. Those checks are evidence for the configured bucket and sample object only; WORM/object-lock enforcement, IAM policy, lifecycle rules, and deployment-specific retention review remain operator responsibilities.

## Limitations

The in-process store requires `EVYDENCE_RUNTIME_PROFILE=local_memory` and an unset `EVYDENCE_DATABASE_URL`; it is non-durable and cannot run the worker. Explicitly configured local filesystem payload files may remain after in-memory metadata is lost. S3/MinIO runtime object storage is available through the object-store port in PostgreSQL mode. Signing-provider operation receipts, an optional HTTPS signing gateway executor, built-in AWS KMS, GCP Cloud KMS, and Azure Key Vault signing executors, gateway-backed `pkcs11-hsm` mode, native PKCS#11/HSM custody profile records, OIDC discovery refresh, optional live OIDC UserInfo validation, an optional provider validation gateway, SSO credential exchange with session-scoped OIDC group-role mapping, public-transparency proof fetching, an optional transparency proof gateway, and optional worker-owned parser side effects are implemented, but native HSM module loading/execution, direct provider-specific management API clients, and external group synchronization remain deployment hardening work. Hand-tuned per-resource repository implementations remain production-readiness work. `ENV=production` rejects the in-process store, default API-key pepper, unsupported API writer modes or replica counts above one, local plaintext signing-key mode, and bootstrap secret printing.

Evydence does not prove provider truth, scanner authority, runtime security, legal compliance, or release security by itself.
