# Architecture

Evydence follows a ports-and-adapters shape:

- `internal/{identity,release,evidence,risk,package,verification,operations,integration,experimental}/domain` contains the context-owned core models and schema constants.
- `internal/{identity,release,evidence}/app` owns the focused Identity, Release, and Evidence command services implemented by EVY-903.
- `internal/domain` supplies compatibility DTOs at HTTP, persistence, and legacy-facade boundaries while callers migrate.
- `internal/app` is the deprecated Ledger compatibility facade, the shared transaction and storage port surface, and the temporary home of contexts not yet migrated.
- `internal/adapters/httpapi` adapts application services to HTTP and OpenAPI; migrated Identity, Release, Evidence, Decision, Package, and Verification handlers depend on context-specific interfaces.
- `internal/adapters/postgres` provides the durable ledger-state store, migration runner, tenant-scoped relational resource projection, and persisted outbox.
- `internal/platform/wiring` validates the PostgreSQL-only API/worker runtime, opens database and object-store adapters, and composes the API's focused durable authentication/command/query ports. Retired local-memory input fails before resources are opened.
- `internal/adapters/objectstore/filesystem` stores raw uploaded payload bytes under tenant-prefixed object keys for local and self-hosted deployments.
- `internal/adapters/objectstore/s3` stores the same tenant-prefixed object keys in S3/MinIO-compatible buckets.
- `cmd/*` contains process entry points.

PostgreSQL API first-tenant bootstrap is composed directly from focused Identity
and Verification commands, independently of Ledger construction or inventories.
The boolean empty-installation check and tenant/API-key/audit/initial-signing-key
writes use one startup transaction; an empty-table-safe lock prevents concurrent
or ordinary tenant inserts from racing the bootstrap decision. Credentials are
returned only after commit and never on restart. Local evaluation uses this same
database path. The [bootstrap configuration reference](reference/configuration.md#first-tenant-bootstrap)
owns the input bounds, lock timing, secret-output policy, and local signing-key
storage limitations.

## Current runtime composition

The PostgreSQL API entry point binds
`httpapi.NewNativeServerWithOptionsContext`, without constructing a Ledger.
The constructor requires every focused authentication, command and query port,
streamed/historical durable replay, and a stable pagination key. Missing or
typed-nil ports fail startup; no local-memory adapter or aggregate replay is
installed. Its shared composition helper accepts only focused options: it has
no Ledger parameter, constructor/binding call or local-mode switch. The API entry
point no longer constructs Ledger or `app.Config` in any branch. PostgreSQL is
required for local evaluation as well as deployment. Request middleware, route
registration and response contracts are unchanged.

HTTP transport exposes no Ledger-accepting server constructor, aggregate field,
legacy replay interface or aggregate handler fallback. Historical fixture
construction/binding and focused test-port adapters exist only in `_test.go`
files; existing HTTP behavior assertions are preserved. Production callers
use `NewNativeServerWithOptionsContext`. The unused non-context `app.NewLedger`
factory has also been deleted. The application constructor and remaining
aggregate implementation still await physical retirement in EVY-906. This
fixture separation is not completion of that work and does not create another
supported runtime backend. See the
[unreleased migration note](reference/configuration.md#retired-local-memory-profile-unreleased).

PostgreSQL HTTP integration fixtures now construct native servers directly,
without an otherwise empty Ledger. Their former reload-counter/cache probes
are replaced by an unreadable database snapshot canary and assertions that no
legacy transport binding is installed. The canary must remain unchanged after
requests and at fixture cleanup. Existing HTTP status, DTO, tenant/grant,
rollback, privacy and restart/replay expectations remain in place.

Release-context HTTP creation, lifecycle transitions, attestation ingestion,
catalog point/page reads and evidence-flow plans now have only focused
command/query paths. The broad `releaseCatalog` Server field and its entire
interface are deleted, including the remaining 16 methods after the earlier
creation cleanup. Native decoders, cookie-origin checks, command guards,
revision fingerprints, cursor binding, payload-coordinate redaction and
response mappings are unchanged. Transitional local test setup supplies
test-only focused adapters; its failure-after-write regression verifies that
the isolated command clone does not publish product or audit effects on
rollback. This does not retire the remaining aggregate implementation or
other contexts' legacy handler branches.

API-key and role-binding metadata lists now require their focused query ports;
the old inventory-list branches and two broad identity-interface methods are
deleted. Native page parsing, tenant/admin checks, error mapping and public
metadata encoding remain unchanged. Test-only readers retain real fixture
authorization, strip credential hashes and use the shared cursor-key ordering.
API-key creation also requires its focused command/replay ports; the broad
identity credential-creation method and fallback handler are deleted. Native
input validation, tenant-wide administration, instance-scope restrictions and
one-time-secret replay behavior remain unchanged. The test-only guard uses
the real focused policy and validates ownership through the legacy fixture's
retained bootstrap key; any attempted preflight issuance/write fails closed.
Failure-after-issuance tests check credential/audit rollback, unusable rolled-
back secrets and current authorization before replay. Other identity writes
and session compatibility paths still await retirement.
The existing in-memory unit-of-work fixture now implements the tenant-scoped
API-key creation read capability, so the real focused command can run its
preflight and issuance tests. It uses optimistic commit-version checks, not
PostgreSQL row locks. Rejected/readonly guards do not issue credentials or
change repository data. This is test-adapter groundwork, not a new API runtime
or completion of aggregate retirement.

Deployment environment/event creation, inventory pages and event point reads
now require the focused Operations command/query ports. The broad local
deployment Server binding and interface are deleted. Existing native request
validation, cookie-origin checks, current ownership/grant guards, replay,
cursor binding and DTOs are unchanged. Test-only adapters retain real fixture
authorization; failure-after-write tests prove that environment/event,
evidence, audit and outbox effects roll back together. This is transport
retirement, not deletion of the remaining Ledger maps and methods.

Generic evidence creation, supersession, linking and lifecycle-event handlers
now require focused Evidence command/replay ports. Both broad local evidence
bindings and their interfaces are deleted. Native structured decoding, exact
JSON numbers, cookie-origin checks, current ownership/grant guards and response
mapping remain unchanged. Test-only adapters retain real fixture authorization
and the isolated command clone. Failure-after-write regressions compare every
repository effect, reject partial responses and verify that failed commands
do not publish core, link or supersession changes.

Collector creation/releases/health/inventory, commercial definitions and all
source repository/commit/branch/pull-request/snapshot handlers now require
focused Integration ports. Twelve handler fallbacks (thirteen routes) and four
aggregate-only input mappers are deleted. Native input, cookie-origin,
current-ownership, replay and one-time-credential rules are retained. Test-only
adapters preserve former source guards and real isolated child commands;
collector preflight runs the actual focused guard, with fail-loud write,
credential, clock and ID capabilities. Fixture tenant checks depend on real
bootstrap keys and do not emulate SQL locking. Nine failure-after-write/replay
cases cover credentials, pins, source children and audits; read regressions
cover tenant/grant filtering, complete pages, cancellation and detached metadata.
Runtime readers continue to filter and limit in PostgreSQL, not these fixture
inventories. Other contexts and the aggregate itself remain EVY-906 work.

Incident creation/timeline/tasks, signed receiver creation/ingress, incident
reports, legal holds, retention extensions and retention reports now require
focused Operations/Package ports. Eight handler fallbacks across nine routes
are deleted. Native current ownership/grants, signature-before-parsing,
timestamp/replay protocols, cookie-origin checks and atomic writes are retained.
Test-only adapters run actual native preflight algorithms on focused memory
transaction readers; writes retain the isolated historical commands. No guard
may invoke effects, private webhook reads, clocks or IDs. The signed callback
fixture retains its separate real business-replay unit of work, not HTTP
idempotency. Six full-state write rollback/replay regressions, callback
failure-after-insert recovery and read-only report/metadata-detachment tests
are separate from live PostgreSQL lock, restart and concurrency evidence.
The memory readers validate coherent incident parents and selected retention
root ownership without consulting Ledger; they do not model SQL row locks.

Framework/control creation, starter-pack installation, evidence linking and
their definition/catalog/link reads now require focused Risk ports. Eight
handler fallbacks and three aggregate-only input converters are deleted.
Native decoding, cookie-origin checks, current ownership/grants, replay and
DTO/cursor contracts remain unchanged. Test-only bridges preserve the actual
former guards and isolated historical writes, with full-state rollback/replay,
complete-page tenant/grant filtering, cancellation and definition-detachment
regressions. Static starter packs contain no tenant data and require only the
credential read scope. The old template-install command now attributes human
audits correctly; native PostgreSQL already used the actual principal.
These fixture checks are not SQL locking evidence or completion of aggregate
retirement. Runtime query limits and current-subject validation remain in SQL.

Custom-policy creation/evaluation, vulnerability workflow annotation, release
security summary and vulnerability posture handlers require focused Risk or
Package ports. Their five aggregate fallback paths are deleted. Native guards,
structured decoders, durable replay and public DTOs are unchanged. Test-only
guards run the actual focused authorization algorithms on transaction-owned
tenant/policy/release/finding references; policy-rule/evidence-content reads,
effects, hashes, clocks and IDs fail loudly during preflight. Historical writes
retain isolated replay clones. Three full-state rollback/replay regressions
cover current human grants and foreign parents; report checks cover all public
fields, tenant/grant filtering, private-note omission, cancellation and detached
metadata. The historical custom-policy commands now attribute human audits
correctly, matching existing native behavior. Fixture ownership and inventory
checks are not evidence of SQL locks or bounded production reads.
The memory Risk repository now has a focused identifier-only workflow reader:
it validates current typed source/parents and ambiguity, preserves a scan's
declared release-less state, and ignores vulnerability text and old reasons.
It uses the transaction snapshot, not Ledger maps or PostgreSQL locks.

Evidence list/search and point reads, lifecycle pages, SBOM documents/components,
scan/contract points, VEX documents/reports and both VEX previews also require
focused query ports. Their twelve fallback branches and sixteen obsolete broad-
interface methods are deleted, including four unused creation/relationship
methods. Native filters, cursor parsing/binding, query error mapping, lifecycle
redaction, document DTOs and preview validation are unchanged. Test-only readers
retain actual former ownership/grant policies and detach mutable document,
issue and advisory metadata; read-only regressions cover both tenants, complete
fixture pages, revoked grants and previews. The SBOM component fixture retains
its former 500-item cap; runtime SQL pagination has separate beyond-cap tests.

SBOM/SPDX, OpenVEX/CycloneDX VEX, vulnerability-scan, OpenAPI, security-scan,
API-security and manual-document uploads, plus both document diffs, now require
focused Evidence commands. Their eleven transport fallbacks, fifteen-method
broad interface, Server binding and aggregate streamed-upload wrapper are
deleted. Native parsing, body limits, semantic-header fingerprints, current
ownership/grant guards and atomic PostgreSQL writes remain in place. Test-only
adapters run the actual native preflight algorithms and authorizers; effect,
clock and ID capabilities panic if a replay guard reaches them. Fresh fixture
writes use the real legacy parsers and isolated command clone, not those guard
capabilities. Eleven failure-after-write and replay regressions check complete
repository state, including payload, audit, outbox and derived-record effects.
They are not a substitute for the live PostgreSQL transaction tests.

VEX idempotency replay preserves a plain author email only in the closed,
validated, versioned public document DTO. Unknown fields, credential-like author
text, other response fields, logs and customer-package redaction keep the generic
policy. Previously cached responses whose author was already redacted cannot be
reconstructed by this fix. The explicit memory test adapter also accepts a
zero-finding security scan without requiring a nonempty summary; required
metadata and nonzero-finding validation are unchanged. Direct context Ledger
calls and the aggregate implementation still require retirement under EVY-906.

Report-template creation/rendering and portable bundle import/export now
require focused Package ports. Their three broad local bindings and interfaces
are deleted. Native field whitelists, inert template data, portable import
receipts, signature/audit writes and saved-selection replay guards are unchanged.
Export replay rechecks the original saved evidence IDs against current authority;
it does not rebuild the manifest or sign again. Test-only clone adapters retain
the legacy response guard after execution, not SQL ownership locking. Their
failure-after-write tests check rollback of all repository effects, including
definitions, rendered reports, receipts, bundles, signatures and audits. Other
release/customer creation, audited package access/download, security-review,
HTML and readiness-report fallbacks have also been deleted, along with the
ten-method `packageService` interface and Server binding. Test-only adapters
preserve the former real scope policies, signing, privacy and access-audit
behavior; native ports continue enforcing bounded SQL ownership/transactions.
The release-bundle API description now states that PostgreSQL is required,
including local evaluation.
Control coverage, CRA readiness/vulnerability handling, security-update,
missing-evidence and both release-bundle reads also require focused queries;
their seven aggregate fallback paths are deleted. Native filters, errors,
current grants/parents and bounded SQL are unchanged. Test-only readers retain
actual former grant rules and detach mutable report and manifest data. The
missing-evidence fixture uses real current authority and a pure readiness
preview with the same Package renderer, not the old write-producing helper.
Regressions compare all public DTO fields and complete repository state after
reads, denials, cancellation and nested metadata mutations. The memory ownership
dispatch now recognizes control-scoped exceptions without weakening wrong-tenant
checks. Other direct Package-context Ledger calls and aggregate state remain
EVY-906 work; fixture inventories do not establish SQL limits or locking.

Signing-key and audit-log pages, custody reports, and audit-chain/Merkle/backup
verification handlers now require their focused Verification ports. Six broad
read/report branches and four obsolete transport-interface methods are deleted.
Native page parsing, cursor binding, public key DTOs, error mapping and failed-
verification response semantics remain unchanged. Test-only readers retain
actual tenant/admin policies, omit private key bytes and preserve lifecycle,
assurance-profile and report metadata. Their pure query tests verify no writes;
verification calls retain their existing result/audit behavior. The local audit
fixture retains its former 500-entry inventory cap; runtime SQL pages filter
before limiting.

Signing-key rotation/revocation and signing-provider/DSSE trust-root creation
also require focused Verification commands. Their four fallback branches and
five obsolete broad-interface methods are deleted. The native durable callbacks
retain tenant-wide administration, flat key ownership, strict input bounds,
cookie-origin checks, public-only key responses, and atomic audit/replay effects.
Test-only command adapters retain the real former policies and isolated replay;
failure-after-write tests compare all repository effects and cached key lifecycle.
The four request descriptions now require PostgreSQL, including local evaluation;
their schemas and response contracts are unchanged.

The remaining subject, release-bundle, DSSE and Cosign verification, backup
generation, Merkle creation, recorded-checkpoint and retention handlers also
require focused ports. All nine remaining broad Verification branches, the
ten-method `verificationService` interface and Server binding are deleted.
Native callbacks, current-authority guards and atomic receipt/audit/job/replay
behavior are unchanged. Test-only adapters preserve actual policies, public
assurance metadata and the legacy fixture's distinct v1 backup hash; they are
not a runtime backend or a PostgreSQL locking proof. Seven affected API
descriptions now require PostgreSQL without schema or response changes.
Artifact-signature recording and signature point reads now require focused
Verification ports; both direct aggregate handler fallbacks are deleted.
Native authorization, input bounds, cookie protection, canonical-reference
replay and current-digest query contracts are unchanged. Test-only adapters
retain the former guards/point rules and isolated writes; actual filesystem
staging regressions cover repository rollback, no-restaging replay/denials,
human grants, tenant boundaries and complete public DTOs without raw bytes.
The legacy command now attributes human audits correctly. Fixture reads are
not proof of native SQL locks or current digest/source validation.
Other contexts' Ledger calls and aggregate state still await
retirement; deleting the transport interface alone does not complete EVY-906.

Vulnerability-decision and exception pages, plus the customer-safe decision
summary, now require focused Risk queries. Their three broad fallback branches
and obsolete interface methods are deleted. Native filter/cursor validation,
scope-before-limit PostgreSQL reads, error mapping and response schemas are
unchanged. Test-only readers retain actual tenant/resource-grant filtering,
supersession and visibility semantics, omit internal notes before the query
boundary, and copy public report/approval metadata. Read-only state and mapping
regressions cover these fixtures.

The explicit in-memory unit-of-work test adapter now supplies focused waiver,
exception and approval readers. They resolve current typed tenant/product/
release/source ownership, reject ambiguous findings, separate authority-only
transition reads from bounded fresh records, and detach mutable timestamps.
Tests exercise the real native governance guards and fresh commands/audits
without constructing Ledger. The five waiver/exception creation and approval,
and approval-record transport fallbacks and their broad-interface methods are
also deleted; these handlers unconditionally use focused commands. Native
callbacks and API schemas are unchanged. Governance HTTP fixtures explicitly
opt into the repository adapter, execute actual native authority guards and
preserve isolated replay writes. Failure-after-write tests cover complete effect
rollback; retries recheck current grants without reapplying transitions. These
test-only bridges do not install another API runtime or prove SQL locks.

Vulnerability-decision creation and built-in release evaluation now also
unconditionally use focused Risk commands. Their two remaining broad fallback
branches, the `riskDecisionService` interface and Server binding are deleted.
Native input validation, current-authority guards, private-note omission,
append-only decision history and atomic evaluation/audit/replay callbacks are
unchanged. Test-only bridges use actual Risk authorizers and current owned
coordinates, isolate writes, preserve exact replay and detach recorded checks.
The existing synchronous VEX import/manual-link assertions remain intact;
additional repository-fixture coverage exercises links to queued documents.
Repository-backed ingestion fixtures now resolve product/project/release
ownership through the actual focused Evidence scope capability, rather than
catalog DTO/cache reads. Validation and the current grant check share one
fixture transaction; the reader selects only coherent owned IDs, including
current tenant existence, and ignores unrelated descriptive/lifecycle fields.
Explicit repository configuration survives rebinding and does not fall back
to legacy caches after missing-dependency or commit failure. Six native guard
regressions cover repository-only parents, removed/foreign grants, no clock/ID
or write effects, cancellation, one-transaction reads and safe failed preflight.
Operations, governance and identity repository helpers opt into this scope
configuration. The memory capability reuses coherent point-coordinate reads;
it is not PostgreSQL locking, durability or bounded-transfer evidence. Artifact
and diff fixture reads, historical parser writes and unsupported synchronous
fixtures retain separate retirement dependencies. This removes guard coupling
for configured fixtures, not the remaining production Ledger implementation.
The broad Risk transport surface is gone, but direct context-to-Ledger calls
and aggregate state still require retirement before EVY-906 can close.

`cmd/openapi` renders the shared route contracts through
`httpapi.GenerateOpenAPI`, without constructing Ledger, credentials or runtime
ports. This path returns only the validated document, not a runnable server;
the native server's mandatory dependency checks remain unchanged.

Constructor tests cover every missing dependency and typed-nil case. The live
native route sweep uses a deliberately invalid compatibility snapshot: aggregate
loading must fail, while all 189 routes, valid product creation, restart replay
and current-grant revocation remain functional. The canary stays invalid after
writes. This is focused API evidence, not complete production-gate evidence.
The worker daemon now composes a closed native processor with subject-scoped
reads, claim-fenced writes, dependency inspection and payload lifecycle ports.
Its object adapter must support bounded replay reads. Unknown job kinds are
rejected before data access; production cannot select a whole-state load or
snapshot publication fallback. Signals cancel runtime I/O and idle poll waits.
EVY-906 has physically removed the worker's whole-state read, snapshot
publication and unfenced mutation fallbacks; tests use focused ports. See the
[worker outbox contract](reference/worker-outbox.md) for evidence and limits.
EVY-905 composition/query migration passed its complete local production gate.
That includes full tests, race, live dependencies, coverage, migration compatibility,
black-box API/worker/restart flows and signing smoke. See the root backlog for
commands, commits and limits. EVY-906 physical legacy retirement and architecture
enforcement remain outstanding; local checks are not hosted CI or publication.

Per-route transition notes below include historical migration checkpoints.
Their pending EVY-905 startup, worker, wrapper and query-migration statements are
superseded by this section; they are not descriptions of current native production
wiring. Local-memory passages below describe historical migration or remaining
test utilities, not a supported API runtime. See the [runtime configuration reference](reference/configuration.md#first-tenant-bootstrap)
for current operator behavior.

## Architecture enforcement (EVY-906 in progress)

`make architecture-check` tests the source inspector and policy, then scans
non-test Go source under `cmd`, `internal`, `pkg`, `sdk` and `examples` with the
Go AST. Build-tagged source is included regardless of the current platform;
tests, testdata, vendored and hidden directories are excluded. Selected source
is never compiled or executed. Child symlinks, non-regular source and files
over 8 MiB fail inspection; errors do not quote source tokens.

Import cycles and inward-boundary violations fail the check, including indirect
paths through helpers. Context domains remain independent; application/query
packages cannot import concrete transport/storage/provider adapters, foreign
application/query services, or production dependencies on experimental contexts.
Scoped foreign-context domain read models remain allowed. The neutral legacy
pagination package `internal/app/query` is not an aggregate service. Generated
source must obey the same import policy.

Non-generated files above 800 lines and public interfaces above 12 declared
methods plus embeddings produce review flags, not automatic rejections.
This metric does not expand embedded method sets; reviewers must inspect those
as well. Generated declaration size is exempt, not generated imports. These
are review triggers, not proof of cohesive architecture.

The Package report query now consumes Risk-owned readiness facts and the pure
`internal/risk/domain` evaluator, not the Risk application service. Complete
policy-result compatibility vectors preserve its check order, wording and
timestamps; tenant/grant checks and bounded query behavior remain unchanged.
DSSE parsing and offline policy verification are supplied through inward ports.
Concrete `dsse` adapters are constructed by outer wiring and test-only fixture
setup, never by the legacy application package. Its constructor rejects absent
or typed-nil ports before state loading; local idempotency clones retain the
configured ports. Native bounded-object verification uses the same offline
policy adapter without changing its tenant/key/digest/size/media checks.

The redundant `identityService`, `releaseEvidenceService`, and
`packageReportService` shells have been deleted together with their factories
and 34 Ledger-to-shell forwarding methods. These were wrappers around the same
aggregate, not focused services. Existing local implementations retain their
authorization, locking, audit and redaction behavior directly on the legacy
receiver while its maps, snapshot machinery and mutex await retirement.
This deletion adds no replacement compatibility layer and does not complete
EVY-906.

Eleven additional leaf methods have been removed from the production Ledger
surface: tenant-inventory, missing-evidence reporting, ordinary key revocation,
non-paged evidence search, API-scan/SPDX ingestion and source-provider snapshot
facades, plus two obsolete approval/waiver target validators and an unused
streamed-attestation facade. Ten remain unchanged solely in
`internal/app/legacy_leaf_oracle_test.go` for package-local historical tests;
the unused attestation facade is deleted. The source-snapshot parser and its
schema, used only by the two retired provider facades, are also test-only.
Native focused commands, bounded queries and streamed ingestion remain
unchanged. These historical oracles are not supported runtimes or proof of
native SQL behavior; source checks forbid the retired production declarations.

The import-graph gate now passes without boundary exemptions and is included in
`fast-check` and `finalize`. Size/interface review flags remain. A passing import
graph is not Ledger retirement: EVY-906 stays incomplete until its obsolete
aggregate surface is removed and all required final validation passes.

## Storage and workflow adapters

Both object-store adapters expose `app.BoundedObjectReader.GetBounded` for
workflows that require a payload budget. It checks actual file/provider size
before reading and reads at most the requested limit plus one overflow byte,
independently of declared database sizes. Oversize returns conflict with no
partial object; successful reads retain key, tenant, metadata-size and digest
validation. Filesystem reads stay beneath `os.Root`, require regular files and
limit metadata sidecars to 64 KiB. S3 reads close the provider stream even when
HEAD understates the body size. Limits must be positive and permit overflow
detection without integer overflow. Durable DSSE and Cosign verification require this
capability; other existing `ObjectStore.Get` callers retain their unbounded
compatibility behavior until their owning workflows migrate.

PostgreSQL-profile backup-manifest verification uses a focused transaction
reader for one tenant-owned manifest's recorded state hash and consistency
checks, not Ledger state. Tenant-wide verification authorization precedes
content reads; the tenant and manifest stay share-locked through atomic
receipt/audit/outbox effects. Unused resource-count maps and stored limitations
are not loaded. The shared inspector preserves the existing recorded-check
profile, not a fresh state-export comparison or restore proof. Backup generation
remains separate migration work. See
[recorded backup verification](reference/verification-results.md#recorded-backup-manifest-verification).

Core logic does not depend on HTTP routers, SQL drivers, object storage SDKs, queues, KMS providers, provider clients, or UI frameworks. PostgreSQL persistence currently stores a versioned ledger snapshot and rebuilds tenant-scoped relational projection rows plus forward-compatible per-resource tables for implemented release, evidence, source, deployment, and control resources. Identity, idempotency, and customer portal token records are synchronized into relational rows with non-secret hashes and tenant-scoped constraints. Release-ledger core rows are also synchronized for products, projects, releases, artifacts, evidence, audit-chain entries, signing keys, signatures, SBOMs, vulnerability scans, OpenAPI contracts, policy evaluations, release bundles, and verification receipts. Collector/build provenance, source/deployment, incident, security evidence, SBOM diff, vulnerability workflow, contract diff, custom policy, waiver, approval, DSSE trust-root, collector release, Cosign verification, signing provider, Merkle batch, transparency checkpoint, evidence lifecycle, release candidate, VEX/risk decision, control, package, report, retention, provider verification, signing operation, and future-extension records are synchronized into their migration-backed relational tables. PostgreSQL API startup uses focused native composition without aggregate reconstruction. Production database adapters retain relational-only load policy and disable compatibility snapshot writes for worker/import/recovery paths; non-production adapters retain snapshot-preferred compatibility when explicitly used. In production, API startup also takes a PostgreSQL advisory writer lease so an accidental second API writer fails closed while the supported profile remains single-writer. The accepted [database-authoritative command-transaction decision](adr/0001-database-authoritative-transactions.md) requires a command to commit its domain, audit, idempotency, and outbox effects before publication, and defines staged/finalized object-storage handling. Existing focused and broad call sites remain tracked in the generated [persistence decomposition inventory](reference/persistence-decomposition.md); this is production hardening work, not a completed maturity claim.

The PostgreSQL-profile missing-evidence report reads release-readiness facts in a tenant-scoped, repeatable-read transaction and evaluates them without writing a policy receipt. The release security summary uses that same bounded readiness projection together with release workflow, finding, decision, approval, and exception facts in one committed view. The release-readiness report gathers canonical readiness facts, unhandled critical findings, approved unexpired exceptions, and decision/package counters in one read-only transaction, then uses the shared policy evaluator and report renderer. It requires `verify:read` (or admin scope) and matching tenant, product, or release grants for human actors; projections above 4096 combined detail rows and policy identifiers, or oversized selected text fields, fail closed rather than truncate evidence. Explicit policy-evaluation commands still persist their own evaluation and audit records. PostgreSQL is required for local evaluation; historical report adapters are test-only.

PostgreSQL-profile customer-package reads and security-review package reports use a focused package-access command. It locks one tenant-owned package row, resolves its current product/release ownership, checks `package:read` and human resource grants, and checks expiry after acquiring the lock. The access count and `customer_package.accessed` audit entry commit atomically; report rendering does not persist a separate report record. Stored manifests are limited to 8 MiB before transfer, identifiers to 1 KiB, titles to 4 KiB, and state strings to 64 bytes. Security-review reports preserve the frozen manifest's evidence-ID order and reject malformed, duplicate, or more than 4096 IDs before recording access. The remaining compatibility download path also reads the current durable package counter rather than trusting its cached copy. Local-memory access uses the same orchestration through its explicit compatibility transaction adapter.

CRA readiness HTML generation uses the bounded control-coverage query with the requesting actor's real grants. The focused HTML-report command escapes the result and limitations, limits the generated body to 4 MiB, hashes its exact bytes, and commits the persisted report with its `html_report.generated` audit entry in one unit of work. This GET route retains its documented report-persistence side effect; it is not a read-only query. Product and optional release ownership are rechecked at insertion after the committed query view. HTTP responses retain the existing JSON field names. Local-memory generation shares the same renderer and orchestration through explicit compatibility ports. These reports organize readiness evidence, not legal compliance conclusions.

PostgreSQL-profile custom-template creation and rendering use focused template commands. Rendering reads and share-locks one tenant-owned definition, then commits the materialized output and audit entry in the same transaction. Stored template metadata, field names, and text have an 8 MiB combined read budget; oversized or malformed definitions fail closed before rendering. Human actors require a tenant-wide `report:read` grant, not just a product or release grant. Template text is inert: output selects only `subject_type`, `subject_id`, and `generated_at` when named in `allowed_fields`. Other field names add no output, and subject labels do not dereference resources or prove their existence. JSON fields, normalized-JSON hashing, and idempotent HTTP response replay remain compatible. Local-memory mode delegates to the same command orchestration.

PostgreSQL-profile evidence-bundle imports use a focused command and native durable HTTP execution that atomically insert a target-tenant receipt, audit entry, and successful replay response. Every retry checks current tenant-wide `bundle:write` authority and locks only target-tenant identity after the shared writer fence; replay does not rehash the manifest or allocate receipt clocks/IDs. The handler needs no Ledger cloning/replay/refresh, evidence projection, signing provider, source-resource lookup, or projection cache. Source labels never grant target-tenant access. Local-memory mode has explicit transaction and replay-guard adapters and remains nondurable. An accepted receipt is not signature verification or evidence ingestion; see the [import receipt and hash compatibility limits](reference/evidence-format-compatibility.md#portable-evidence-bundle-import-receipts). Runtime startup retirement remains EVY-905 work.

The release-bundle snapshot adapter reads current tenant-owned release metadata, evidence IDs, audit head, and retention-observation proofs in one read-only PostgreSQL repeatable-read transaction. It rejects more than 4096 combined evidence IDs and retention policies, more than 4096 total verification checks and limitation strings, or more than 8 MiB of selected retention metadata, without truncating manifest facts. Identifiers are limited to 1 KiB, release versions and policy names to 4 KiB, and state/provider/mode labels to 64 bytes. Raw evidence, signing material, object paths, and provider bucket names are not selected. A shared verification-context renderer preserves existing proof fields and marks expired observations stale.

PostgreSQL-profile release-bundle creation now uses that snapshot reader and a focused command, without Ledger, a projection refresh, or a local cache. The signing adapter selects one tenant's highest-version active local Ed25519 key (ID ascending breaks ties), bounds its fields and private material, and signs the existing normalized manifest hash. Private bytes are cleared and never cross its port. The write transaction share-locks the release's current tenant-owned parent, rechecks `bundle:write` grants, and share-locks the signing key's public lifecycle fields. It rejects revoked, compromised, not-yet-valid, expired, or mismatched keys and verifies the staged signature before atomically inserting the signature, bundle, signature-linked audit entry, and `sign_bundle` job. The manifest is the earlier committed snapshot, not a claim that no later release facts exist. Existing response fields and idempotent replay are preserved; local-memory mode uses explicit adapters to the same orchestration. This remains the existing local Ed25519 package-signature path, not a new external-provider custody or encryption claim. Other package generation and runtime Ledger retirement remain EVY-905 work.

Evidence-bundle export (`POST /v1/evidence-bundles`) uses focused commands and native durable HTTP execution in the PostgreSQL profile. Its read-only repeatable-read snapshot selects evidence IDs and validated tenant-owned product/project/release/build/deployment coordinates, the indexed audit head, and public object-lock proof metadata, never raw evidence payloads or provider locations. The same 4096 combined evidence/proof-row and 8 MiB proof-metadata limits apply. Automatic selection omits only authorization denials; explicit unauthorized IDs and inconsistent stored parents fail closed. A release-scoped export requires a matching release-root grant as well as authorization for selected evidence. The shared writer fence precedes current tenant/selected-parent share locks. Fresh persistence requires the resolved coordinates to match the snapshot and validates the staged signature against current key lifecycle, then atomically commits signature, bundle, signature-linked caller audit and replay, with no worker job. Completed replay checks current authority for the original saved IDs inside that transaction, without a new snapshot, metadata reads, signing-key reads, hashing or signing. It cannot substitute a newly filtered selection when grants change. The bundle describes its earlier committed view, and replay is not a current signature-verification claim. Explicit local-memory ports check the actual response selection before disclosure but remain nondurable. See [export replay and limits](api.md#evidence-bundle-export). Neither path proves evidence completeness, external key custody, legal compliance or complete provider WORM enforcement. Remaining runtime startup retirement is EVY-905 work.

PostgreSQL-profile custom policy creation/evaluation uses Risk-owned commands,
bounded database readers, and direct durable HTTP dispatch. Creation checks
tenant-wide policy-write permission and relies on the tenant/name/version unique
constraint. Evaluation resolves current policy/release ownership before loading
one definition and at most 19 evidence-presence facts under the transaction's
tenant projection fence. Evidence payloads and evaluation history are not read.
The shared presence-only rule evaluator preserves existing explanations and
arbitrary nonblank severity labels; versioned DTO mappers preserve the existing
normalized-JSON hash input. Policy/evaluation, audit, and replay completion commit
together. Snapshot import is insert-or-compare, never an update of historical
policy inputs or evaluation results. Other production command paths and startup
Ledger retirement remain EVY-905 work. See [custom policies](api.md#custom-policies)
for authorization, limits, and non-claims.

Built-in policy evaluation (`POST /v1/policies/evaluate`) uses a focused Risk
command and a dedicated transaction-scoped readiness-reader port. The existing
readiness SQL projection executes in the command transaction under its tenant
projection fence, without a second snapshot transaction or Ledger refresh.
Current release/product ownership and grants are checked before facts and
before saved-response replay. Evaluation, audit, and replay completion commit
atomically. Existing verification-reader interfaces remain unchanged; the
readiness port does not replace or wrap them. Historical evaluation import is
insert-or-compare, never an update of result or checks. The shared pure evaluator
retains the existing 13 checks and policy-set version. See
[built-in policy evaluation](api.md#built-in-policy-evaluation) for limits and
compatibility; other production paths and startup Ledger retirement remain
EVY-905 work.

SBOM diff creation (`POST /v1/sbom-diffs`) uses a focused Evidence command with
identifier-only parent resolution before bounded component reads. Both inputs,
dependency records, audit, and replay completion share the active command
transaction and tenant projection fence, including pending inputs in compound
commands. The existing deterministic diff evaluator is reused. Historical diff
and dependency imports compare existing records instead of updating them. See
[stored SBOM diffs](api.md#stored-sbom-diffs) for limits and compatibility.

OpenAPI diff creation (`POST /v1/openapi-diffs`) also uses a focused Evidence
command. Current contract/source coordinates and requested-release grants are
checked before bounded operation reads or saved-response replay. It reuses the
existing pure comparison rules while retaining attachment to any release of
the common product. Reads, diff insertion, audit, and replay completion join the
active transaction; snapshot import cannot rewrite the historical diff. See
[stored OpenAPI contract diffs](api.md#stored-openapi-contract-diffs) for limits
and compatibility.

OpenAPI contract ingestion (`POST /v1/openapi-contracts`) now binds a focused
Evidence command in the PostgreSQL composition root. Its flat transaction ports
reuse generic evidence preparation without constructing a Ledger or unrelated
parsers. Identifier-only parent resolution and current grants precede the
stateless, digest/size-bound parser and object staging. Contract, evidence,
audit, payload metadata, outbox, and durable replay completion join one active
transaction, including pending parents in compound commands. Replay checks
current authorization without parsing or staging; retained body-only native
receipts also require exact original coordinates. Parser-owned stored
projections, inline operation data, and worker finalization semantics are
preserved. See [OpenAPI contract ingestion](api.md#openapi-contract-ingestion)
for input limits and compatibility.

CycloneDX and SPDX SBOM ingestion (`POST /v1/sboms` and
`POST /v1/sboms/spdx`) likewise bind one focused Evidence command in the
PostgreSQL composition root. Identifier-only release ownership and current
optional-artifact grants are checked before the stateless shared normalization
pipeline opens source bytes or stages objects. Its reader enforces the declared
size before parsing and verifies the source digest. Flat transaction ports
reuse generic evidence preparation; SBOM, evidence, audit, payload lifecycle,
outbox, and replay completion join the same active transaction. Parser-owned
stored components, inline responses, and body-only native receipt compatibility
are preserved without Ledger reloads. See [SBOM ingestion](api.md#sbom-ingestion)
for limits and compatibility.

Vulnerability-scan ingestion (`POST /v1/vulnerability-scans`) binds a focused
Evidence command with flat transaction ports in the PostgreSQL composition
root. Scope-only authorization precedes the stateless, bounded release-ID
probe; current tenant-owned release parents and human grants precede full
findings normalization and staging. The same checked scanner adapters retain
their parser identities and public finding fields. Evidence, scan, audit,
payload metadata, outbox, and replay completion commit together without Ledger
reloads. Replay probes the incoming scope but does not normalize findings or
stage objects. See [vulnerability scan ingestion](api.md#vulnerability-scan-ingestion)
for limits, worker-owned projections, and compatibility.

OpenVEX and CycloneDX VEX ingestion (`POST /v1/vex` and
`POST /v1/vex/cyclonedx`) bind a focused Evidence command in PostgreSQL mode.
Flat transaction ports reuse evidence preparation and accept no decision
repository. Current tenant-owned release parents and optional-artifact grants
precede stateless, digest/size-bound parsing and object staging. VEX document,
accepted import report, evidence, audit, payload metadata, outbox, and durable
replay completion join the same active transaction, including pending parents
in compound commands. The upload always retains normalized VEX metadata and a
bounded versioned decision request; only the post-commit worker writes mapped
decisions. Replay checks current authorization without parsing, staging, or
Ledger reloads, and retained body-only native receipts require exact original
coordinates. See [VEX ingestion](api.md#vex-ingestion) for limits and
compatibility.

VEX previews bind a focused Evidence query with an explicit read-only Risk
mapping port in PostgreSQL mode. One repeatable-read snapshot resolves current
release ownership and artifact associations, authorizes grants before parsing,
and selects only relevant finding coordinates and active-decision presence.
Private decision notes, evidence metadata, and object payloads are not loaded.
The reader caps release scans and candidate findings at 4096 each and combined
candidate text at 8 MiB; malformed or oversized projections fail closed without
partial results. Shared Risk matching rules retain advisory counts, ambiguity,
duplicates, and original statement indexes. Snapshot changes become visible on
the next request, with no Ledger reload, persistence, jobs, or replay records.
See [VEX import preview](api.md#3-upload-sbom-and-vulnerability-evidence) for
grant and compatibility limits. Other ingestion paths and startup Ledger
retirement remain EVY-905 work.

Security-scan and manual-document uploads now bind a focused Evidence command
in PostgreSQL mode. Its flat transaction exposes parent/artifact validation,
security:write authorization, evidence/payload/audit/outbox insertion, and only
the two accepted-document writes; it cannot reach policy, decision, or incident
repositories. Current parents and grants are checked before the shared reduced
scan parser or object staging. Evidence, document, payload metadata, finalizer,
two audits, and safe replay completion share the active transaction, including
pending parents in compound commands. Replay uses current grants without
parsing, staging, or Ledger reloads. Central replay privacy continues to omit
payload references; raw document bytes remain outside responses. Local-memory
mode retains its explicit compatibility command and shares DTO conversion.
See [security-document uploads](api.md#security-document-uploads) for bounds,
reduced-format compatibility, and secret-scan flag limitations.

Human incident creation, timeline append, and remediation-task creation bind
one focused Operations service in PostgreSQL mode. Its flat port exposes only
identifier-based current ownership reads, incident-scope authorization, the
three append operations, and audit insertion. The adapter selects bounded
tenant-and-ID coordinates rather than incident text, evidence metadata, or
release documents. The worker projection fence precedes row locks; coherent
subject and parent share locks survive through command/replay commit. Each
reference is independently granted, including tenant-only evidence and
deliberately separate incident/remediation release scopes. Record, principal
audit, and durable replay completion join one active transaction, including
pending incidents in compound commands. Live tests forbid Ledger refreshes,
check ownership locks/reparenting, and inject record/audit/completion/commit
failures. Local evaluation uses PostgreSQL. See
[incident commands](api.md#incident-commands) for input and compatibility
limits.

Signed incident webhook receivers and ingress also bind focused Operations
ports in PostgreSQL mode. An unauthenticated primary-key lookup exposes only
the receiver's tenant locator; the active transaction then re-reads and locks
the receiver by tenant and ID before verifying its current Ed25519 key.
The tenant projection fence precedes ownership row locks. Current incident
parents and incident-scoped evidence authority are checked on acceptance and
replay. Natural replay uses the unique tenant/receiver/event key and a bounded
timeline point read, not a full event inventory. Event, timeline, and webhook
audit append atomically, including pending parents in compound commands.
Concurrent retry, restart, receiver revocation/key replacement, evidence
reparenting, large unrelated documents, and insertion/audit/commit failures
have narrow live tests. Human receiver creation additionally joins durable
HTTP idempotency completion. The pure signing protocol is also used by test
fixtures, not a supported memory API. See [signed incident webhooks](api.md#signed-incident-webhooks)
for protocol and migration limits. Remaining aggregate retirement is EVY-906 work.

## Bounded-context transition

Custom report definition creation and materialization now use Package-owned
commands and native durable HTTP execution. Read-only replay guards require
current tenant-wide report permission, tenant existence and optional template
ownership, not definition metadata or subject lookups. The shared writer fence
precedes locks held through record/audit/replay commit. Fresh rendering still
reads one bounded current definition and selects only inert metadata labels;
template text is never executed. Flat PostgreSQL and explicit memory repository
capabilities provide the scope locks; the legacy Service bridge is not a native
HTTP replay capability. Schemas and normalized string-output hashes remain
unchanged; new durable timestamps use UTC microseconds. Other wrappers and
startup Ledger retirement remain EVY-905 work. See
[custom report templates](api.md#custom-report-templates) for limits and non-claims.

Generic evidence creation now has standalone Evidence-owned
`EvidenceCreationCommands`, with a two-check reader and flat transaction ports
for scope/artifact validation, authorization, payload recording, audit, outbox
and insertion. It needs no parser, document reader, lifecycle sanitizer or
projection refresher. The compatibility Evidence service delegates creation
and parser preparation to the same implementation. Recognized parent and
subject references are revalidated and authorized inside the transaction before
any writes; empty audit receipts fail closed. New evidence hashes use UTC
microsecond timestamps, matching PostgreSQL persistence precision without
rehashing historical records. Nested JSON-shaped source identity and metadata
are copied without changing numeric types or empty containers; non-JSON or
cyclic creation metadata is rejected before hashing. Existing response and
schema fields remain unchanged. PostgreSQL-profile `POST /v1/evidence` now binds
this command directly in the composition root. Its bounded scope resolver
selects identifiers only, rejects coordinates above 1 KiB, and share-locks
tenant/product/project/release/build/deployment parents before authorization
and insertion. Initial checks join an enclosing idempotency transaction, so
pending build and artifact associations are visible without Ledger publication.
Human creation requires current `evidence:write` grants; artifact reuse checks
current tenant associations and any supplied digest, while ID-only references
remain supported. Evidence, audit, staged-payload metadata and finalization jobs
commit together. Live tests cover rollback at each write boundary, parent row
locks, pending associations, durable canonical hashes and HTTP restart replay.
Native HTTP now uses a read-only current ownership/grant guard before
reservation and completed replay, without Ledger cloning or refresh. Artifact
identity is replay authority; fresh creation separately checks supported
declared digests and staged payloads. Guard locks survive through the outer
evidence/audit/replay commit without generating clocks, IDs or hashes. Transport
and replay retain exact numeric metadata, while the existing float64 hash
normalization profile and historical hashes remain unchanged. Replay retains
the established private `payload_ref` omission. Local memory keeps explicit
nondurable storage and current-map guards. Other wrappers and broad startup
state loading remain EVY-905 migration work. See
[generic evidence creation](api.md#generic-evidence-creation) for input bounds,
authorization, compatibility and metadata-only limitations.

PostgreSQL-profile external transparency-checkpoint creation uses a focused
command and reads only the tenant-owned batch root, not Ledger state or batch
leaves/signatures. The selected root stays locked until checkpoint and audit
commit; replay does not add duplicate records. Provider/URL metadata remains an
operator assertion with state `recorded`, not proof of external anchoring.
Local memory shares the normalized-JSON hash policy. See
[recorded external checkpoints](reference/verification-results.md#recorded-external-transparency-checkpoints)
for authorization, bounds and explicit non-claims.

PostgreSQL-profile `POST /v1/verify` receives one focused subject-verification
port from `BuildAPIReadServices`. A closed application dispatcher binds all
nine supported subject types to their focused commands, with no dynamic service
lookup or Ledger fallback for unknown types or command failures. Subject-specific
authorization and transaction ownership remain in those commands. Explicit
local-memory mode keeps its compatibility path. Other production command paths
and startup Ledger retirement remain EVY-905 work. See
[generic subject dispatch](reference/verification-results.md#generic-subject-dispatch).

Full-chain verification (`GET /v1/audit-chain/verify` and `POST /v1/verify`
with `audit_chain`) uses a focused command in the PostgreSQL profile.
Tenant-wide `verify:read` authorization precedes audit content reads. The
transaction holds the existing exclusive projection and audit fences, in writer
lock order, to keep the chain count/head and paged contents stable until receipt,
audit and outbox effects commit. This temporarily serializes that tenant's audit
appends and worker projection changes, not all tenants. The reader selects at
most 128 audit records per page and only referenced signed-object hashes,
signatures and public key lifecycle fields. It does not load unrelated tenant
resources or private keys. The inspector retains existing per-entry checks and
both canonical schema versions, including v1 timestamp reconstruction. See the
[full-chain verification boundary](reference/verification-results.md#full-audit-chain-verification)
for resource limits, HTTP compatibility and the distinction from signed
checkpoint/external anchoring assurance. Both signed-checkpoint subjects now
have focused commands; broad startup Ledger retirement remains EVY-905 work.

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

Both DSSE verification entry points (`POST /v1/build-attestations/{id}/verify-signature`
and build-attestation requests to `POST /v1/verify`) use a focused command in the
PostgreSQL profile, whose DSSE inspection and receipt effects need no Ledger
reads or publication. It checks `verify:read`
and tenant/product/project/release grants before loading payload metadata. The
transaction share-locks current tenant-owned attestation/evidence coordinates,
build outputs, referenced artifacts and release links, finalized payload metadata
and active root policies through receipt persistence. Expected subjects derive
from registered artifact digests and release links, not parsed attestation claims
or opaque digest labels on links. Each root's complete immutable policy is
evaluated independently by the shared offline cryptographic adapter; signature
trust cannot borrow another root's builder or claim policy. No eligible root
produces `not_verified`, not an optimistic pass. Receipt, audit and verification
job commit together; successful POST replay adds no duplicate effects and failed
POST verification rolls back its enclosing transaction. Public profiles, schemas
and response fields remain compatible. See the [DSSE verification limits and
compatibility boundary](reference/evidence-format-compatibility.md#dsse-and-in-toto-json).
Local-memory inspection shares the profile and root-policy evaluation but retains
its explicit compatibility storage/transaction path. Other verification subjects
and broad startup Ledger retirement remain EVY-905 work.

PostgreSQL-profile artifact-signature creation uses a focused command with
transaction-scoped artifact grants, bounded digest reads and the shared
Ledger-independent payload staging boundary. Signature, staged lifecycle,
finalization job and audit persist atomically; creation records evidence without
assigning cryptographic trust. See
[artifact signature recording](reference/verification-results.md#artifact-signature-recording)
for authorization, input bounds and orphan-reconciliation limits.

Artifact-signature requests to `POST /v1/verify` use a focused metadata-only
command in the PostgreSQL profile. The tenant, selected artifact and signature
remain share-locked through receipt, audit and outbox insertion. After
`verify:read` and human tenant-grant authorization, the reader selects bounded
digest labels and only algorithm/signature presence flags; it does not load raw
signature text, payload references, bundles, trust roots or signing keys. The
shared core policy preserves the `artifact-signature-metadata.v1` profile and
its `limited` result for matching metadata, never a cryptographic pass. See the
[metadata assessment boundary](reference/verification-results.md#artifact-signature-metadata-assessment).

PostgreSQL-profile `POST /v1/merkle-batches` uses bounded sequence/hash reads
and transactional local signing without Ledger state. Tenant-wide `keys:admin`
authorization precedes reads; tenant, projection and audit fences stabilize the
range and signing-key selection. An initial local key, signature, batch and
audit commit atomically, with no outbox job. Creation signs stored hashes,
not canonical audit contents or external transparency proof. See
[Merkle batch creation](reference/verification-results.md#merkle-batch-creation)
for bounds, key lifecycle and compatibility limits.

PostgreSQL-profile backup-manifest generation uses a focused command with
tenant-wide `admin` authorization. One SQL snapshot streams the fixed,
credential-excluding tenant resource profile into a bounded digest, rather than
constructing the whole-instance Ledger snapshot. Fresh audit consistency
checks, a v2 manifest and its audit append share one transaction; failed
observations are preserved, and replay does not rehash state. Historical and
local-memory v1 hashes retain their distinct scope. See
[backup generation semantics](reference/verification-results.md#tenant-scoped-backup-manifest-generation)
for exact bounds, exclusions, encoding and non-claims.

Merkle-batch requests to `POST /v1/verify` and
`GET /v1/merkle-batches/{id}/verify` use a focused command in the PostgreSQL
profile. Tenant-wide `verify:read` authorization precedes reading the selected
batch, its covered sequence hashes and referenced public signing material.
These rows and the tenant stay share-locked through atomic receipt, audit and
outbox insertion. No raw audit metadata, canonical entry bodies or private key
ciphertext is loaded. The core inspector is shared with explicit local-memory
mode. It preserves the three-check `merkle-checkpoint.v1` profile and historical
key validity. This verifies recorded hashes, not canonical audit contents or
external anchoring; `audit_chain_checkpoint` remains a distinct profile. See
[Merkle verification bounds](reference/verification-results.md#merkle-batch-verification).

The PostgreSQL-profile `audit_chain_checkpoint` command composes the focused
full-chain and Merkle readers in one transaction, without Ledger state. It
checks all canonical entries and binds the selected checkpoint hashes to those
same inspected pages. Tenant-wide authorization precedes content reads; the
audit writer fence and shared rows keep the chain, batch and public signing
material stable through atomic receipt/audit/outbox persistence. It preserves
the distinct `audit-chain-merkle-checkpoint.v1` profile and early failed-range
contract. It proves neither external publication nor third-party log inclusion.
See [signed checkpoint verification](reference/verification-results.md#signed-merkle-audit-chain-checkpoint-verification).

The PostgreSQL-profile `audit_chain_release_manifest` command similarly
composes full-chain and bounded release-bundle readers in one transaction.
Manifest hashing and signature policy reuse the ordinary bundle inspector;
the signed sequence/head is matched against the same canonical chain pages.
Human actors need a tenant-wide verification grant because the receipt includes
all tenant entries, rather than only the release's evidence. Release-only grants
remain sufficient for ordinary resource-scoped bundle signature verification,
not this checkpoint profile. Receipt/audit/outbox effects commit atomically;
oversized projections fail closed. See
[release-manifest checkpoint verification](reference/verification-results.md#release-manifest-audit-chain-checkpoint-verification)
for compatibility and assurance limits.

Cosign verification (`POST /v1/artifact-signatures/{id}/verify-cosign`) in the
PostgreSQL profile uses focused transaction-scoped signature/artifact/payload
reads and a bounded object reader, not Ledger state. `verify:read` is required;
human actors also need a tenant grant because artifacts have no product/release
authorization coordinate. The selected tenant, artifact, signature, optional
container image and payload lifecycle rows remain share-locked through receipt
persistence. The verifier receives only finalized digest-bound bundle bytes and
the operator-configured offline trust policy. The Cosign receipt, generic result
and audit entry commit atomically, with no worker job. Receipt library version,
trust-root version and mode persist in their existing migration-backed columns.
Successful POST replay adds no effects; failed POST verification rolls back its
enclosing transaction. See [Cosign limits and compatibility](reference/evidence-format-compatibility.md#cosign-offline-sigstore-bundles).
Startup and outer compatibility HTTP/idempotency state still require the
remaining EVY-905 migration; this does not claim full Ledger retirement.

Signing-provider registration and DSSE trust-root creation in the PostgreSQL
profile use focused trust-configuration commands with tenant-wide `keys:admin`
authorization. Each metadata row and its audit entry commit in the same unit of
work, including the HTTP replay record; there is no Ledger map publication or
worker job. DSSE roots retain the existing tenant/key-ID uniqueness constraint,
Ed25519 public-key format, supported SLSA predicate, builder allowlist and required
claims. Policy lists are copied and sorted, limited to 4096 combined entries,
1 MiB of combined list text and 4 KiB per entry before copying. Names and provider
key references are limited to 4 KiB; DSSE key IDs to 1 KiB. Inputs must be valid
UTF-8 without NUL bytes. Existing explicit credential-marker rejection now
applies to every provider reference, not only native PKCS#11 references; operators
must still supply only non-secret key locators. HTTP `null` fields are rejected
according to the existing non-nullable schemas. Public response and storage
schemas remain unchanged, and local-memory mode shares the orchestration through
its explicit adapter. Registration makes no provider call and does not prove key
custody, encryption, provider availability, builder authenticity, or legal
compliance. Historical registered rows are not rewritten or newly verified.

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
Product, project and release HTTP creation now use native durable execution.
Their shared read-only guard port locks the current tenant and, for children,
the tenant-owned product through the outer replay transaction after the
common writer fence. It projects no name, slug, version or existing child,
performs no uniqueness query and allocates no clock/ID. Current tenant/product
authority is rechecked on every retry and inside native writes. Input bounds
precede trimming; the existing trimmed product-slug limit is preserved.
Local maps and the explicit memory transaction adapter retain nondurable
semantics; neither supplies PostgreSQL lock guarantees. Live tests cover all
three native routes, exact historical numbers, large unrelated metadata,
four failure/recovery stages each, current grants, parent lock lifetimes,
concurrent one-time creation and cancellation. Broader API startup and other
unmigrated wrappers remain EVY-905 work. See
[catalog creation](api.md#1-create-product-project-and-release).

The release context has standalone product-, project-, and release-create
commands with narrow tenant-scoped repositories and audit transactions.
Durable product creation uses a boolean slug-existence port; it never loads an
existing product's name, slug, or creation metadata to detect a duplicate.
The transaction repeats tenant-wide authorization before its first catalog
read. PostgreSQL acquires the worker-projection fence before locking the tenant
row, serializing absent slugs; the unique constraint remains the durable
backstop. New product IDs and tenant IDs are bounded to 1024 UTF-8 bytes,
names to 64 KiB, and slugs to 1024 bytes; write fields must be NUL-free UTF-8.
Creation times use microsecond-precision UTC. Live tests cover pending-slug
visibility, rollback, durable replay, wrong-level and removed grants, invalid
storage text, independent slugs across tenants, and concurrent creation with
one product/audit pair. Shared audit translation no longer exposes full catalog
reads or project/release insert methods.
Project and release creation check the parent product both before and inside
the write transaction; release versions remain unique per product. Both durable
creation builders take only a unit-of-work factory. Their initial reads use the
enclosing transaction when present, so pending products are visible;
both reads use a coordinate-only port containing product ID, tenant ID, and
slug, preserving the existing slug-drift check without loading product names or
timestamps. PostgreSQL acquires the worker-projection fence before a share lock
on the tenant-filtered product. IDs are bounded at 1024 UTF-8 bytes and stored
slugs at 64 KiB; oversized stored coordinates return conflict, not truncation.
Release creation checks version uniqueness through a boolean existence port,
without loading existing release lifecycle metadata. PostgreSQL acquires the
projection fence before the product lock that serializes absent version
identities. New project names and release versions must be NUL-free UTF-8 within
64 KiB. Durable creation times use microsecond-precision UTC. Live tests cover pending-parent visibility,
compound rollback, single-execution replay, tenant/grant denial, and bounds.
Concurrent release-create tests prove one release/audit pair for a product's
version, conflicts for losing requests, and independent versions across products.
These database adapters and the idempotency executor have been exercised together
without constructing a Ledger. Production product-, project-, and release-create HTTP now
use creation-only focused service interfaces. Live HTTP tests use an empty
Ledger and durable transaction factory to verify fresh-instance replay, point
reads, build/evidence/source-repository/deployment consumers, tenant and grant
rejection, and creation/audit failure rollback. Local-memory mode keeps its
explicit compatibility bindings. Product HTTP tests additionally verify exact
create/read/list metadata and tenant-filtered lists without publishing products
into Ledger maps. This does not retire production startup's Ledger construction
or its remaining full-state command-view reloads; those migrations are still
required before the composition-root work is complete.
Standalone release freeze and approval commands read current tenant-owned
release state and product coordinates through the active unit of work, not a
pool reader. The factory-only builder uses bounded SQL fields and acquires the
worker-projection fence before the release row lock. Stored release versions
and product slugs are limited to 64 KiB; IDs to 1024 UTF-8 bytes; overflow fails
closed. The write transaction rechecks parent ownership, immutable coordinates,
current authorization, expected revision, and lifecycle state before appending
the audit entry atomically. UTC transition times use microsecond precision.
Live tests cover a pending product/release, freeze plus approval in one outer
transaction, compound rollback and replay, wrong tenant/grants, stored-field
bounds, and competing freezes with one state/audit winner. Production freeze
and approval HTTP use native durable execution through a transition-only interface. Fresh
server instances with an empty Ledger verify the complete response metadata,
durable replay and point reads, safe current-revision conflicts, tenant and
grant denial, and rollback of state changes when update or audit insertion
fails. The read-only replay guard locks current tenant/release/product ownership
without lifecycle state, revision, version, slug, clocks or IDs; these locks join
the outer state/audit/replay transaction, with no Ledger cloning or refresh.
Local memory keeps its explicit nondurable binding. Conditional
action fingerprints include the validated strong `If-Match` revision; changing
it under the same key conflicts rather than replaying a different intent.
Standalone release-candidate promotion/rejection now has a factory-only
transaction builder. It reads one locked candidate plus the current tenant-owned
release/product coordinate in a single SQL statement, without loading release
versions or product names. The worker-projection fence precedes candidate and
parent locks. Authorization runs against those locked coordinates before a
revision conflict can disclose the current revision. Snapshot fields remain
unchanged; the transition time/revision and audit append commit together.
Stored candidate names are bounded at 64 KiB, IDs/schema identifiers at 1024
bytes, state at 32 bytes, hash at 128 bytes, and the JSON snapshot at 1 MiB;
oversized, non-object, or incorrectly typed snapshot references fail closed
with conflict rather than truncation. Live tests cover pending candidate
visibility, compound rollback/replay, tenant/grant denial, write/audit failures,
and competing transitions with one state/audit winner. Production candidate
promotion/rejection HTTP uses native durable execution and a transition-only dependency. Fresh-server
tests with empty Ledger candidate maps verify immutable snapshot DTOs,
durable point/list reads, conditional replay, safe revision metadata, and
storage/audit rollback. Its ownership-only guard holds current tenant/candidate/
release/product share locks through the outer transaction without loading the
candidate document, lifecycle/revision, private metadata, clocks or IDs.
Completed delivery preserves the original response; fresh transitions retain
revision/state validation. Raw budgets precede trimming, strict body/origin rules
apply in both profiles, and the canonical revision-plus-body fingerprint is
unchanged. Live tests cover all four update/audit/replay/outer-commit failure
stages, concurrent once-only effects, cancellation and lock lifetime. Local
memory remains nondurable; startup and other wrappers still need migration.
Standalone candidate creation now has a factory-only transaction builder.
It reads the current tenant-owned release/product coordinates without release
version or product metadata, then validates all seven reference groups through
one identifier-only SQL existence result. Builds must have matching current
project/release products; SBOM, scan, VEX, and OpenAPI references must match
their source evidence's tenant, release, and type. OpenAPI product coordinates
must also match the release. Human artifact reuse checks current authorized
build/evidence associations in that same unit of work. No foreign-context
payloads or Ledger maps participate. Candidate IDs/references are bounded at
1024 UTF-8 bytes, names at 64 KiB, and the combined reference work at 4096 IDs
and 64 KiB of identifier bytes. Inputs are trimmed, NUL-free UTF-8; reference
sorting preserves duplicates. The existing versioned normalized-JSON hash
profile is retained. Snapshot creation and audit append commit together, with
microsecond-precision UTC times. Live tests verify pending parents and every
reference type, compound rollback/replay, foreign/missing/wrong-release
references, removed grants, artifact reuse, and insertion/audit failures.
Production candidate creation uses a creation-only dependency and native durable
HTTP execution, without Ledger cloning, replay or refresh. Its read-only guard
rechecks current parents, all seven reference groups and grants without existing
candidate documents, private metadata or snapshot hashing. The identifier-only
SQL result now also holds selected references and their source-evidence parents
under share locks through the outer transaction, after the common writer fence.
Snapshot, principal audit and replay commit atomically. Live tests cover exact
historical JSON, preserved duplicates/hash profile, current grants, ownership
locks and four-stage rollback/recovery. Raw budgets precede normalization; local
memory keeps explicit nondurable storage/replay and matching origin rules.
Startup composition and other wrappers remain migration
work; this is not completed production Ledger retirement.
The transactional catalog repositories now expose tenant-filtered project and
release point reads that verify the parent product in the same read and lock
the selected rows. Standalone artifact registration now looks up digests in
current tenant-scoped rows, authorizes reuse of an existing artifact, and
recovers from concurrent digest inserts without a duplicate audit entry. Its
standalone durable command emits microsecond-precision UTC creation times and
normalizes stored timestamps to UTC, so fresh-instance reuse returns identical
immutable metadata regardless of the database/session timezone. Duplicate
authorization now uses the current transaction's identity-only artifact-grant
reader; pending build/evidence associations are visible without a pool read or
Ledger links. A live regression proves pending grant reuse, compound rollback
and single-execution replay. Durable duplicate registration separates bounded
identity lookup from authorization and only then loads private metadata. The
identity and metadata queries are tenant-filtered and share-locked; they acquire
the worker-projection fence before the tenant lock that serializes absent digest
identities. IDs are bounded at 1024 UTF-8 bytes, names and media types at 64 KiB,
and SHA-256 digests at 71 bytes. Oversized stored fields return conflict, never
truncated metadata; new records reject oversized, invalid UTF-8, or NUL-bearing
fields. Unit tests verify authorization precedes metadata access, and live tests
cover denied access, oversized stored fields, and immutable authorized reuse.
Production artifact-registration HTTP uses a registration-only dependency and
native durable execution, not Ledger cloning, replay or refresh. Its read-only
guard locks the tenant and existing digest identity and checks current grants
without private metadata, clocks or IDs. Fresh execution still reads bounded
immutable metadata on natural-key reuse. Record, caller audit and replay are
atomic. Live checks cover restart, current grants, exact integer sizes, oversized
private metadata and record/audit/replay/outer-commit recovery. Explicit local
memory retains nondurable replay with the same raw input and origin rules. A
focused build-create command reads only project tenant/product ownership,
release tenant/product/version coordinates, and output artifact tenant/digest
identity, then rechecks them under share locks in the write transaction. Its
PostgreSQL adapter acquires the worker-projection fence before those relational
locks. IDs are bounded at 1024 UTF-8 bytes, stored release versions at 64 KiB,
and stored SHA-256 digests at 71 bytes; oversized stored coordinates return
conflict, never truncated values. Product/project names, artifact names/media
types and release lifecycle metadata do not enter this command. Human output
grants use the existing current tenant-valid evidence/build association
predicates through an identity-only projection, not Ledger artifact links or
artifact metadata. Parent and output-artifact authorization is repeated against
the transaction's current coordinates before any writes. Initial reads reuse
the active idempotency transaction, so pending parents and output associations
are visible without a separate pool connection. Build and audit effects are
atomic with durable HTTP replay when called through the idempotency executor.
CI-provided source metadata
remains unverified metadata, including a forced `oidc_verified: false` that
submitted metadata cannot override. Live regression tests in
`internal/platform/wiring/build_identity_commands_test.go` exercise large
unrelated metadata, tenant/grant isolation, rollback and replay. The PostgreSQL
HTTP profile now binds this focused command. Tests in
`internal/platform/wiring/build_creation_commands_test.go` cover pending parent
visibility, build and audit failures, and the HTTP build-to-evidence-to-attestation
flow without cached parents or builds. The explicit local-memory profile keeps
the compatibility command binding. Build creation now uses native HTTP durable
execution rather than the outer Ledger replay/refresh envelope. Its read-only
`BuildCreationGuardReader` returns locked parent and artifact ownership only;
every retry rechecks current grants without rereading versions, digests or build
metadata. The common writer fence precedes tenant/parent/artifact share locks,
which join the outer replay transaction. Raw input normalization is shared with
the explicit local map guard. Live native HTTP and fence suites cover current
grants, historical exact-number replay, large unrelated metadata, all four
write/replay/commit failure stages, concurrent delivery and cancellation.
Startup aggregate loading and other unmigrated workflows remain EVY-905 work;
this build boundary does not claim that the production Ledger is retired.

Build-attestation upload orchestration now lives in the standalone Release
`BuildAttestationCommands`. Its four-read, fixed-shape transaction port rechecks
the build, parent and output-artifact coordinates before committing evidence,
attestation, audit and parser-job effects. The compatibility Release service
delegates to the same command; it does not duplicate orchestration.

Its HTTP route now uses native durable replay and the application's existing
20 MiB payload limit, with the shared upload concurrency budget. A separate
read-only guard selects bounded build/parent/output-artifact ownership and
current grants only, holding share locks through the outer replay transaction
after the common writer fence. It never reparses or stages a completed upload,
materializes build source identity or rereads historical ingestion records.
Fresh and replayed HTTP responses both omit private payload storage coordinates;
internal records retain them. Current tenant/grant checks, all nine database
failure stages, malformed stored projections, concurrent one-time staging and
cancellation are exercised by the native HTTP/guard/fence suites. Broader
startup and unmigrated workflows remain transitional. See
[attestation upload](api.md#build-attestation-upload) for the exact contract.

The DSSE ingestion parser is independently composable from
`internal/adapters/verification/dsse`, validates the observed bytes/size/digest
within the existing 20 MiB limit, and performs structural parsing only, not
signature verification. Worker-owned replayable uploads retain the parsed
response but persist the accepted projection for worker completion. Its durable
build-snapshot reader joins the build and tenant-valid project/release/product
parents in one statement. Selected identifiers and labels have 1 KiB limits,
optional text fields 64 KiB limits, and source identity and outputs each a
1 MiB JSON limit, all checked before transfer. It rejects overflow and malformed
JSON shapes instead of truncating, selects no parent names, and normalizes times
to UTC. Transaction reads acquire the projection fence before share-locking all
four rows. The Evidence-owned `BuildAttestationEvidenceWriter` now supplies the
fixed-shape ADR 0003 capability: it rechecks parent scope and artifact grants,
validates staged lifecycle identity, and prepares the existing evidence and
parser-provenance fields. It hashes PostgreSQL-precision UTC timestamps before
payload/finalization-job and evidence/audit writes. All ports must share the
caller's active transaction; this writer opens none of its own. It records
structural parsing, not signature trust. The PostgreSQL API now composes the
standalone command and Evidence capability on one unit of work, including
transaction-bound parent/artifact authorization. The ingestion command neither
reads cached builds nor maintains Ledger maps. Initial build, parent and artifact
grant reads also use the active unit of work, including a build created earlier
in the same transaction. The pending-build composition regression verifies the
scoped human grant, compound rollback and replay without a second execution.
Evidence, attestation, staged
payload lifecycle, both audit entries and worker jobs commit atomically with
durable HTTP replay. The existing
`EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS` setting reaches this composition;
inline mode keeps its parsed projection. Local-memory mode retains the explicit
compatibility adapter. Replay retains the existing privacy-filtered response
contract, which omits `payload_ref`. Focused live tests cover write-failure
rollback, tenant/grant denial before staging, canonical hashes, exact finalized
bytes, malformed HTTP bodies and replay through a fresh server with no cached
build. Other production commands and the transitional Ledger-owned HTTP replay
envelope, including its broad cache refresh after commit, remain EVY-905
migration work; this is not complete Ledger retirement.

Container-image registration now has a standalone Release command with a flat
transaction capability for artifact coordinates, current authorization,
repository/digest identity, insertion and audit. The compatibility service
delegates to it. Both a supplied artifact and an existing image's actual
artifact association must be tenant-owned and authorized inside the transaction;
reuse returns the original immutable image without another audit entry. Record
and audit use one timestamp. Its standalone PostgreSQL adapter reads only
artifact identity/digest and current grant associations, including pending rows
in the active unit of work. Image identity lookup returns one bounded record:
identifiers and schema labels are limited to 1 KiB, repository/tag/platform text
to 64 KiB, and SHA-256 digests to 71 bytes. Overflow returns conflict rather than
truncated metadata. New durable records must fit that projection and contain
valid UTF-8 without NUL characters. The adapter takes the worker-projection fence
before relational locks and serializes absent repository/digest reuse with a
tenant row lock. Live regressions cover giant unrelated artifact metadata,
pending grants, compound rollback/replay, audit failure and concurrent reuse.
The PostgreSQL HTTP profile uses native durable execution without Ledger replay
or refresh. Its ownership-only guard reads flat image identity and both supplied
and existing attached artifacts, applying current grants without private image
metadata or digest revalidation. These locks join the outer transaction; fresh
execution retains digest checks and immutable natural-key reuse. Live tests
cover record/audit/replay/outer-commit recovery, concurrent delivery, cancellation
and lock lifetime. Raw input limits precede trimming; encoded repository index
overflow maps to safe validation rather than a server error. Local memory keeps
its explicit nondurable binding. Startup and other command wrappers still need
migration; this does not establish Ledger retirement or multi-writer support.

SSO trust normalization now lives in a stateless Identity application policy,
shared by local compatibility and production callers. It rejects recognized
private/symmetric JOSE members, retains only supported public JWK fields, and
normalizes parsed RSA public certificates without retaining trailing PEM blocks.
It has no Ledger, HTTP, SQL, or provider-client dependency. PostgreSQL provider
registration now binds focused Identity commands with a narrow tenant lock,
atomic provider/audit/replay writes, and current tenant-wide authorization
before reservation or completed replay. It loads no provider inventory and
does not refresh Ledger state. The registration handler now requires the focused
command, with no aggregate fallback. PostgreSQL is required for local evaluation.
Trust rotation also binds focused Identity commands. A tenant-filtered, bounded
provider read holds the current trust version through conditional update; the
update, canonical-hash audit and safe replay receipt commit together. Current
authority, input and provider checks precede reservation/replay. Live tests cover
restart replay, foreign/scoped access, oversized and ill-typed stored metadata,
public SAML PEM preservation, and write/audit/replay/deferred-commit rollback.
Only normalized public certificates and harmless group names get purpose-fixed
replay preservation; generic privacy redaction is unchanged. OIDC discovery
refresh now uses the same focused transaction capability and provider projection.
The composition root supplies the existing hardened network adapter explicitly;
its stateless DTO translation has no Ledger dependency. Read-only replay guards
never fetch metadata. A newly acquired command validates fetched issuer/public
keys, conditionally updates trust and appends its canonical-hash audit in the
same transaction as safe replay completion. Live tests cover current grants,
restart replay without refetching, unavailable providers and all four rollback
stages. Trust rotation, discovery and identity-link handlers also require
focused commands; four methods are removed from the broad transport port.
HTTP fixtures run the actual focused provider creation, trust rotation,
discovery and identity-link commands on their current memory repositories.
Repository-only provider tests reject stale-cache authority. Provider reads
preserve bounded complete metadata with defensive copies; linking checks only
current tenant-owned user/provider coordinates and exact email, not login
eligibility. Read-only guards cannot write, audit, hash, fetch, use clocks or
generate IDs. Optional discovery and fixed clocks stay in explicit test-only
ports and survive fixture rebinding; no Server/Ledger resource fields or global
registry are added. Fake discovery calls are not undone by rollback and do not
establish provider truth. These fixtures are not runtime backends or SQL
locking/durability evidence. Remaining aggregate deletion is EVY-906 work.
Session issuance now has a focused Identity command and one
tenant-owned user/provider query that requires an active user. Shared parent
locks hold status/ownership through session/audit/replay commit without reading user
display metadata or provider trust inventories. The shared stateless credential
adapter retains session entropy/prefix/HMAC compatibility; only the initial
response returns the secret. Live tests cover restart metadata replay, real
authentication, revocation/expiry, current authority/parents, rollback at all
four stages and parent-lock contention. Session revocation/logout now use a
separate focused Identity command and one bounded, hash-free session row held
through lifecycle/audit/replay commit. Administrative invalidation does not
depend on active or present user/provider parents or unexpired credentials;
self logout requires the caller's exact user/session. HTTP cookie mutations
require a matching HTTPS Origin, and durable logout clears its
cookie only after successful commit. Credential exchange orchestration now
lives in a standalone Identity command with four read operations and a narrow
snapshot-validation/session/verification/audit transaction port. It does not
construct the broad Identity service or depend on Ledger, HTTP, SQL, or provider
clients. The existing compatibility path delegates to that command rather than
duplicating login rules. Verification runs before the write transaction, which
rechecks provider trust, identity-link presence, user status, and loaded grants
before committing verification/session records and their audits. Failed trust
or authorization assessments commit only a verification receipt; any storage,
audit, cancellation, or commit failure returns no record or secret. Incoming
credentials and issued secrets are not idempotency replay material. The
production composition now binds the command directly to PostgreSQL and HTTP,
with no Ledger reload or login-state access. Short preflight transactions read
only the selected provider, tenant-owned identity link/user, and at most 256
user role bindings; the final transaction rechecks the same bounded projections.
Provider JSON is bounded before transfer by the existing 128 KiB stored-field
limits; link/user text is preflighted under a row lock, and grant fields are
bounded in SQL. Excess historical data conflicts rather than producing a
truncated identity or grant set. Empty provider collections use the same
defensive-copy representation in both preflight and comparison. Live tests cover
signed OIDC login on fresh servers with empty compatibility state, real session
authentication, fresh credentials on repeated exchange, no replay receipts,
identity changes between verification and commit, oversized projections, and
write/audit/deferred-commit rollback without cookies. Session issuance, exchange,
revocation and logout handlers now require their focused commands, with no
aggregate fallback. The broad `identityAccess` Server field and transport
interface are deleted. Focused memory issuance checks current active-user and
provider ownership; revocation reads detached, bounded hash-free metadata even
when login parents are unavailable. HTTP fixtures run actual focused issuance,
revocation/logout and session authentication, without session-cache publication.
Memory authentication selects at most 64 prefix candidates and 256 owned user
bindings; it reads only user ID/tenant/email/status and provider group mappings,
not unrelated user details or public/private trust material. Excess or corrupt
selected data returns no partial identity. Revocation compares complete public
metadata under one transaction lock and preserves the unselected credential
hash. Final active-session validation rejects closed transactions and changed
stored session/user IDs. Explicit test credentials and clocks survive rebinding.
Public credential-exchange fixtures also run the actual focused command on
bounded current provider/link/user/grant ports, with local signature verification
outside the write transaction. Signed-login tests use repository-only providers
and links; repeated exchanges create distinct sessions without replay receipts.
Failures after real receipt/session/audit writes or before commit roll back all
effects and expose no cookie or secret. Denials commit only a safe verification
receipt and audit. Trust, user or grant changes after verification conflict at
the final snapshot fence. Memory readers detach selected metadata and reject
oversized identities or excess grant rows without truncation. API-key
authentication fixtures still use their historical path. Regressions preserve
complete metadata replay, no secret
reissue, whole-state post-write rollback, current authority, cancellation,
credential invalidation and post-commit cookie clearing. Seven historical
trust/session declarations are excluded from production and retained unchanged
in `internal/app/legacy_sso_trust_oracle_test.go` and
`internal/app/legacy_sso_session_oracle_test.go`; source guards forbid their
production return. Six additional provider/link/exchange declarations are
excluded from production and retained unchanged in
`internal/app/legacy_sso_provider_exchange_oracle_test.go`. These checks are not
SQL-locking, durability or external provider-truth proof.
PostgreSQL is required for local evaluation. Remaining aggregate maps, locks,
snapshots and methods still require deletion in EVY-906. Identity linking
now uses a separate focused Identity command with a tenant/projection lock and
one current user/provider/email existence query. Parent share locks hold
ownership and email through link/audit/replay commit; no user display metadata
or provider trust inventory is transferred. Current tenant-wide authority and
parents are checked even before completed replay. Live checks cover uniqueness,
permission/parent changes, restart DTO replay, all four rollback stages and
parent-lock contention. This stores an administrator assertion, not provider
credential verification or a session/role grant. Physical aggregate retirement
remains open. Transitional credential-exchange snapshot validation
now acquires the same mutation fence before identity-table/parent locks,
avoiding inverted ordering with focused identity writes; token verification
still runs outside that transaction. See
[SSO provider registration](api.md#sso-provider-registration),
[SSO trust rotation](api.md#sso-trust-rotation),
[OIDC discovery refresh](api.md#oidc-discovery-refresh),
[SSO identity linking](api.md#sso-identity-linking),
[administrator-issued SSO sessions](api.md#administrator-issued-sso-sessions),
[SSO session revocation/logout](api.md#sso-session-revocation-and-logout) and
[SSO public trust material](api.md#sso-public-trust-material) for compatibility,
limits and historical-record caveats.

Administrative provider-identity receipts now use a separate focused Identity
command with tenant-owned provider/link reads, local credential and optional
live-provider ports, conservative assurance aggregation and a receipt/audit-only
transaction. Production wiring binds PostgreSQL directly; no Ledger inventory,
session issuer or user/grant reader is exposed. Existing bounded provider/link
SQL and snapshot comparison reject oversized or changed state, including an
absent link appearing before direct-command commit. Caller attribution, DTO
fields and safe restart replay are preserved. HTTP uses its existing outer
idempotency transaction, so a failed assessment rolls back receipt/audit and
retains only a failed-retry marker; direct application calls can persist the
failed assessment. Preflight takes the worker/audit fence before parent locks;
the live contention test observes advisory waiting and proves the waiting read
does not hold the provider row. Provider output is bounded, credential-redacted
and rechecked after redaction before assessment/persistence. Live tests cover both modes, current human authority,
restart replay, provider/link changes, oversized rows and real write/audit/
deferred-commit failures. See [provider identity verification receipts](api.md#provider-identity-verification-receipts)
for input and cookie-origin compatibility. The HTTP handler requires focused
ports only, with no aggregate fallback. PostgreSQL is required for local
evaluation. HTTP fixtures now run the actual focused receipt command using
bounded current provider/link reads from memory transactions. The complete
provider/link snapshot, including link absence, is rechecked before receipt and
audit writes; user/grant readers and session issuers are not exposed. Live fakes
and fixed test clocks stay in existing test-only ports, not Server/Ledger fields
or a global registry. Preflight sentinels forbid link reads,
credential verification, provider calls, effects, clocks and IDs. Regressions
cover full-state post-write rollback, complete credential-free replay, current
human grants, foreign providers, failed assessment semantics and cancellation.
Repository-only link regressions reject stale-cache authority, and ambiguous or
oversized memory link rows fail closed without returning a partial projection.
Twelve historical provider-receipt declarations are excluded from production
and retained unchanged in `internal/app/legacy_provider_verification_oracle_test.go`.
The stateless provider DTO translator and local OIDC/SAML verifier remain in
production; their declarations are unchanged. These memory checks are not SQL
locking, durability or provider-truth evidence. Other identity surfaces and
physical aggregate deletion remain EVY-906 work.

API-key and SSO-session verification now has a
standalone identity application service with narrow credential-read and
activity-write ports. The PostgreSQL profile binds those ports to current
credential, session, user, role-binding, and provider rows; API-key and collector
activity updates commit atomically. API-key-dependent HTTP fixtures can now bind
that actual authenticator with explicit credential/clock ports and bounded memory
prefix/collector projections, without credential-cache fallback. Activity rechecks
current key/collector identities, expiry and revocation before updating both
monotonic heartbeats under one transaction lock. Other legacy test authentication
setup still awaits migration; it is not a supported local-memory runtime.
PostgreSQL API-key issuance now binds a separate focused Identity
command with flat credential/audit transaction ports. It reads only a current
tenant identity, fences worker/audit writes in the established order, and
shares the HMAC issuer and production pepper policy with authentication.
Authority is checked before durable reservation/replay; key, audit and replay
completion share one commit. A fixed public DTO projection preserves replay
metadata without the hash or one-time secret; generic diagnostic/package
redaction is unchanged. HTTP issuance fixtures run that actual focused command
on their active repositories; guards check current tenant identity without
bootstrap-key inventory and cannot mint credentials, write, audit or use clocks/IDs.
Scoped tests preserve complete public DTOs, one-time-secret omission on replay,
repository-only credential authentication, expiry and full failed-write rollback.
Two unchanged historical key facades are excluded from production and retained
in `internal/app/legacy_api_key_oracle_test.go`; source guards forbid their return.
Memory replay clones preserve concrete DTO JSON ordering, exact interface-field
numbers and detached metadata, retaining existing byte-equality assertions when
collector fixtures move to transactions. These checks are not SQL durability,
locking or field-transfer evidence. See [API key issuance](api.md#api-key-issuance) for
bounds and compatibility. PostgreSQL organization/user creation and user
deactivation bind focused Identity membership commands with flat read/write,
authorization and audit ports. SQL selects tenant-scoped identity predicates,
one bounded user and optional organization identities, never membership or
credential inventories. Worker/audit fencing precedes tenant and parent locks;
status, audit and replay completion commit together. Live empty-Ledger HTTP
tests prove restart replay, foreign/revoked grants, current parents, bounded
metadata, concurrent uniqueness, session revocation, and rollback at write,
audit, replay and deferred-commit stages. Fixed versioned user replay retains
the required public email for authorized administration; generic diagnostics
and customer-package redaction remain unchanged. See
[organization and user writes](api.md#organization-and-user-writes) for limits
and compatibility. PostgreSQL role assignment now binds focused Identity commands
using a target-resolution port rather than cross-context repository inventories.
Bounded identity-only SQL holds the subject and coherent resource parents through
commit; no names, credential hashes, evidence payloads or manifests are selected.
Worker/audit fencing precedes tenant and parent locks. Assignment, audit and safe
replay completion share one transaction; current tenant-wide human authority and
parents are checked before replay. Live HTTP tests cover real session grants,
direct foreign rows, foreign/mismatched parents, repeated assignment, restart
replay and write/audit/replay/deferred-commit rollback. All four membership/role
handlers now require focused commands, with no optional aggregate branch; the
broad transport interface no longer exposes these methods. HTTP fixtures run
actual focused membership/assignment commands on current memory repositories,
without organization/user/role cache publication. Repository-only parent/user
regressions reject stale-cache authority. Read-only guards cannot write, audit,
use clocks or generate IDs. Tests retain tenant/parent ownership, cancellation,
detached public lifecycle metadata, complete response replay and whole-state
post-write rollback. Eight unchanged historical declarations are excluded from
production and retained in `internal/app/legacy_membership_oracle_test.go`;
`internal/app/identity_service.go` is deleted and source guards forbid its
retired facade declarations. Memory transactions use optimistic conflicts,
not PostgreSQL locks; guards do not read provider/session credential inventories. See
[role binding writes](api.md#role-binding-writes) for compatibility and bounds.
Other identity handler and aggregate deletion remains EVY-906 work; PostgreSQL
is required for local evaluation. API-key inventory pages read public metadata
from tenant-filtered PostgreSQL rows without selecting credential hashes.
HTTP key-page fixtures use the focused query over current memory rows, selecting
public fields only after tenant/keyset filtering. Credential hashes are neither
copied nor validated by metadata reads; oversized selected data fails without a
partial page. Collector preflight checks current tenant identity without key
inventory. Historical default fixture authentication and remaining aggregate
state/methods still require retirement in EVY-906.
Role-binding inventory also pages current tenant rows through a focused query,
with no aggregate inventory fallback. HTTP role-page fixtures run that query
on current repository rows. Their memory reader applies tenant/keyset selection
before projecting complete selected metadata, and rejects corrupt selected
fields without returning a partial page. It does not inspect user/credential
inventories or confer SQL transfer/locking/durability guarantees. API and worker runtime commands,
including reconciliation and parser replay, now share a composition root for
profile/load-mode validation, PostgreSQL migrations, object-store selection,
and the production API writer lease.
The production outbox diagnostics route reads the existing payload-free
PostgreSQL aggregate through a focused operations query that requires explicit
instance-admin scope before querying. It does not load outbox jobs or tenant
labels into the API. The handler requires this focused query, with no aggregate
fallback. PostgreSQL is required for local evaluation.
Production terminal-job replay now uses a focused operations command. It
checks explicit instance-admin authority before idempotency lookup, then
requeues the locked job and appends its audit entry in the same PostgreSQL
transaction as the safe replay response. The handler requires the self-owned
native idempotent command; it has no aggregate replay fallback. HTTP fixtures
now run the actual focused replay service with explicit external operator fakes
and retain receipt/retry/current-authority checks. Those external fake effects
cannot roll back with the fixture transaction; they are not SQL atomicity or
durability evidence. Invalid operator feedback cannot become a success receipt.
Production public readiness and instance-admin diagnostics now use a focused
operations probe service, not Ledger state. The composition root requires
PostgreSQL and migration probes, plus writer-lease and signing-configuration
probes in production; raw probe errors never enter either response, and safe
failure details appear only for an explicitly authorized instance admin. Both
handlers require the focused query rather than optionally falling back to the
aggregate. Instance-count diagnostics also require a focused current database
snapshot query, without an aggregate fallback.
The production metrics route uses a repeatable-read PostgreSQL projection for
tenant resource, portal, and reconciliation counters. Global outbox counters
are read in the same snapshot only for explicit instance administrators. The
route keeps its existing JSON and Prometheus response shapes and requires the
focused metrics query. HTTP readiness, metrics, instance-count and outbox
fixtures now use the actual focused services, with explicit clocks, safe probes,
and operator/reconciliation fakes retained across fixture rebinding. Count
readers select current transaction-owned scalar projections rather than
aggregate caches; tenant metrics cannot expose foreign rows or global outbox
counts without explicit instance authority. The memory test backend scans its
existing transaction maps, models only queued jobs and has no reconciliation
receipt history. Its zero receipt counters and external fake reads do not prove
bounded SQL transfer, a shared database snapshot, queue state or durability.
Complete DTO/Prometheus, read-only, metadata-detachment, cancellation, current-
repository and failure-after-projection tests retain the response/privacy
contracts. The six aggregate operator command/query methods now compile only
as unchanged package-local historical test oracles. The remaining aggregate
implementation and global application mutex still require retirement in
EVY-906; these fixtures do not expose another API runtime profile.
EVY-905 also routes production product-list pages and product, project,
release, and build point reads through focused release query services with
tenant-bound PostgreSQL queries. Their actor-scope and catalog-grant checks
no longer read the Ledger's product, project, release, or build maps. The
build query joins its project, release, and product in one statement before
the service applies resource grants.
HTTP product/candidate pages and product/project/release/build/candidate point
fixtures now run those actual focused services against current transaction-owned
readers, without an aggregate query fallback. The memory readers filter tenant
and product/release grants and apply keyset selection before projecting metadata;
project/release/candidate points require a same-tenant parent product; build
points additionally require project/release agreement on that product. Build
source identity and outputs have selected JSON byte checks; candidate reference
arrays use the creation model's identifier/count budgets. Nested identity JSON
uses exact-number decoding, but this is not a claim about the older whole-memory
snapshot clone or PostgreSQL generic-number decoding. Mutable build/candidate
metadata and release lifecycle timestamps are detached. Selected malformed
metadata or failed query commits cannot return a partial projection. These memory
scans are test-model semantics, not PostgreSQL transfer/locking/durability evidence. The product-list,
project-read, build-read and candidate-read/list Ledger facades now exist only as
unchanged package-local test oracles. Product/release facades still serve
historical synchronous ingestion guards and require migration before retirement.
The evidence-flow HTTP fixture now separately composes the focused Release
query with current transaction-owned counts and an explicit clock retained
across rebinding. The nine scalar categories match the existing SQL vocabulary,
including deduplicated SBOM/VEX/build artifact references, current decisions,
and same-tenant attestation/build joins. Reads reserve no replay record; denied,
cancelled or failed-commit reads return no plan and do not consult the plan clock.
Its Ledger plan method is now an unchanged test-only oracle. The old aggregate
count helper still serves the remaining release-security-summary facade;
artifact fixture reads and other aggregate surfaces remain EVY-906 work. Memory
count scans still do not establish SQL transfer/work bounds or durability.
The 32-caller HTTP idempotency fixture now uses native credential authentication
and records actual credential-use writes. Its memory transaction admission is
serialized to avoid optimistic whole-snapshot conflicts; HTTP callers remain
concurrent and retain their original exactly-once/replay assertions. Cancellation
and commit/rollback admission release have regressions. This is not proof of
parallel PostgreSQL transactions or retirement of the remaining Ledger locks.
The built-in control-template catalog is owned by the risk context and read
without the Ledger in the PostgreSQL profile. It contains static starter
definitions, not tenant state. Installation binds a focused risk command and
native durable HTTP replay, without Ledger cloning or state publication. Its
read-only guard checks current tenant-wide administration and tenant existence
before both fresh installation and replay; it does not reread installed
framework metadata, controls, or the version key on replay. The common writer
fence precedes the tenant share lock and both survive the outer replay commit.
Fresh installation checks the tenant/slug/version key, inserts every starter
control, and appends one principal-attributed audit in that transaction, with
no outbox job. Late control/audit, replay-completion and commit failures roll
back the whole installation; concurrent same-key requests execute it once.
A different-key duplicate version conflicts. Local-memory mode retains its
explicit compatibility storage and nondurable replay, with the same tenant
administration and raw-slug validation. Broad startup retirement remains open.
Manual framework and security-control creation now also have focused risk
commands composed solely from the active write transaction. Their readers
return tenant-owned existence bits rather than framework metadata or control
inventories; the PostgreSQL projection fence precedes parent locks and audit
appends. Framework/version and control/code uniqueness checks, current
tenant-wide administration grants, insertion, and audit share that transaction.
The commands preserve slug derivation, requirement order, applicability sorting
with duplicates, limitation order, and existing schema versions. They reject
unsupported text/index sizes and excessive list work before persistence.
PostgreSQL HTTP creation routes bind these commands with native durable replay,
without cloning or publishing Ledger state. Read-only guards check current
tenant administration/existence and, for controls, framework ownership before
replay. They hold tenant/parent share locks through outer commit, without
reading duplicate keys or mutable metadata. Live regressions cover restart and
role revocation, parent reparenting, record/audit/replay/commit failures,
concurrent delivery and cancellation. Both profiles share raw-text bounds and
strict JSON decoding; local memory retains compatibility storage and nondurable
replay. Broad startup retirement remains open. Control-evidence linking now has
a focused risk command core with transaction-only control/subject/duplicate readers and one
atomic link/audit append. It checks current subject-derived coordinates before
duplicate disclosure, preserves supplied scope and original duplicate results,
and bounds text and the indexed natural key. Its PostgreSQL composition now
requires only the active unit of work: the tenant projection fence precedes
control/framework share locks, subject-coordinate reads, duplicate lookup, and
audit append. Parsed subjects require matching source-evidence kinds and
consistent tenant/product/release relationships; SBOM/VEX artifact references
must also be tenant-owned. Ambiguous finding IDs conflict instead of choosing
an arbitrary scan. Subject documents and artifact metadata stay in PostgreSQL;
duplicate notes above 64 KiB fail closed rather than truncate. Human grants are
checked against current coordinates; artifact grants must match the requested
scope in an evidence/build association, including the artifact's build-output
digest. That query accepts at most 4096 grant IDs and 64 KiB of grant identity
text. Live tests cover every supported subject, focused-list visibility,
uncommitted subject reads, outer rollback, replay, storage failures, and
competing duplicates. PostgreSQL HTTP evidence-link writes now bind focused
commands with native durable replay, without Ledger cloning or publication.
Shared read-only orchestration checks current tenant/control/framework/subject
ownership and grants before fresh writes and replay; it never reads duplicate
notes or allocates IDs. The actor-tenant fence and tenant/control/framework
share locks survive outer replay commit. Live tests cover all sixteen subject
kinds, current grants, restart replay, large unrelated metadata, natural
duplicates, record/audit/replay/commit failures, concurrency and cancellation.
Raw text is bounded before trimming and both profiles share strict JSON and
cookie-origin checks. Local memory retains local-map reference behavior and
nondurable replay, not PostgreSQL source/projection guarantees. These boundaries
do not retire production Ledger startup or its remaining maps. See
[control-evidence linking](api.md#control-evidence-linking).

Approval creation also binds a transaction-only command and direct durable
idempotency in PostgreSQL. Identifier-only queries resolve all five existing
subjects through current tenant-owned parents, including waiver scope, contract
source ownership, security-review source type, and customer-package redaction
profile ownership. Human sessions need a matching product/release grant; waivers
on tenant-wide controls/policies require a tenant grant. Authorization runs before
reservation/replay, and approval, audit, and replay completion share one unit of
work. Optional evidence retains the existing same-tenant ownership rule, not a
new same-release requirement. Live HTTP tests use fresh servers with forbidden
Ledger refreshes and cover replay, role removal, malformed input, and rollback.
Other compatibility paths remain open.

Waiver creation and approval now bind transaction-only commands in PostgreSQL
as well. Current release/finding ownership or tenant-wide control/policy scope
is resolved inside the durable idempotency transaction. Supersession authorizes
both scopes without fetching the prior reason. Approval authorizes metadata
first, then reads one bounded waiver and preserves its immutable core fields.
Existing conditional approval/supersession metadata writes and audit entries
commit with replay completion; this is not a claim that all historical waiver
metadata has been converted to append-only projections. Live fresh-server tests
forbid Ledger refreshes and exercise write, audit, replay-completion, and
deferred-commit rollback. Production Ledger startup and unrelated workflows
remain to be retired.

Trusted relational/snapshot replay no longer rewrites existing waiver rows.
It compares stored core fields and any supplied lifecycle metadata, rejecting
mismatches. An unchanged older snapshot may omit later approval/supersession
metadata without undoing it. Legacy initial imports remain supported; an absent
historical creation time on replay never replaces the stored timestamp.

Exception creation and approval also bind focused transaction-only commands
in PostgreSQL. Current tenant-owned release/product, optional finding, and
control/framework parents are resolved before reservation or replay. Metadata
authorization precedes the single bounded approval-record read; queries take
the tenant projection fence before row locks and retain it through commit.
Existing conditional approval metadata and audit writes share the durable
idempotency transaction. Repeated approval of an unexpired exception returns
the original record without a second approval audit. Live tests cover concurrent
approvals, current-parent replay authorization, expiry, and rollback at each
write/completion/commit stage without Ledger refreshes.

Trusted exception replay uses the same no-rewrite discipline as waivers: core
fields and supplied approval metadata must match, while omitted later approval
metadata in an unchanged older snapshot cannot undo durable state. Initial
legacy imports remain supported. These changes do not convert all exception
metadata to append-only projections or retire production Ledger startup.

Vulnerability workflow annotations now bind a focused Risk-owned command in
PostgreSQL. Its finding reader resolves current tenant-owned scan/source and
release/product identifiers only, with a two-row ambiguity sentinel; scanner
payloads and historical workflow reasons never cross the port. The projection
fence precedes scan row locks and remains held through workflow insertion,
audit append, and durable replay completion. Existing action labels remain
annotations, not finding-state or decision-supersession operations. Release-less
scans retain their tenant-wide grant requirement. Fresh-server HTTP tests forbid
Ledger refreshes, preserve old scanner/decision/workflow rows, and cover current
ownership, replay, malformed input, and rollback at each transaction stage.
The explicit local-memory path and unrelated production workflows remain.

Vulnerability-decision creation now has a separate transaction-only command
core. It uses the existing normalization and decision-construction rules, but
does not refresh projections or list a tenant's full decision history. Current
finding coordinates authorize the command before evidence, VEX, supporting
records, or active heads are read. Supporting records use the existing closed
six-type vocabulary and must match the current product/release. The command
accepts at most 128 active heads for one finding, with an explicit 129th-row
overflow sentinel. It orders heads by ID for deterministic supersession and
passes only identity/status summaries to the append port, never prior decision
statements or notes. That port must preserve historical content while appending
the new decision and supersession relationships in the same transaction as the
audit events. Input text is NUL-free UTF-8: statements are bounded at 64 KiB each,
internal notes at 8 KiB, identities at 1024 bytes, up to 256 evidence-ID inputs
and 20 supporting references, and total input text at 128 KiB before copying or
deduplication. Finding labels are bounded projections, not full scanner JSON.
Transaction-fake tests cover exact bounds, current-grant ordering, foreign or
inconsistent references, review dates, cancellation, late audit failure, and
commit rollback. The PostgreSQL decision repository now implements this core's
bounded read port inside an active transaction. It selects finding coordinates
from at most two matching current typed scan sources, rejects ambiguity and
malformed or oversized selected labels, and resolves SBOM context without
transferring scanner or component inventories. SBOM selection preserves PURL
precedence over name/version fallback, then creation-time, ID, and component
order, including Unicode whitespace normalization. Evidence, VEX and all six
support types require current tenant-owned parent relationships; approvals also
validate their release, waiver, customer-package/redaction, contract-diff/typed
contract sources, or security-review/typed document subject. Active-head reads
return only identity/status fields, ordered by ID and row-locked, with a maximum
129-row request. The exclusive tenant projection fence is acquired before row
locks and retained through the surrounding transaction. Live tests cover these
reads, foreign/broken parents, oversized historical content, pending rows,
rollback visibility, head limits, and fence release. The append adapter compares
bounded current heads and source/reference coordinates, then inserts immutable
supersession relationships and the new decision without updating historical
decision rows. Migration `20261002000100_vulnerability_decision_supersession`
retains existing rows and legacy `superseded_by` values. Tenant/ID foreign keys
bind both relationship ends to the same tenant, and deferred constraint triggers
check finding agreement at commit, including related finding changes. Two-key
indexes preserve the declared 1 KiB identity limits without exceeding PostgreSQL
btree tuple bounds. A derived head table's primary key replaces the legacy
active-row index; triggers maintain that constraint for legacy writes too.
Relationship updates/deletes are rejected, and downgrade refuses to discard
nonempty supersession history. The response view derives `superseded_by` from
new links with a legacy-field fallback; the focused head reader excludes linked
predecessors. Live tests prove unchanged historical row content, expected-head
conflicts, database-enforced active-head uniqueness, tenant-safe relationship
ends, rollback on either insert and outer abort, and migration round-trip/data
preservation. Decision pages, customer summaries, flow/security counts,
readiness facts and reports, security-update and vulnerability-handling reports,
worker projections, and transitional relational loading now read that response
view. Their existing tenant/grant filters, report bounds, and note-free public
columns are unchanged. Live regressions cover new and legacy successor links,
historical timestamps later than the current head, current readiness blockers,
and exclusion of superseded missing statements/justifications. Internal worker
history retains private notes; customer projections do not.
The existing transaction-scoped `SupersedeAndInsert` port now compares bounded
current head identities and shares the append-only row writer. It retains its
legacy ownership contract rather than claiming the focused command's stricter
source/reference validation. Tests prove unchanged historical content and stale
head rejection. These are adapter/storage-port tests, not route or production
proof. The bulk relational synchronizer now inserts new decision rows or compares
all historical content in SQL; it no longer updates existing decision fields.
Only successor links are appended. Identical replays, including a loaded
projection or an original active row replayed after supersession, cannot
reactivate a predecessor. Tests cover every stored content field, replayed links,
nullable/empty collections and unspecified legacy creation clocks, stale heads,
foreign/missing/misbound successors, insert failures, and late transaction abort.
These trusted import/sync paths retain initial legacy rows and their raw
`superseded_by` fields; they are not new API authorization or source-validation
ports. A same-ID historical content mismatch now fails instead of silently
merging or ignoring changed metadata. Supersession timestamps use a supplied
successor creation time or the time of import, never the predecessor's age.
The PostgreSQL decision route now binds the focused command and a direct
unit-of-work idempotency executor. Current tenant-owned finding coordinates and
human product/project/release grants are checked before reservation or replay.
The command, immutable supersession links, audit entries, and safe replay response
share one transaction; neither Ledger cloning nor post-commit whole-state refresh
is used on this route. Live HTTP tests use fresh servers and a store that rejects
any Ledger reload after construction; they cover grant removal, foreign inputs,
unchanged historical rows, note-free responses/replays, and rollback on decision,
audit, replay-completion, and deferred commit failures. Local memory retains its
explicit compatibility command. This route does not prove retirement of the
remaining compatibility operations or startup load.
PostgreSQL backup commitments now use an explicit v2
profile that includes supersession history; the immutable v1 allowlist and
digester remain available for historical reproduction. See
[verification results](reference/verification-results.md#tenant-scoped-backup-manifest-generation).
The read-only release evidence-flow plan also uses a focused service in the
PostgreSQL profile: one tenant-filtered SQL statement collects nine release
counts from a consistent snapshot, then current resource grants are checked
before the response is returned. The local-memory profile keeps the Ledger
count path. The counts describe recorded evidence, not its completeness or
security assurance.
The PostgreSQL API and worker daemon use focused composition without broad Ledger
startup or worker snapshot fallbacks. EVY-905 closure validation passed; physical
legacy cleanup remains EVY-906. See [current runtime composition](#current-runtime-composition).
Evidence list and search pages now use focused Evidence query services and
bounded PostgreSQL identity batches. SQL-side candidate grants precede keyset
limits; current ownership and selected worker provenance are checked before
metadata in the same repeatable-read view. Only policy denials are filtered,
with batch refill preserving authorized continuation. These routes no longer
use Ledger authorization maps, tenant-wide projection refreshes or caches.
They unconditionally roll back; selected item/provenance budgets remain 8 MiB
and 4096 facts, while encoded returned items have a 16 MiB page budget. Stored
JSON numbers remain exact for transport without changing normalized hashes.
See [evidence collection reads](api.md#evidence-collection-reads) and
[current runtime composition](#current-runtime-composition).

Evidence supersession, linking and lifecycle-event creation now bind a focused
Evidence relationship service and native durable HTTP execution. Current
tenant-owned evidence coordinates, coherent parents, optional replacement and
link targets are share-locked and authorized before every fresh request or
completed retry. The common writer fence precedes these locks and survives the
outer transaction. Replay does not read evidence metadata, lifecycle history,
legacy origins, clocks or IDs. Fresh execution uses bounded item/provenance
reads and selects only authoritative legacy origins (8 MiB, at most 4096 rows),
not a complete timeline. Relationship fields, append-only event(s), audit and
safe replay completion commit together; immutable core fields and canonical
hash profiles stay unchanged. Both profiles share strict raw-bounded input and
cookie-Origin protection. Explicit local memory uses current-map guards and
nondurable compatibility storage, not the native transaction guarantees. See
[evidence relationship writes](api.md#evidence-relationship-writes).

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

PostgreSQL signing-operation creation binds focused Verification commands to
bounded provider metadata and owned subject coordinates. Canonical request
hashing and receipt validation are shared with test-only memory adapters. The
provider call, receipt/operation/audit writes and replay completion run under
current root/provider locks and the projection fence. Database rollback cannot
undo a provider call. The HTTP handler uses focused commands only; PostgreSQL
is required for local evaluation. HTTP fixtures run the actual focused signing
service on memory transactions, reading current owned subject coordinates and
bounded provider metadata directly from repositories. Provider results are
validated before metadata redaction; signature, operation, audit and replay
writes remain atomic. Read-only guards cannot sign, write, audit, use clocks or
generate IDs. Fake signing dependencies stay in explicit test-only command
ports, not Server/Ledger fields or a global registry. Eleven historical PDF and
signing declarations are excluded from production and retained unchanged in
`internal/app/legacy_pdf_signing_oracle_test.go` for package-local regressions.
The obsolete PDF guard file is deleted; pure signing boundary mappers remain.
Whole-state rollback, complete DTO, provider-failure and replay tests do not
prove SQL locking, durability or real-provider trust. Aggregate maps, snapshots
and other methods still require physical retirement in EVY-906.
See [signing operation creation](api.md#signing-operation-creation)
for bounds, replay authorization, retry limitations and non-claims.

Release readiness is deterministic and evidence-scoped. Open critical vulnerability findings block readiness unless the latest decision marks the finding `not_affected` or `fixed`, or an approved unexpired exception applies to the release or finding. Passed build provenance and a structurally valid build attestation must link to release artifact digests.

DSSE attestation signatures can be verified against configured Ed25519 trust roots when raw attestation bytes are available. The Cosign route verifies a finalized stored offline Sigstore bundle with operator-configured Fulcio/public-key trust material, the artifact digest, signature bytes, keyless caller-supplied identity/issuer policy when applicable, and an embedded Rekor inclusion proof. It records a safe library and trust-root version receipt, never raw trust material or bundle bytes. Requests requiring online verification fail rather than downgrading; missing trust material returns `COSIGN_FULL_VERIFICATION_UNAVAILABLE`. Signing keys support revocation and valid-at-signing semantics for historical signatures.

Merkle batches, signed checkpoints, optional transparency checkpoint/public transparency records with operator-supplied or fetched inclusion proof verification, backup manifests, object-retention policy records with verification hashes, legal holds, retention overrides, readiness, metrics, instance admin diagnostics, external signing gateway/AWS KMS signing receipts, and admin audit queries provide operational integrity and review surfaces. The production retention report reads tenant-filtered legal holds and overrides from one PostgreSQL snapshot; it describes Evydence records and does not verify external storage lifecycle enforcement. The production incident report reads one tenant-owned incident, its timeline, and its remediation tasks from one PostgreSQL snapshot. It rejects rather than truncates reports with more than 4096 combined timeline events and tasks; evidence links organize recorded references without proving root-cause or remediation completeness.

## Reports And Customer-Facing Packages

PostgreSQL portal issuance/revocation and token-based JSON, HTML and ZIP access
now use focused Package commands. Administrative guards read only current
package ownership and selected public portal metadata, not manifests or hashes.
Token verification resolves bounded prefix coordinates, takes the tenant writer
fence before row locks, and rechecks one credential and package. NDA transitions,
monotonic portal counters and access/download audits commit together; failed
tokens and NDA-required denials retain their audited denial effects. Shared
record-only HTML/ZIP rendering does not regain Ledger access. The API composition
root binds both issuer and consumer so newly issued/revoked tokens are visible
immediately without reloading broad state. Issuance, revocation, inventory and
JSON/HTML/ZIP token consumption require focused ports, with no aggregate
fallback. Test-only composition runs the actual focused services on memory
transaction snapshots, not legacy portal maps. Administrative reads exclude
hashes; consumption owns the NDA/counter/audit transaction, including deliberate
denial commits. Pure guards cannot mint, revoke, audit or read private package
content. Whole-state failure tests cover issuance/revocation and token lifecycle
writes; public-page/replay checks preserve current grants and privacy.
These checks do not prove SQL locking or durability. PostgreSQL is required for
local evaluation. The historical Ledger portal lifecycle, archive methods,
inputs and helpers are now excluded from the production build and retained
only in `internal/app/legacy_portal_oracle_test.go` for package-local historical
regressions. The two uncalled aggregate portal replay guards are deleted;
source checks prevent the retired production surface from returning. These
oracle tests do not exercise the supported native runtime. Shared aggregate
maps, snapshots and other methods still require deletion in EVY-906.
See [portal lifecycle](api.md#customer-portal-lifecycle)
for bounds, privacy-safe replay and existing archive-content limitations.

Control coverage and CRA-readiness reports use versioned tenant-created controls, explicit evidence links, approved unexpired control exceptions, and built-in starter packs for CRA-readiness, NIST SSDF-lite, SOC 2-style technical evidence, and ISO 27001-style technical evidence.

In the PostgreSQL profile, these reports read controls, current tenant-owned evidence subjects, and active exceptions from one repeatable-read snapshot. Subject scope and observed time are resolved from durable records before freshness is evaluated; stored link coordinates alone do not grant report inclusion. The reader rejects reports above 4096 combined controls, links, and exceptions or 8 MiB of selected text rather than silently truncating them; SQL preflight bounds individual control, link, and exception rows before transfer. An empty framework yields unknown coverage, and broad reports do not apply release-specific waivers. Local-memory mode retains the compatibility Ledger report path. These reports organize recorded technical evidence; they do not determine legal compliance.

The production security-update evidence report reads fixed decisions, scans, incidents, and remediation tasks for one tenant-owned release from a repeatable-read PostgreSQL snapshot. It omits private decision notes, verifies linked evidence remains in the tenant and report scope, and rejects rather than truncates reports above 4096 source rows or linked evidence identifiers. It organizes recorded evidence only; it does not prove legal sufficiency, notification completeness, or release security. Local-memory mode retains the Ledger report path.

The production CRA vulnerability-handling report uses the same tenant/release snapshot and evidence-scope discipline. PostgreSQL aggregates scan finding counts without loading raw finding arrays into the API, then projects active decisions and approved unexpired exceptions with a 4096-row/evidence-ID cap. It excludes private decision notes and does not claim complete detection, scanner authority, legal compliance, or release security. Local-memory mode retains the Ledger report path.

Source snapshots, deployment records, signed incident webhook events, incident packages, security scans, manual reviews, SBOM diffs, contract diffs, API security checks, customer packages, customer portal package access, questionnaire packages, evidence bundles, and custom policies add traceability and reproducible decisions. Reports include gaps, assumptions, and limitations.

Evidence summaries, questionnaire drafts, graph snapshots and anomaly reports organize stored records with their documented assumptions and limitations. Customer-facing packages require explicit package scope, redaction profile, expiry, and access auditing. Customer package JSON and ZIP download paths return scoped manifest metadata and verification guidance; raw tenant evidence payload bytes are not returned.

Experimental public-log creation and publication now bind focused commands to
bounded PostgreSQL tenant/log/checkpoint/Merkle-root projections. The actor-tenant
worker/audit fence is acquired before root share locks and retained through
the metadata/audit/replay commit. Publication reads one owned root chain; it
does not select log endpoint/key metadata or Merkle leaf/signature arrays.
SQL caps transfer of corrupt batch IDs and root text before core validation.
Both HTTP handlers use focused commands only. PostgreSQL is required for local
evaluation. HTTP fixtures run the actual focused services on memory transactions,
selecting only current owned identifiers and the root commitment. Repository-only
checkpoint regressions reject stale-cache authority; creation retains the pure
canonical entry hash, complete DTO and atomic audit/replay assertions. These are
not SQL guarantees. These commands do not publish externally or assign inclusion
assurance.
See [public transparency metadata](api.md#public-transparency-metadata).

Operator-supplied public-log proof verification now uses focused Experimental
commands and one bounded tenant-owned entry/root-chain projection. It locks
the assessment row and current roots after the actor-tenant fence, then commits
the local result, proof-bound audit and replay together. Old diagnostic arrays,
log endpoints/keys and Merkle leaves are not selected. Same-state updates
compare previous proof commitments as well as publication coordinates. The HTTP
handler has no aggregate fallback. Memory fixture reads omit historical diagnostics
and unrelated metadata, and detach the selected assessment timestamp. The writer
compares all prior assessment coordinates under one transaction lock, including
same-terminal-state proof changes. Complete DTO, negative-proof and whole-state
failure assertions remain intact. No authenticated public-log root or
provider identity is implied. Remaining aggregate deletion is EVY-906 work; see
[proof verification](api.md#public-transparency-proof-verification).

Public-log proof fetching now uses focused Experimental commands, current
bounded entry/endpoint ports, and the runtime's configured direct/gateway
fetcher. Endpoint/root locks and the actor-tenant fence survive the bounded
provider call and assessment/audit/replay commit. A frozen source is compared
again before writing; provider diagnostics never become local authority.
Replays perform current authorization but no network request. The transaction
does not roll back remote observation, so a failed-commit retry may refetch.
The HTTP handler has no aggregate fallback. HTTP fixtures run the actual fetch
service with explicitly supplied fake fetchers and fixed test clocks in existing
test-only ports, not Server/Ledger fields or a global registry. Read-only guards
cannot fetch, write, audit, use clocks or generate IDs. Fake provider calls are
not undone by rollback and are not provider verification evidence. Twenty-three
historical declarations are excluded from production and retained unchanged in
the three `internal/app/legacy_public_transparency*_test.go` oracle files.
Three obsolete production guard files are deleted; only detached persistence
mappers remain in `internal/app/public_transparency_records.go`. Source guards
prevent the retired surface from returning. Aggregate maps, locks, snapshots and
other methods still require physical retirement in EVY-906. See
[proof fetching](api.md#public-transparency-proof-fetching) for timeout,
tenant-mutation latency, input and provider-trust limits.

Experimental marketplace collector registration now uses focused commands and
flat tenant/reference ID projections in PostgreSQL. The transaction acquires
the actor-tenant worker/audit fence before locking current roots. Supplied
signature, SBOM and scan rows are tenant-filtered and share-locked through the
collector/audit/replay commit; the query never selects signature bytes, signing
keys, component arrays or scan findings. Missing/foreign references fail closed
and successful replay rechecks current human tenant grants and references.
HTTP registration, list and health handlers use focused ports only; PostgreSQL
is required for local evaluation. HTTP fixtures run the actual focused commands
and marketplace query service on memory transactions, not collector caches.
Their reference ports project only ownership IDs; current health points retain
the distinction between missing and invalid references. Paging filters the
tenant before selecting and detaching complete records. Read-only guards cannot
write, audit, generate IDs or use clocks. These checks are not SQL guarantees.
No package bytes are verified or published, and no provider is endorsed.
See [marketplace collector creation](api.md#marketplace-collector-creation).
Remaining aggregate code deletion remains EVY-906 work.

Experimental SaaS profile creation now uses focused commands and at most two
current tenant keys, with exact instance-admin authority. Profile, audit and
replay writes are atomic and root deletion is locked through commit. Pure
raw-value hashing and record rules are shared with test-only memory adapters.
HTTP fixtures run the actual focused profile command on memory transactions,
including the deliberate existing cross-tenant admin reference; an instance
grant does not establish provisioned isolation or provider readiness.
The HTTP handler has no aggregate fallback or local-memory runtime path.
These records express hosted-deployment intent only, not provisioned isolation.
See [SaaS profile creation](api.md#saas-profile-creation) for the deliberate
cross-tenant admin-reference boundary and compatibility limits.

Experimental anomaly reports bind focused commands and current scoped SQL facts
to the report/audit/replay transaction. Release checks share readiness presence
predicates without loading full readiness or Ledger snapshots. Other subjects
currently have no checks; `clear` is not a security conclusion. The HTTP handler
has no aggregate fallback. Test-only adapters retain actual guards, detached
signals and isolated writes, not SQL guarantees. HTTP fixtures now run the
actual focused anomaly command on memory transactions. The repository returns
only three release-fact booleans and owned IDs, matching registered artifact
digests, coherent build/attestation sources, trusted receipt profile/version,
exact active finding decisions and approved unexpired scoped exceptions.
Fact readers reconstruct neither Ledger nor a full readiness snapshot.
Read-only guards cannot read facts, write, audit, use clocks or generate IDs.
Whole-state failure and
current-grant replay tests retain their assertions; repository-only scan tests
reject stale-cache authority. Typed memory copies preserve valid empty signals
for clear reports while still rejecting nil signals. Six historical anomaly
declarations are excluded from production and retained unchanged in
`internal/app/legacy_anomaly_oracle_test.go`; the obsolete guard file is deleted
and its pure error mapper remains in `internal/app/experimental_command_error.go`.
These tests do not prove SQL locking, durability or cryptographic validity of
recorded receipts. Aggregate maps, locks and snapshots still require deletion.
See
[anomaly report generation](api.md#anomaly-report-generation) for exact signals,
input limits, current-grant replay and remaining limitations.

PDF report packaging binds focused Package commands and current product/release
coordinates in PostgreSQL. Verified staging, lifecycle metadata, finalizer job,
report, audit and replay completion commit together; failures publish no report
result. The payload remains a minimal title-only envelope, not stored evidence
or report-type-specific pages. The HTTP handler has no aggregate fallback.
HTTP fixtures run the actual focused Package service on memory transactions.
Coordinate-only guards cannot stage, hash, write, audit, use clocks or generate
IDs. Focused inserts recheck current ownership and the complete record's
versioned payload hash, byte count and canonical object reference. Existing
whole-state failure, complete DTO, actual staged-byte and current-grant replay
checks retain their assertions. Storage dependencies stay in explicit test-only
ports; physical staged bytes can outlive rollback. These checks are not SQL
locking or durability evidence. See
[PDF report packaging](api.md#pdf-report-packaging) for byte/hash compatibility,
storage modes, physical orphan recovery and privacy-safe replay limitations.

PostgreSQL graph snapshots bind focused Package commands and selected adjacency
repositories. Coordinate-only guards resolve current tenant ownership before
replay; creation retains the worker/audit fence and root/evidence/parent locks
through commit. SQL preflight bounds selected rows and text before fetching
labels or structured references. The shared pure builder retains deterministic
node/edge ordering and normalized-JSON hashing without loading raw payloads or
unrelated tenant state. Snapshots and their hash-linked audit entries are
append-only; failures publish no result. Recorded opaque references are not
verification authority or evidence completeness. See
[graph snapshot creation](api.md#graph-snapshot-creation) for exact limits and
privacy-safe replay caveats. The HTTP handler has no aggregate fallback. HTTP
fixtures run the actual focused graph command on memory transactions, selecting
bounded root labels and structured adjacency directly from repository rows.
They preserve raw product/release selection and inferred authorization parents;
coordinate-only guards cannot read labels, adjacency or hash a graph. Twenty
historical graph/profile/marketplace declarations and helpers are excluded from
production and retained unchanged in
`internal/app/legacy_peripheral_oracle_test.go` for package-local regressions.
Three obsolete production guard files are deleted; only detached DTO mappers
remain in `internal/app/peripheral_legacy_records.go` for persistence translation.
These tests do not prove SQL locking, durability or provider trust. Aggregate
maps, snapshots and other methods still require physical retirement in EVY-906.

PostgreSQL questionnaire drafts bind focused Package commands and a pure
tenant/product/release policy in the composition root. The worker/audit fence
precedes root/template locks. Bounded question selectors and candidate scope
metadata are selected before authorized winner text; template prompts and raw
evidence payloads never cross these ports. Citation parents are resolved and
locked so misleading control-link/library coordinates cannot broaden scope.
The focused writer rechecks ordered template identities, citations, output
bounds and the versioned response hash; draft, audit and replay commit together.
HTTP replay fingerprints also bind the original credential scopes and human
resource grants, preventing permission downgrades from returning an old private
answer even when the draft root remains accessible. The handler requires
focused ports only; PostgreSQL is required for local evaluation. Test-only
guards read bounded template/root coordinates from memory transactions and
run the actual focused policy; private selector/candidate/answer/citation
reads, report writes, audits, clocks and IDs fail loudly during preflight.
Historical writes remain isolated and returned response metadata is detached.
See [questionnaire draft creation](api.md#questionnaire-draft-creation) for
limits and compatibility.

Questionnaire-template creation also binds a focused Package command. Its
transaction port can validate tenant/control/framework identities, insert one
definition, and append an audit; it cannot access full tenant state or private
control text. Tenant-wide human authority, shared canonical input/record
validation and exact encoded-byte bounds apply before persistence. The shared
worker/audit fence precedes parent locks, and template/audit/replay effects
commit together. The handler requires focused ports and rechecks current
template-create authority on replay. PostgreSQL is required for local
evaluation. See [template creation](api.md#questionnaire-template-creation).

Redaction-profile creation now binds Package-owned focused commands directly
in the PostgreSQL profile. Flat ports permit only one profile insert and its
caller audit. The tenant writer fence precedes the selected tenant row lock,
and profile/audit/replay commit atomically. Creation does not read evidence,
existing profiles, customer manifests, or signing keys. Both profiles share
preset/normalization rules and recheck tenant-wide package-write authority
before replay. Historical profiles are not rewritten or subjected to new
creation bounds. Customer-package creation rules are now extracted into a
focused command with a native selected-scope/policy write adapter, but its
production snapshot reader and HTTP binding are not yet installed. Creation
and API startup still have Ledger dependencies; these prerequisites do not
remove them. See [customer-package creation](api.md#customer-package-creation)
and [redaction-profile creation](api.md#redaction-profile-creation).

Authenticated customer-package downloads now use the same focused audited
access command as package JSON reads, followed by the existing bounded
record-only ZIP renderer. PostgreSQL access takes the common worker/audit fence
before locking the selected package row, consistent with portal-token access.
No evidence reload, full tenant snapshot, or Ledger archive lookup is needed.
The successful access count/audit commits before rendering; failed rendering
or delivery may therefore retain an access audit, not a delivery receipt. See
[archive download](api.md#customer-package-archive-download).

Answer-library creation also binds a focused Package command. Its flat ports
resolve only current root/reference ownership, authorize tenant/product/release
grants, and insert one bounded draft plus caller audit. Selected controls have
same-tenant framework parents, and cited evidence has coherent current
product/project/release/build/deployment parents. Raw selection coordinates
remain separate from resolved authorization coordinates. The shared worker/audit
fence precedes selected row locks; answer/audit/replay effects commit together.
Replay rechecks current root grants and referenced ownership without loading
existing private answers or evidence payloads. Creation and inventory handlers
require focused ports; PostgreSQL is required for local evaluation. See
[answer-library creation](api.md#questionnaire-answer-library-creation).
Questionnaire-package generation also binds focused Package commands. It shares
the bounded response builder with drafts but authorizes both root selection and
each private answer under `package:write`. Optional customer-package association
has separate current parent/grant checks and never supplies an implicit evidence
filter. Bounded parent coordinates replace manifest reads; the worker/audit fence
precedes selected locks and package/audit/permission-bound replay commit together.
The focused writer rechecks ordered question identities, citation ownership,
output bounds and response hash. See
[package creation](api.md#questionnaire-package-creation) for association and
compatibility limits. The template, answer-library creation/inventory and
questionnaire-package handlers have no aggregate fallback. Template, package and
draft HTTP fixtures now run the real focused commands over memory transactions.
Their bounded ports project only current ownership and question selectors;
private answers are read only after per-answer authorization. Template creation
and package/draft generation work without publishing template caches back into
Ledger. Read-only guards panic on clocks, IDs, private reads or effects. Focused
memory inserts reject mismatched customer-package associations and reordered
question responses. Historical generator declarations and inputs are now
excluded from production and retained in
`internal/app/legacy_questionnaire_oracle_test.go` solely for package-local
regressions. The obsolete package guard file and unused fixture input conversion
are deleted. Answer-library fixtures now also use real focused commands and
the focused paged reader over memory transactions, without publishing answer
caches back into Ledger. Current-parent and grant predicates precede pagination
and private answer projection. Historical answer-library declarations are
excluded from production and retained unchanged in
`internal/app/legacy_answer_library_oracle_test.go` solely for package-local
regressions; the obsolete answer-library guard file is deleted.
Existing and new tests cover whole-state rollback,
complete DTO/hash/audit, current-grant/foreign-reference, permission-fingerprint,
page and nested-metadata detachment regressions. They are not SQL bounds,
locking or durability evidence. Physical aggregate maps, snapshots and the
remaining methods still require deletion in EVY-906.

PostgreSQL evidence-summary creation now binds Package-owned focused commands
directly through the composition root. One transaction locks root coordinates,
authorizes the scope, preflights bounded citation lengths/IDs, reads only their
text, and inserts the summary with its audit/replay effects. The shared
worker/audit fence precedes root row locks. Resolved authorization coordinates
are separate from stored selection filters, preserving evidence/build/package
root behavior without loading payloads or manifests. See
[evidence summary creation](api.md#evidence-summary-creation) for limits and
the customer-package/redaction distinction. The handler requires focused ports
only. Summary/draft HTTP fixtures also run real focused commands on memory
transactions. Summary ports select current repository citation metadata without
publishing evidence caches to Ledger, bound counts/bytes before projection,
and revalidate the current root and exact citation metadata before insertion.
Read-only guards use bounded root/parent projections and actual focused policy;
they panic on citation reads, clocks, IDs, report writes or audit effects. Raw
selection filters are not narrowed by inferred authorization parents. Historical
summary declarations are excluded from production and retained unchanged in
`internal/app/legacy_summary_oracle_test.go` solely for package-local regressions.
PostgreSQL is required for local evaluation. Both summary/draft regressions
cover whole-state rollback, complete DTO/citation/hash/audit bindings, current
grants, foreign roots, permission-bound replay and detached metadata; memory
checks are not SQL bounds, locking or durability proof. No HTTP handler calls
Ledger directly. The HTTP Server's Ledger and legacy replay fields, the
aggregate create-helper chain/context alias, and the legacy replay interfaces
are deleted. Regression checks scan every production HTTP source file for
aggregate dependencies and assert the retired fields are absent. Historical
test setup obtains its Ledger from existing test-only identity query fixtures;
there is no production back-reference or global fixture registry. Conditional
replay tests still seed historical body-only receipts directly through the
test ledger and verify rejection by the focused HTTP executor. The aggregate
implementation itself still requires physical retirement in EVY-906.

## Provider And Deployment Boundaries

PostgreSQL collector registration, release evidence recording, and commercial
definitions use Integration-owned commands with flat transaction ports. A
shared credential adapter issues HMAC-compatible one-time keys without Ledger
state. Bounded tenant/ID and identity lookups hold coherent evidence parents
through commit; the projection fence precedes relational locks. Collector/key,
pin, audit, and replay effects are atomic, and replay preserves only public
credential metadata. These routes never reload Ledger inventories. See
[collector writes](api.md#collector-writes) for grants, limits, and the
reference-presence-only health labels.

PostgreSQL-profile source repository creation uses an Integration-owned command
and native durable replay, not a Ledger command clone. The read-only current
guard and fresh command share bounded ownership checks; completed replay never
reads repository metadata, allocates IDs, or appends audit entries.
Tenant/provider/name reuse retains original metadata and commits new rows with
their audit entry and replay state. The adapter acquires the projection fence
before its tenant serialization lock, then holds both submitted and existing
product/project identities through the outer commit. This avoids reversing the
audit and worker lock order. The HTTP transport checks raw input bounds before
trimming and requires current grants on retries. This path does not load Ledger
maps or invoke provider/network services. See [source repository creation](api.md#source-repository-creation)
for grant boundaries, validation limits and metadata-only semantics.

PostgreSQL-profile source commit recording uses the same Integration ownership
policy with a focused transaction port and native durable HTTP replay. Its
read-only guard checks current flat ownership before replay without reading
commit metadata, hashing messages or allocating IDs/timestamps. Repository
ownership and a single
commit are read through bounded projections; no clone URL or provider payload
is loaded. The projection fence precedes the repository serialization lock.
Lowercase SHA reuse returns the original record without new effects; new commit,
audit and replay state are atomic. Raw commit messages never reach the storage
or audit ports. See [source commit recording](api.md#source-commit-recording)
for hash inputs, grant boundaries and metadata-only limitations.

PostgreSQL-profile source branch upserts share the repository ownership and
serialization port with source commit recording. A bounded head-commit identity
read enforces tenant/repository binding without loading author metadata, and
share-locks those coordinates through the native replay commit. A
bounded branch read preserves creation identity while replacing current branch
state. Each execution and audit is atomic, including unchanged updates; HTTP
replay does not reapply old state. See [source branch upserts](api.md#source-branch-upserts)
for replacement defaults, concurrency and submitted-protection limitations.

PostgreSQL-profile pull-request recording uses a focused Integration command
with the shared repository ownership/locking and head-identity ports. Only the
provider default is read when omitted, after authorization; no earlier snapshots
or unrelated repository/commit metadata are loaded. Each executed call appends
a snapshot and audit atomically with replay state, even for an already-recorded
provider ID. Title/review text stays in the scoped record, not the audit. See
[pull-request recording](api.md#pull-request-recording) for metadata defaults,
replay behavior and provider-trust limitations.

All three source-write routes bypass Ledger-backed HTTP replay. Their shared
writer fence precedes tenant, repository, product/project and optional-head
locks; current grants are checked before fresh execution and completed replay.
The guards never read mutable branch metadata, previous commits/PRs or provider
defaults. The HTTP transport checks raw input bounds and cookie Origin rules.
See the
[shared replay boundary](api.md#source-write-replay-boundary).

PostgreSQL-profile GitHub/GitLab source snapshots compose those four focused
Integration commands and one read-only creation-scope guard through a focused
transaction port. Native durable HTTP replay bypasses Ledger clones. The guard
locks only current tenant/submitted-project and existing repository ownership,
without reading child metadata or calling child writes, clocks or IDs. The composition
adapter binds every child to the same transaction-scoped repositories rather
than opening nested units of work or accessing Ledger state. Late failures roll
back earlier inserts and existing branch changes. All reads retain the child
commands' bounded projections and current ownership checks; replay shares the
same transaction and adds no component or audit effects. Submitted provider
labels are not promoted to verified origin. The HTTP transport bounds all raw
nested input before trimming, validates shape and business input before replay,
and requires current grants and cookie Origin protection. Local evaluation uses
the same PostgreSQL-backed services. See
[provider source snapshots](api.md#provider-source-snapshots) for optional
component defaults, response compatibility and trust limitations.

PostgreSQL-profile deployment-environment creation uses an operations-owned
command with tenant/product grants and bounded parent/name reads. The
product-row lock serializes creation and original-row reuse without blocking
foreign-key readers; environment and audit append commit together with replay
state. Native HTTP uses durable execution rather than Ledger replay/refresh.
Current tenant/product grants are checked on every retry without name reuse,
metadata, clocks or IDs; the shared writer fence precedes ownership locks held
through the outer commit. Durable creation/reuse timestamps use UTC microsecond
precision. See
[deployment environment creation](api.md#deployment-environment-creation)
for input bounds, identity reuse and the metadata-only boundary.
Deployment-event recording also uses an Operations-owned command and bounded
transaction-scoped identity reads. The only cross-context write is the ADR 0003
fixed-shape deployment evidence capability: an Evidence-owned writer prepares
the versioned commitment and audit entry in the same transaction as the event.
No Ledger aggregate or arbitrary evidence mutation is exposed to the command.
Native HTTP checks current parent, artifact and rollback ownership/grants on
every retry, without private metadata or new evidence generation during replay.
Its locks remain held through the event/evidence/audit/replay commit. Both
profiles use strict raw-bounded input and cookie-Origin protection; local memory
remains nondurable. Startup composition and other wrappers still need migration.
See [deployment event recording](api.md#deployment-event-recording) for
authorization, timestamp precision and atomic replay semantics. EVY-906 owns
the compatible transition from this synchronous exception to a durable saga.

GitHub OIDC subject metadata can be captured, and stored OIDC/SAML identity links can be verified against tenant metadata. OIDC provider records can include public JWKS material for local EdDSA or RS256 ID-token signature and claim verification, and SAML provider records can include PEM signing certificates for local assertion signature and claim verification. Trust material can be rotated without recreating the provider, and OIDC public JWKS can be refreshed from discovery metadata. SSO credential exchange can issue bearer session secrets plus HttpOnly cookies for browser clients after local OIDC/SAML verification. Live provider management API verification, browser redirect/callback orchestration, and external group synchronization remain trust boundaries outside those records. Collector supply-chain records track pinned collector versions with signature, SBOM, and scan evidence where available; commercial and marketplace collector definitions add extension metadata without granting provider trust.

Air-gapped import-bundle workflows preserve the same tenant-scoped import path after controlled transfer. Object-retention policy APIs record tenant-scoped retention intent and, when the S3/MinIO object-store adapter is configured, verify bucket versioning plus default object-lock mode and duration. Policies can also name a tenant-prefixed sample object key for object-level retention and optional legal-hold checks where the provider supports them. Those checks are evidence for the configured bucket and sample object only; WORM/object-lock enforcement, IAM policy, lifecycle rules, and deployment-specific retention review remain operator responsibilities.

## Limitations

Current API and worker source requires PostgreSQL; the former non-durable API runtime is retired. Existing local payload files are not automatically deleted or imported. S3/MinIO runtime object storage is available through the object-store port in PostgreSQL mode. Signing-provider operation receipts, an optional HTTPS signing gateway executor, built-in AWS KMS, GCP Cloud KMS, and Azure Key Vault signing executors, gateway-backed `pkcs11-hsm` mode, native PKCS#11/HSM custody profile records, OIDC discovery refresh, optional live OIDC UserInfo validation, an optional provider validation gateway, SSO credential exchange with session-scoped OIDC group-role mapping, public-transparency proof fetching, an optional transparency proof gateway, and optional worker-owned parser side effects are implemented, but native HSM module loading/execution, direct provider-specific management API clients, and external group synchronization remain deployment hardening work. Hand-tuned per-resource repository implementations remain production-readiness work. `ENV=production` additionally rejects default API-key pepper, unsupported API writer modes or replica counts above one, local plaintext signing-key mode, and bootstrap secret printing.

Evydence does not prove provider truth, scanner authority, runtime security, legal compliance, or release security by itself.
