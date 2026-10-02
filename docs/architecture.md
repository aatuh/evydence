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
Replay retains the established private `payload_ref` omission. Local-memory
mode keeps the compatibility path. The HTTP replay envelope still refreshes
Ledger projections, and remaining evidence/parser adapters and broad startup
state loading remain EVY-905 migration work.

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
The release context now has standalone product-, project-, and release-create
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
and approval HTTP now depend on a transition-only focused interface. Fresh
server instances with an empty Ledger verify the complete response metadata,
durable replay and point reads, safe current-revision conflicts, tenant and
grant denial, and rollback of state changes when update or audit insertion
fails. Local memory keeps its explicit compatibility binding. Conditional
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
promotion/rejection HTTP now uses a transition-only dependency. Fresh-server
tests with empty Ledger candidate maps verify immutable snapshot DTOs,
durable point/list reads, conditional replay, safe revision metadata, and
storage/audit rollback. Local-memory transitions retain their explicit
compatibility path.
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
Production candidate-create HTTP now uses a creation-only dependency. Fresh
empty-Ledger servers verify all snapshot fields/reference lists, durable
point/list reads and replay, downstream promotion, adversarial input, foreign
parents, removed grants, safe storage errors, and insertion/audit rollback.
No authoritative candidate cache is published. Local-memory creation keeps
its explicit compatibility binding; remaining production Ledger composition
and full-state command-view reloads are still migration work.
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
Production artifact-registration HTTP now binds that focused command through a
registration-only handler interface. Live HTTP tests use an empty Ledger with
only a unit-of-work factory: artifact creation, fresh-instance replay and reuse,
point reads, and build/evidence/container-image consumers use durable state.
Explicit local-memory mode retains the compatibility binding. A
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
the compatibility command binding. Startup loading and the outer Ledger replay
and refresh envelope remain migration work; this binding does not remove them.

Build-attestation upload orchestration now lives in the standalone Release
`BuildAttestationCommands`. Its four-read, fixed-shape transaction port rechecks
the build, parent and output-artifact coordinates before committing evidence,
attestation, audit and parser-job effects. The compatibility Release service
delegates to the same command; it does not duplicate orchestration. The DSSE
ingestion parser is independently composable from
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
The PostgreSQL HTTP profile now binds this command directly. Fresh-server HTTP
tests use uncached artifacts and cover immutable replay/reuse, current grants,
malformed input, private backend errors and atomic image/audit rollback. The
explicit local-memory profile retains its compatibility binding. The outer
Ledger replay/refresh envelope still needs migration; these checks do not
establish Ledger retirement or multi-writer support.

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
definitions, not tenant state. Installation now uses a focused risk command:
one transaction checks the tenant/slug/version key, inserts the framework and
every starter control, and appends a single installation audit attributed to
the authenticated principal. The read port returns only version existence.
Outer rollback, late control/audit failures, same-key replay, and competing
installs preserve atomicity; a different-key duplicate version conflicts.
Local-memory mode retains its explicit Ledger catalog/installation paths.
Manual framework and security-control creation now also have focused risk
commands composed solely from the active write transaction. Their readers
return tenant-owned existence bits rather than framework metadata or control
inventories; the PostgreSQL projection fence precedes parent locks and audit
appends. Framework/version and control/code uniqueness checks, current
tenant-wide administration grants, insertion, and audit share that transaction.
The commands preserve slug derivation, requirement order, applicability sorting
with duplicates, limitation order, and existing schema versions. They reject
unsupported text/index sizes and excessive list work before persistence.
PostgreSQL HTTP creation routes bind these commands directly: separate server
instances can create, replay, read, and report a framework/control without
publishing authoritative Ledger maps. Local-memory mode retains its explicit
compatibility command binding. Control-evidence linking now has a focused risk
command core with transaction-only control/subject/duplicate readers and one
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
competing duplicates. PostgreSQL HTTP evidence-link writes now bind the focused
command directly. Fresh-server tests create and list every supported subject
without publishing Ledger maps, preserve replay and natural-duplicate DTOs,
and prove link/audit rollback and safe error responses. The handler rejects
null fields and invalid decoded control IDs before they reach storage.
Local-memory mode retains its explicit compatibility path. These boundaries
do not retire production Ledger startup or its remaining maps.
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
preservation. These are storage-port tests, not route or production proof.
Remaining query/worker/legacy-writer migration, focused command composition,
and HTTP binding remain EVY-905 work; the current decision route still uses its
compatibility service. PostgreSQL backup commitments now use an explicit v2
profile that includes supersession history; the immutable v1 allowlist and
digester remain available for historical reproduction. See
[verification results](reference/verification-results.md#tenant-scoped-backup-manifest-generation).
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

PostgreSQL-profile source repository creation uses an Integration-owned command
with bounded ownership reads and a separately authorized existing-row read.
Tenant/provider/name reuse retains original metadata and commits new rows with
their audit entry and replay state. The adapter acquires the projection fence
before its relational serialization lock; this avoids reversing the audit and
worker lock order. It does not load Ledger maps or invoke provider/network
services. See [source repository creation](api.md#source-repository-creation)
for grant boundaries, validation limits and metadata-only semantics.

PostgreSQL-profile source commit recording uses the same Integration ownership
policy with a focused transaction port. Repository ownership and a single
commit are read through bounded projections; no clone URL or provider payload
is loaded. The projection fence precedes the repository serialization lock.
Lowercase SHA reuse returns the original record without new effects; new commit,
audit and replay state are atomic. Raw commit messages never reach the storage
or audit ports. See [source commit recording](api.md#source-commit-recording)
for hash inputs, grant boundaries and metadata-only limitations.

PostgreSQL-profile source branch upserts share the repository ownership and
serialization port with source commit recording. A bounded head-commit identity
read enforces tenant/repository binding without loading author metadata. A
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

PostgreSQL-profile GitHub/GitLab source snapshots compose those four focused
Integration commands through a four-method transaction port. The composition
adapter binds every child to the same transaction-scoped repositories rather
than opening nested units of work or accessing Ledger state. Late failures roll
back earlier inserts and existing branch changes. All reads retain the child
commands' bounded projections and current ownership checks; replay shares the
same transaction and adds no component or audit effects. Submitted provider
labels are not promoted to verified origin. See
[provider source snapshots](api.md#provider-source-snapshots) for optional
component defaults, response compatibility and trust limitations.

PostgreSQL-profile deployment-environment creation uses an operations-owned
command with tenant/product grants and bounded parent/name reads. The
product-row lock serializes creation and original-row reuse without blocking
foreign-key readers; environment and audit append commit together with replay
state. It does not build Ledger maps. See
[deployment environment creation](api.md#deployment-environment-creation)
for input bounds, identity reuse and the metadata-only boundary.
Deployment-event recording also uses an Operations-owned command and bounded
transaction-scoped identity reads. The only cross-context write is the ADR 0003
fixed-shape deployment evidence capability: an Evidence-owned writer prepares
the versioned commitment and audit entry in the same transaction as the event.
No Ledger aggregate or arbitrary evidence mutation is exposed to the command.
See [deployment event recording](api.md#deployment-event-recording) for
authorization, timestamp precision and atomic replay semantics. EVY-906 owns
the compatible transition from this synchronous exception to a durable saga.

GitHub OIDC subject metadata can be captured, and stored OIDC/SAML identity links can be verified against tenant metadata. OIDC provider records can include public JWKS material for local EdDSA or RS256 ID-token signature and claim verification, and SAML provider records can include PEM signing certificates for local assertion signature and claim verification. Trust material can be rotated without recreating the provider, and OIDC public JWKS can be refreshed from discovery metadata. SSO credential exchange can issue bearer session secrets plus HttpOnly cookies for browser clients after local OIDC/SAML verification. Live provider management API verification, browser redirect/callback orchestration, and external group synchronization remain trust boundaries outside those records. Collector supply-chain records track pinned collector versions with signature, SBOM, and scan evidence where available; commercial and marketplace collector definitions add extension metadata without granting provider trust.

Air-gapped import-bundle workflows preserve the same tenant-scoped import path after controlled transfer. Object-retention policy APIs record tenant-scoped retention intent and, when the S3/MinIO object-store adapter is configured, verify bucket versioning plus default object-lock mode and duration. Policies can also name a tenant-prefixed sample object key for object-level retention and optional legal-hold checks where the provider supports them. Those checks are evidence for the configured bucket and sample object only; WORM/object-lock enforcement, IAM policy, lifecycle rules, and deployment-specific retention review remain operator responsibilities.

## Limitations

The in-process store requires `EVYDENCE_RUNTIME_PROFILE=local_memory` and an unset `EVYDENCE_DATABASE_URL`; it is non-durable and cannot run the worker. Explicitly configured local filesystem payload files may remain after in-memory metadata is lost. S3/MinIO runtime object storage is available through the object-store port in PostgreSQL mode. Signing-provider operation receipts, an optional HTTPS signing gateway executor, built-in AWS KMS, GCP Cloud KMS, and Azure Key Vault signing executors, gateway-backed `pkcs11-hsm` mode, native PKCS#11/HSM custody profile records, OIDC discovery refresh, optional live OIDC UserInfo validation, an optional provider validation gateway, SSO credential exchange with session-scoped OIDC group-role mapping, public-transparency proof fetching, an optional transparency proof gateway, and optional worker-owned parser side effects are implemented, but native HSM module loading/execution, direct provider-specific management API clients, and external group synchronization remain deployment hardening work. Hand-tuned per-resource repository implementations remain production-readiness work. `ENV=production` rejects the in-process store, default API-key pepper, unsupported API writer modes or replica counts above one, local plaintext signing-key mode, and bootstrap secret printing.

Evydence does not prove provider truth, scanner authority, runtime security, legal compliance, or release security by itself.
