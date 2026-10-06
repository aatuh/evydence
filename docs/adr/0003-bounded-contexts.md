# ADR 0003: Bounded Context Ownership And Dependency Rules

Status: accepted. EVY-902 implemented the context-owned model layer described
below. EVY-903 implemented focused Identity, Release, and Evidence command
services. EVY-904 has added focused Decision, Package, and Verification
services and moved their migrated HTTP workflows behind context-specific
interfaces. The composition-root and database-backed query migration and
legacy-facade retirement remain assigned to EVY-905 and EVY-906.

## Context

Customer-package creation now owns its orchestration in Package's focused
`CustomerPackageCommands`. One snapshot-reader port supplies public manifest
inputs and policy; flat transaction ports permit only current-scope
authorization, selected-policy reads, package insertion, and audit append.
The legacy Package service delegates to these same rules rather than retaining
a second creation implementation. Bounded JSON normalization retains existing
collection/public-profile shapes with owned mutable slices; opaque/custom
metadata uses the sanitized public JSON tree. A native PostgreSQL write adapter
takes the common worker/audit fence before tenant/product/release/policy locks
and joins the durable executor's active unit of work. Focused tests cover rollback,
outer-commit failure, and lock-order behavior using an immutable snapshot
fixture, not a production reader.
The native reader's private catalog projection now selects public tenant,
organization, product, release, evidence-reference, and artifact metadata in a
caller-owned repeatable-read transaction. It validates evidence parent
associations inside the selected tenant/product, binds build-output artifact
digests, and rejects row/byte overflow before transferring selected metadata.
It neither loads Ledger state nor acquires the writer fence on its read
connection. This catalog component is tested against live PostgreSQL as part
of the complete snapshot reader. Its evidence component selects SBOM,
scan, VEX, and API-contract/diff summaries in that same caller-owned view and
shares the metadata byte budget. It excludes raw findings, components,
documents, payload locations, VEX authors, and private operation extensions;
malformed public list/count fields are rejected before metadata transfer.
Operation normalization is shared with the explicit local reader. Legacy
product ownership is resolved from coherent source parents, or from the
contract's declared product when optional source coordinates are absent.
Product-only document summaries remain unreleased-only and product-scoped;
contract diffs may reference other releases of that same product. Live tests
cover these compatibility cases, unambiguous artifact binding, and concurrent
commits. The private governance component now selects active, customer-visible
decisions, product/release approvals, approved unexpired exceptions and waivers,
and scoped answer-library metadata. It uses the caller's fixed generation time
and shared byte budget in that same read-only view. Source findings and optional
evidence, SBOM, VEX, control, policy, and supporting-reference parents must resolve
inside the selected scope. Tenant-wide reusable answers retain their existing
meaning, but every citation must belong to the package scope; unrelated citations
and incoherent parents are excluded. Decision fields, optional omissions, ordering,
and profile selection are shared with the explicit local reader. Internal notes,
approver identities, source payloads, private reference extensions, and control
objectives are not selected. Live tests cover expiry boundaries, append-only
supersession, reference kinds, concurrent commits, row/byte bounds, malformed
metadata, and reads while a command holds the writer fence. The private provenance
component now selects public build/attestation metadata in that same view and
budget. Builds require coherent tenant/product/project/release and optional
collector parents; registered outputs require same-tenant artifacts with matching
digests. Unregistered digest-only outputs retain their existing public meaning.
Attestations additionally require their typed evidence source to match the build,
project, product, release, payload hash/size, and storage reference, without
selecting source identity, raw payloads, storage locations, builder identity, or
signature bytes. Public output sorting is shared with local memory. Null-list and
timestamp shapes, recorded verification states, and the existing requirement for
an included build before attestation inclusion are preserved. This metadata
projection does not itself verify an attestation or signature. The private
selected-policy component reads only the tenant-owned redaction profile in
that same view and budget. Its bounded decoder is shared with the write-time
policy comparison, preserving exact microsecond timestamps, list ordering,
and optional descriptions. Only the write path takes the mutation fence and
policy row lock. Invalid array shapes, oversized values, and out-of-range
timestamps are rejected before policy JSON crosses the database driver.
The private readiness component reuses Risk's fact reader and canonical
evaluator in that same view, using the fixed generation time for exceptions,
package expiry, and signing-key validity. Readiness and anomaly presence facts
now share the catalog/provenance parent checks: the selected tenant/product/
release must agree with source evidence, build projects, optional collectors,
registered outputs, and typed attestation payload bindings. Parsed scans must
have a coherent typed source. Current decision handling and exported decision
summaries require an unambiguous finding with matching vulnerability/component;
an unrelated successor cannot inherit historical handling. Exception controls
and optional findings must resolve inside the selected scope before contributing
handling or missing identifiers. Malformed unrelated scans do not enter readiness
validation. These are recorded facts, not fresh provider verification, and the
Risk evaluator remains the single policy owner. Missing decision, exception, and
package identifiers share pre-transfer row/byte bounds; package product and
release ownership must agree. The final public check representation is
charged to the shared metadata budget without persisting an evaluation or
receipt. Product-only packages retain no release-readiness checks. The private
audit-summary component uses Verification's canonical, sequence, predecessor,
subject-bound signature, and historical-key checks over bounded read-only
database pages. It takes no mutation fence or row lock. Canonical audit details
stay inside the verifier; only the existing aggregate result, count, head hash,
and public integrity check reach the package. Private signing-key ciphertext is
never selected. Source inspection has its own 8 MiB budget and JSON structure
limits, while only the public summary charges the shared manifest budget.
The aggregate does not prove external anchoring or third-party log inclusion.
The private verification-metadata component now selects release-bundle,
verification-receipt, and Cosign-assessment summaries in that same view and
shared budget. Receipt subjects must resolve through coherent tenant/product/
release ownership; attestations reuse the provenance source checks, while
artifact signatures and Cosign assessments use the catalog's selected artifacts.
Cosign signature/digest and optional image coordinates must agree. Bundles with
unrelated or missing signature/key parents are excluded as whole records, not
silently trimmed. Check formatting is shared with the local reader; recorded
states, profile fields, ordering, optional omissions, and nil-list shapes are
preserved without upgrading assurance or making fresh provider/cryptographic
claims. Only known check/profile fields cross the driver; bundle manifests,
private extensions, payload locations, signature bytes, certificate identities,
and private keys are not selected. Subject inventories, public row/list counts,
metadata bytes, JSON types, and timestamps are bounded before transfer. The shared
reader materializes both the selected page and its budget aggregate; an actual
query-plan regression checks that the aggregate runs once rather than once per
output row, retaining the same exact-capacity and overflow assertions. The private
retention component now shares a bounded public fact decoder with release-bundle
reads and uses Verification's canonical proof renderer at the fixed generation
time. Observations remain tenant-wide metadata after package-root validation;
product or release ownership of storage settings is not inferred. Only location
presence markers and known check fields cross the driver, not object prefixes,
sample object keys, provider bucket names, or private check extensions. Source
detail counts, policy rows, bytes, array shapes, scalar sizes, and timestamps are
bounded before transfer; canonical expiry checks and proof-text growth also
charge the shared manifest budget. The reader takes no writer fence, calls no
provider, and persists no observation or receipt. Its recorded states and explicit
non-claims are unchanged. The native `CustomerPackageCreationSnapshotReader`
now composes the selected profile and every section in one read-only
repeatable-read transaction with a shared byte budget and fixed generation
time. A separate whole-snapshot JSON limit includes static container/limitation
overhead before publication. Catalog and parsed-summary timestamp projections
also reject non-finite dates or UTC years outside 1–9999 before transfer. The
composition root must inject canonical hashing
and signature verification; there is no Ledger or memory-mode fallback. Begin,
section, cancellation, or commit failure returns no partial view, with bounded
cancellation-independent rollback cleanup.
PostgreSQL API wiring now binds this reader, the focused creation command and
durable executor to the existing HTTP route. Current grants, coherent roots and
selected policy are rechecked before reservation/replay under the writer fence;
package, audit and successful replay commit together. Restart replay does not
rebuild evidence or apply a later redaction policy, and exact stored JSON numbers
survive replay/redaction. Live HTTP tests cover wrong ownership, revoked grants
and sessions, expired-original replay, private-source exclusion, and
insert/audit/replay/commit rollback. Invalid command execution can retain only
the standard safe failed-key tombstone. Both profiles share strict request and
cookie-mutation checks; explicit local memory retains its nondurable reader.
Broad API startup still reaches Ledger. See
[customer-package creation](../api.md#customer-package-creation) for limits and
the remaining boundary.

Package-owned `RedactionProfileCommands` now creates tenant-wide redaction
definitions through flat insert/audit ports. PostgreSQL wiring fences and locks
only the actor's tenant identity, joins the durable replay transaction, and
does not read existing profiles, evidence, manifests, or signing material.
Current tenant-wide package-write authority is checked before replay. The local
Package service delegates to the same preset, normalization, and record rules;
its broad transaction adapter is compatibility-only. Broad API startup remains
separate EVY-905 work. See
[profile creation](../api.md#redaction-profile-creation) for bounds and malformed
request compatibility limits.

Authenticated customer-package archive download now reuses Package-owned
`AccessCommands` for selected-package ownership, expiry, count, and audit,
then renders only the committed public record. PostgreSQL takes the common
worker/audit fence before the package row lock, matching portal access and
avoiding the reverse lock order. The existing bounded record-only archive
renderer has no Ledger authority. Access auditing is not a delivery receipt:
rendering or network failure after access commit does not undo that audit. See
[archive download](../api.md#customer-package-archive-download).

Experimental-owned `SaaSProfileCommands` records configuration intent using
flat two-tenant-key, insert and audit ports, with exact instance authority.
The composition root binds current roots, actor-tenant projection fencing and
atomic profile/audit/replay writes without exposing Ledger state or extending
the mixed Future interface. Local memory shares raw-value hashing and record
rules. The cross-tenant admin reference is deliberate instance authority, not
tenant delegation; these records do not enforce hosted deployment isolation.

Verification-owned `SigningOperationCommands` uses flat bounded provider,
subject-coordinate, executor, insert and audit ports. The runtime supplies the
configured executor; no service locator or mixed Future interface expansion
enters the core. Current SQL root/provider locks and the projection fence cover
receipt/operation/audit/replay commit. Canonical hashing and receipt validation
are shared with explicit local memory. Database atomicity does not imply
rollback or exactly-once execution at an external signing provider.

Experimental-owned `AnomalyCommands` now binds flat subject-coordinate,
release-fact and insert ports without extending the mixed Future repository.
Adapters reuse fixed-size readiness SQL predicates, but no full readiness
snapshot enters the command. The composition root supplies the existing
resolved report-grant policy through a transport-neutral port. Pure signal
generation is shared with local memory; this does not graduate anomaly reports
from experimental status or add checks for non-release subjects.

Package-owned `PDFReportCommands` owns minimal title-only report packaging,
not an evidence renderer. Flat coordinate, staged-payload and insert ports
bind PostgreSQL creation without extending `FutureExtensionsRepository`.
The composition root couples lifecycle metadata, finalizer job, report, audit
and replay through one unit of work. Graph/PDF commands share pure
product/release validation; the legacy helper is local compatibility only.

Package-owned `GraphSnapshotCommands` now materializes durable evidence
adjacency through flat coordinate, root-label, selected-evidence and insert
ports. The PostgreSQL concrete repository implements these ports without
adding methods to `FutureExtensionsRepository`. A pure Package builder is
shared with explicit local memory; normalized-JSON hashing remains an injected
adapter. Remaining experimental peripherals do not gain graph authority.

Package-owned `PortalAccessCommands` and `PortalTokenCommands` now own durable
portal issuance, revocation, NDA acceptance, failure limits and audited package
access. Their selected-row repository and credential ports do not expose Ledger
state. Prefix lookup index `20261003000100_customer_portal_token_lookup` belongs
to Package and reporting. The remaining local identity facade and record-only
archive renderer are compatibility utilities, not production token authority.

The implementation has useful transaction-scoped repository ports, but the
commands and queries not yet migrated to focused services remain behind
`internal/app.Ledger`. The legacy `internal/domain` package also remains the
JSON and persistence compatibility surface while callers migrate. Without
explicit context-owned models and checked adapters, those transition paths make
ownership hard to see and permit accidental broad access to unrelated state.

[ADR 0001](0001-database-authoritative-transactions.md) remains the transaction
contract: one production command owns one PostgreSQL unit of work, including
its durable domain mutation, audit entry, idempotency record when supplied, and
outbox job. Bounded contexts must preserve that contract; they are not a reason
to introduce distributed writes or publish an event before its transaction
commits.

## Decision

Evydence will use the contexts below. A context owns its business rules,
domain types, command service, query model, migration stewardship, and
repository port. A route may call only its owning context's application
service. Contexts exchange identifiers and committed, versioned integration
events rather than importing each other's aggregates or writing each other's
repositories.

### Implemented model and command boundaries

Integration-owned source-repository creation now uses native durable replay.
The shared read-only guard checks current submitted and existing ownership,
without reading private repository metadata, and its writer fence and parent
locks join the replay transaction. New repository, audit and replay records
commit atomically; completed replies preserve their original public JSON.
Explicit local memory shares raw input bounds and current grants but retains
its nondurable compatibility store. This does not remove broad API startup or
the remaining command wrappers. See
[source repository creation](../api.md#source-repository-creation).

Source commit recording, branch replacement and PR snapshot appends also use
native durable HTTP replay. A shared Integration ownership guard holds current
tenant/repository/parent and optional-head coordinates through the outer
transaction without private metadata reads, clocks or identifiers. Distinct
commit-reuse, branch-replacement and append-only PR behavior remains in the
owning command; each domain/audit/replay effect is atomic. Input bounds precede
trimming and cookie writes require Origin protection. Local memory shares
current guards but retains its nondurable store; production startup and the
CI HTTP wrappers remain migration work. See the
[source-write replay boundary](../api.md#source-write-replay-boundary).

GitHub/GitLab source-snapshot HTTP routes now use the same native durable replay
boundary. Their focused transaction exposes four child commands and one
read-only repository-creation authority guard; all ports bind to the same
repositories. The guard holds current tenant/submitted/existing ownership
through the outer commit without child metadata, writes, clocks or IDs. Fresh
children enforce actual derived IDs and their own immutable/replacement/append
semantics. Raw nested input is bounded before any composed write; completed
replay preserves original public JSON without reapplying branch state. Local
memory retains its nondurable workflow. This is submitted metadata, not provider
verification; broader startup and CI paths remain EVY-905 work. See
[provider source snapshots](../api.md#provider-source-snapshots).

Release-owned build creation also uses native durable HTTP execution. Its
read-only guard locks current tenant/product/project/release and supplied
artifact ownership coordinates through the outer replay transaction and
rechecks current grants without versions, digests, build metadata, clocks or
IDs. Fresh creation retains its bounded digest checks and derived, explicitly
unverified CI identity. Build, caller audit and replay completion are atomic;
current ownership/grant denial prevents disclosure of a historical response.
Local memory shares raw bounds and current guards but remains nondurable.
API startup loading and other workflows are still transitional. See
[build creation](../api.md#build-creation).

Build-attestation HTTP upload uses native durable execution too. A bounded
ownership-only guard locks the current build, parents and supplied output
artifacts through replay and checks current grants without invoking parsing,
staging, clocks or IDs. Fresh ingestion still uses the fixed-shape Evidence
capability documented below; this change does not replace it with a new saga.
The transport shares the existing 20 MiB application limit and upload budget,
and omits private object coordinates from both fresh and replayed public
responses. Internal payload lifecycle and worker-pending records remain intact.
Local memory retains its explicit nondurable store. See
[attestation upload](../api.md#build-attestation-upload).

Product/project/release creation now binds native durable HTTP execution too.
A shared ownership-only port checks current tenant/product creation authority
through the outer transaction without metadata, uniqueness reads, clocks or
IDs. Fresh commands retain unique product slugs, non-unique project names and
unique per-product release versions, alongside the existing slug-drift checks.
Raw input normalization is shared with the explicit local profile. This does
not retire startup aggregate loading or remaining command wrappers. See
[catalog creation](../api.md#1-create-product-project-and-release).

Artifact and container-image registration use native durable HTTP execution,
with Release-owned read-only replay guards instead of Ledger cloning/refresh.
Artifact guards select only the current tenant/digest identity and grants;
image guards select flat natural-key identity and current submitted/existing
artifact ownership and grants. They do not load private metadata, reapply image
artifact digests or allocate IDs. The common writer fence precedes relational
locks held through the outer transaction. Fresh immutable reuse and record,
audit and replay atomicity remain. Both profiles share raw input/origin rules;
local memory remains nondurable. Startup aggregate composition is still
transitional. See [registration behavior](../api.md#container-image-registration).

Release-candidate creation uses the Release command's native durable execution
and ownership-only replay guard. Current parent/reference coherence and grants
are checked without existing candidate documents, private metadata or hashing.
The shared writer fence precedes locks held on selected tenant, parent, reference
and source-evidence rows through snapshot/audit/replay commit. The bounded SQL
validator returns one boolean and preserves duplicate snapshot references.
Local memory shares raw input and origin rules but remains nondurable. Startup
is still transitional. See [API behavior](../api.md).

Release freeze/approval and candidate promotion/rejection use native conditional
durable execution too. Ownership-only guard ports select current tenant, subject
and release/product parents without lifecycle state, revision or private metadata.
The common writer fence precedes locks held through state/audit/replay completion.
Fresh revision/lifecycle checks remain; historical delivery does not rerun them.
The existing canonical `If-Match`-plus-body fingerprint is retained. Local memory
shares strict raw input/origin rules with nondurable replay. This does not retire
startup or unrelated command wrappers. See
[conditional transitions](../api.md#conditional-release-transitions).

EVY-902 created tag-free, standard-library-only domain packages at
`internal/{identity,release,evidence,risk,package,verification,operations,integration,experimental}/domain`.
Together they own all 142 models assigned in the table below. Schema and policy
constants now originate in those packages; `internal/domain/schema_context.go`
re-exports them only for source compatibility.

Stable lifecycle behavior uses validated named values in the context model for
release and release-candidate state, evidence lifecycle action, vulnerability
decision status, release-bundle state, verification result and signing-key
status, incident status, and collector status. Normal constructors and parsers
reject empty or unknown values, and release transitions reject invalid order.
Verification profile normalization, conservative result aggregation, profile
policy definitions, and signing-key historical-validity evaluation are owned by
the verification context. Signing-key core metadata deliberately excludes
private key bytes.

EVY-903 added transport-neutral command services under
`internal/{identity,release,evidence}/app`. They depend on focused reader,
repository, transaction, authorization, clock, identifier, object-ingestion,
audit, and outbox ports. The HTTP handlers for the 15 Identity, 21 Release, and
27 Evidence operations now depend on context-specific interfaces rather than
on `*app.Ledger`. Temporary Ledger-backed adapters map the legacy DTOs and
preserve the existing idempotent command scope until the EVY-905 composition
root migration. EVY-904 added focused `internal/{risk,package,verification}/app`
services for decisions, policy readiness, customer and release packages,
evidence bundles, CRA HTML and custom report materialization, signing-key
lifecycle, and verification receipts. Committed
read snapshots and transaction ports keep these services independent of the
legacy Ledger maps; the compatibility adapters still translate persisted and
HTTP DTOs.

EVY-905 is in progress. PostgreSQL-backed point reads for products, projects,
releases, builds, artifacts, and release candidates use release-catalog queries. The
API's read dependencies are now assembled by `internal/platform/wiring.BuildAPIReadServices`
from the same validated runtime that opens API and worker infrastructure; the
API entry point supplies HTTP limits and bootstrap configuration separately.
This centralizes the durable read ports but does not yet remove the production
Ledger compatibility surface or finish all database-backed queries. Release
candidate pages filter current product/release grants before the SQL limit;
artifact point reads resolve current evidence/build associations in the same
tenant-filtered statement before granting scoped human access;
deployment point and list reads use operations-owned queries. Deployment list
visibility and keyset limits are applied in PostgreSQL; release and environment
joins must resolve to one tenant-owned product before grant evaluation.
Ordinary evidence point reads use a tenant-scoped, snapshot-consistent query.
Ordinary evidence lifecycle-event lists use one tenant-scoped snapshot for the
evidence authorization point and bounded SQL keyset page; worker-owned evidence
retains the provenance-checked Ledger projection. Response redaction remains
at the API boundary.
OpenAPI contract point reads verify their source evidence, product, and optional
release in one tenant-filtered statement before applying human resource grants;
local-memory mode retains the Ledger reader.
Parsed SBOM point reads also verify current source evidence, release, and
artifact parentage and require sole artifact/source-evidence subject agreement in
one tenant-filtered statement before applying human
resource grants. They preserve accepted, not-yet-parsed rows and return one
document with its stored components when available, not a
tenant-wide projection; local-memory mode retains the Ledger reader.
Vulnerability-scan point reads now use a repeatable-read tenant snapshot to
validate the scan's source evidence, current release/product ownership,
parsed finding identities, and human resource grants. Accepted pending scans
retain their empty parser fields; local-memory mode retains the Ledger reader.
The PostgreSQL worker reuses the source-validated SBOM, vulnerability-scan, and
OpenAPI contract point readers to hydrate only a claimed parser subject.
Parser writes remain lease-fenced. Signing jobs reuse the tenant-scoped release
bundle point reader, and verification jobs read one tenant- and subject-bound
result. Attestation jobs read one source-validated, tenant-scoped build
attestation before lease-fenced replay. VEX jobs use a claimed-document and
same-release dependency snapshot, plus only the matching acceptance audit
entry and tenant audit tip. Operator replay uses a focused source/marker/tip
read. Both durable append transactions still check full committed sequence
and predecessor continuity before rebasing pending entries. API startup
retains a broad compatibility read pending EVY-905.
OpenAPI contract point reads require the linked source evidence to have the
`openapi_contract` type.
VEX document and import-report point reads validate tenant-owned source,
release, artifact subject, and report/document identity under one repeatable-
read snapshot. Ambiguous reports fail closed; local-memory mode keeps its
compatibility reader.
SBOM component pages now expand tenant-owned JSONB component arrays in a
repeatable-read PostgreSQL snapshot, apply current resource grants before the
keyset limit, and transfer only a bounded page to the API. This removes the
production Ledger's 500-component preselection cap, but does not provide a
component-level search index; local-memory mode retains the cap. The page
query applies the same source-type, release, artifact-subject, and optional
build/deployment parent checks as the parsed SBOM point read before expansion.
Control-evidence lists now use a risk-owned query service in PostgreSQL mode:
one SQL statement resolves current control/framework/subject ownership and
applies actor grants before keyset pagination. Broken parent relationships are
excluded. The local-memory profile retains the Ledger compatibility reader;
the remaining production Ledger reads still belong to EVY-905.
Exception lists also use a risk-owned PostgreSQL query. One repeatable-read
snapshot resolves an optional release filter and applies current tenant,
product, and release grants before the bounded keyset page. Local-memory mode
retains the compatibility reader.
Vulnerability-decision history also uses a risk-owned PostgreSQL query. It
validates filtered product/release coordinates in one snapshot, applies current
evidence-read grants and filters before keyset pagination, and never selects
tenant-internal notes. Local-memory mode retains its compatibility reader.
The customer-safe vulnerability-decision summary uses a separate risk-owned
read snapshot: it checks the release and `report:read` grant before loading
only active, customer-visible decisions for that release. The versioned report
wording and field redaction are shared with the local-memory compatibility
path.
Worker-owned evidence types still use the Ledger projection so their parser,
document, and audit provenance checks are not bypassed. Source-repository
pages use an integration-owned query that validates current project/product
parentage and filters grants before the keyset limit. Collector inventory
pages use an integration-owned tenant-scoped query; human sessions
need a current tenant-level `collector:read` grant, while issued credentials
remain scope-bound. The query does not select credential secrets or hashes.
Commercial collector-definition pages use the same integration-owned tenant
authorization boundary and a SQL-side keyset limit.
Experimental marketplace collector metadata pages and health points now use
tenant-filtered PostgreSQL reads, with current evidence-reference ownership
resolved in one statement. Human sessions need a current tenant-level
`collector:read` grant in both runtime profiles. These presence checks do not
prove package safety, marketplace trust, or provider endorsement.
Marketplace collector creation now uses Experimental-owned commands with
flat tenant/signature/SBOM/scan ID ports. PostgreSQL composition takes the
actor-tenant mutation fence before current-reference share locks and commits
metadata, manifest-bound audit and replay together. The command never loads
signature/key bytes, components or findings. Both runtime profiles require
tenant-wide human administration and current ownership before replay. This
records package metadata only; broad Ledger startup retirement still requires
migration. Public-transparency creation/publication now belong to focused
Experimental metadata commands with flat tenant/log/checkpoint/batch/root
ports. PostgreSQL fences the actor tenant before share-locking the owned root
chain and commits metadata, audit, and replay together, without loading log
keys or leaf arrays. Explicit local memory shares the pure hash/record rules.
Operator proof verification now uses focused Experimental commands and a
bounded owned entry/root-chain projection. The actor-tenant fence precedes
entry/root locks held through assessment/audit/replay commit. Previous proof
commitments participate in same-state compare-and-swap. Local memory shares
pure proof/hash rules; old diagnostic arrays are not command authority.
Neither this result nor metadata creation authenticates public-log trust.
Focused Experimental proof fetching now uses a bounded entry/endpoint reader
and a provider port carrying proof fields only, not provider diagnostics.
The configured runtime fetcher, current source locks and actor-tenant fence
cover the bounded provider call and assessment/audit/replay commit. Shared
snapshot comparison and local proof/hash rules prevent stale-source assessment.
Provider observation is not rolled back by database failure. Startup retirement
remains separate EVY-905 work.
Governance framework pages, control points, and the static starter-template
catalog use risk-owned queries. Template listing does not read tenant state.
Installation now binds focused Risk commands and native durable replay. The
read-only current-tenant administration/existence guard takes the common writer
fence before the tenant share lock and joins the outer replay transaction.
Installed metadata and duplicate-version reads are not replay authority; fresh
installation alone checks the version key and atomically appends the framework,
all starter controls, principal audit and replay response, without a job.
Explicit local memory retains compatibility storage and nondurable replay.
A control must resolve to a framework in the same tenant before it is returned.
Manual framework/control creation also binds focused Risk commands with native
durable replay. Flat current tenant/parent guards retain share locks through
commit without consulting version/code duplicates or installed metadata on
replay. Fresh records, principal audits and replay results commit atomically,
without a job or Ledger projection. Both profiles share bounded raw-input
normalization; local memory keeps compatibility storage and nondurable replay.
Control-evidence linking now also uses native durable replay. Shared Risk
orchestration resolves current control/framework/subject coordinates and grants
without duplicate metadata reads on replay. The actor-tenant writer fence and
tenant/control/framework share locks survive outer commit; fresh link, audit
and replay writes are atomic. Artifact grants remain association-filtered and
parsed sources retain their relational ownership checks. Local memory keeps
local-map reference semantics and nondurable replay, not those PostgreSQL
source/projection guarantees. See [control-evidence linking](../api.md#control-evidence-linking).
Signing-provider and DSSE trust-root creation now use Verification-owned
commands with current tenant-wide administration before native durable replay.
The Identity adapter supplies only a tenant-existence/mutation guard: the
common tenant writer fence precedes tenant/audit locks and survives through
metadata, audit and replay commit. These routes never clone or read Ledger,
load credential inventories, or contact a signing provider. Both runtime
profiles share strict bounded decoding and public-metadata normalization;
explicit local memory retains nondurable replay. Registration establishes
neither key custody nor authenticated builder identity. Broad API startup
and other compatibility-backed operations remain EVY-905 work. See
[trust configuration](../api.md#signing-provider-and-dsse-trust-configuration).
Object-retention creation and verification also use Verification-owned commands
with native durable replay. Current tenant-wide `admin`/`verify:read` authority
and the actor-tenant existence guard precede reservation; verification locks
only the owned policy ID before replay, never changed receipt metadata. The
common writer fence precedes tenant/policy/audit locks and survives through
the outer commit and any fresh provider observation. Fresh commands retain
bounded policy reads, complete-snapshot compare-and-swap, and atomic receipt,
audit-hash and replay writes. A validated public retention DTO may preserve
its safe tenant-prefixed sample key in replay; arbitrary storage references
and diagnostic secrets keep the generic denylist. Provider observations are
not rolled back by database failure and local intent is not enforcement proof.
Explicit local memory retains nondurable compatibility storage. API startup
and the remaining command wrappers still require EVY-905 migration. See
[retention commands](../api.md#object-retention-policy-creation-and-verification).
Package-owned release-bundle creation now uses native durable replay with a
flat current release/product guard. The actor-tenant fence precedes parent
share locks held through bundle/signature/audit/job/replay commit. Completed
replay does not read a manifest snapshot, select signing material, or sign
again. Fresh creation retains the bounded repeatable-read snapshot and exact
local Ed25519 format; its transaction revalidates public key lifecycle and the
signature. Explicit local memory keeps its compatibility store with a narrow
current-root/grant check. Fresh manifests sanitize private fields and sensitive
text before hashing; a hash-bound, versioned creation projection preserves only
the public retention-location presence flag during replay. Generic redaction
is unchanged and old redacted replies are not backfilled. This does not retire
API startup or prove current key
validity, evidence completeness, release security, or legal compliance. See
[bundle creation](../api.md#signed-release-bundle-creation).
Operations-owned legal-hold and retention-extension appends now use narrow
transactions with flat tenant/subject locks, current tenant-wide administration,
and native durable replay. The actor-tenant fence precedes subject share locks,
held through marker/audit/replay commit. No subject metadata, payload bytes,
provider retention state, or Ledger clone is read. Explicit local memory reuses
the input normalizers with its compatibility store. Extension freshness is a
new-command rule, not a replay-expiry rule. The temporary Governance persistence
bridge exposes only the two append methods to this service; neither marker is
storage enforcement or a legal conclusion. See
[retention markers](../api.md#legal-holds-and-retention-extensions).
Signing-key pages use a verification-owned tenant-scoped query that selects
only public lifecycle metadata and applies a keyset limit in PostgreSQL;
human sessions need a current tenant-level `verify:read` grant.
Signing-key rotation/revocation now use native durable HTTP execution, current
tenant-wide `keys:admin` guards and atomic lifecycle/audit/replay transactions.
The shared writer fence precedes tenant/key locks; revocation replay checks
only a flat owned key row, not lifecycle metadata or private material. Completed
replay neither generates keys nor changes revocation semantics, and still
requires current authority. Explicit local memory retains nondurable storage
and its narrow ownership guard. This does not finish broad API startup or the
remaining command-wrapper cutover. See
[key lifecycle commands](../api.md#signing-key-lifecycle-commands).
Merkle-batch creation also uses native durable HTTP execution. Its current
tenant-admin replay guard reads only the tenant root, not chain leaves or keys.
The common writer fence now precedes tenant/chain/leaf/key locks, including the
repository view entry point. Bounded selected hashes retain their existing
Merkle root and Ed25519 format; initial key, signature, batch, audit and replay
commit together. Completed retries preserve the original range without signing
again. This is a stored-hash commitment, not verification of every audit record
or proof of external publication. See
[Merkle creation](../api.md#merkle-batch-creation).
Recorded transparency-checkpoint creation also bypasses Ledger replay. Its
current tenant-admin guard locks flat owned batch coordinates without reading
the mutable root, leaves or signature arrays. The common fence precedes tenant
and batch locks, and checkpoint/audit/replay commit atomically. Fresh creation
keeps the existing five-field canonical assertion hash; completed retries keep
the original assertion without rehashing a later root. State remains `recorded`,
not verified external publication, and no provider call is made. See
[recorded checkpoints](../api.md#recorded-transparency-checkpoints).
Backup-manifest generation now uses native durable HTTP execution as well.
Its current tenant-admin replay guard reads only the tenant root; it does not
stream the state commitment or inspect audit pages. Fresh generation retains
the bounded v2 relational commitment and actual audit observations, while
manifest/audit/replay commit atomically. The common fence precedes tenant and
chain locks in both the commitment reader and audit-view repository entry
points. Completed retries preserve the original manifest without rehashing
later state. Explicit local memory retains its distinct v1 whole-state hash;
neither profile creates a restorable backup. See
[backup generation](../api.md#backup-manifest-generation).
Offline Cosign verification now also uses native durable HTTP execution.
Current verification authority and flat tenant/signature/artifact ownership
locks precede reservation and every replay. The common fence precedes parent
and signature share locks, including the direct subject resolver used by
artifact-signature verification. Guard execution reads no digest, image,
payload or trust material; completed delivery preserves the original receipt
without verification again. Fresh execution retains the existing bounded
finalized-object and full offline Sigstore profile. Both receipts, audit and
successful replay commit together; failed HTTP inspection rolls back business
effects. Local memory remains nondurable and other verification wrappers still
require migration. See [offline Cosign verification](../api.md#offline-cosign-verification).

The dedicated DSSE attestation-signature route now uses native durable
execution too. Its flat current attestation/evidence/build and parent scope
guard precedes reservation/replay, with the common writer fence before all
ownership locks. Completed retries do not read payloads, trust policies or
build outputs. Fresh inspection retains its bounded seven-check offline
profile; receipt, audit, verification job and replay commit together. Failed
HTTP inspection rolls back business effects, while unavailable trust remains
conservative `not_verified`. Local memory retains a narrow current-parent
guard and nondurable replay. Broad API startup remains a separate migration. See
[offline DSSE verification](../api.md#offline-dsse-attestation-verification).

Generic subject verification now binds the closed nine-command dispatcher
to native durable execution. A Verification-owned transaction port resolves
only current ownership coordinates before reservation/replay; the PostgreSQL
adapter takes the common writer fence before tenant/parent/subject share
locks. It does not read inspection facts or previous receipts. Resource
authorization retains each focused profile's scope, including tenant-wide
grants for full-chain checkpoint and detached artifact-signature profiles.
Fresh commands retain their inspectors and atomic receipt/audit/job/replay
writes. Completed delivery preserves exact original values without inspecting
changed metadata. Explicit local memory retains a current-map guard and
nondurable replay. See [generic subject verification](../api.md#generic-subject-verification).

Local-memory mode and other unmigrated handlers still use the Ledger
compatibility model.

Artifact-signature creation now binds Verification-owned commands directly
to native durable HTTP execution. The read-only replay guard takes the common
writer fence before tenant/artifact ownership locks and evaluates current
grant associations using the same transaction's identity-only projection.
It never selects artifact metadata/digest or stages payload bytes. Fresh
recording retains the bounded digest snapshot, payload staging/finalization
job and atomic audit/replay semantics. The public replay projector permits
only a canonical tenant/digest-derived payload reference on the versioned
recorded-signature DTO, without weakening generic storage-reference
redaction. Explicit local memory retains a current-map guard. See
[artifact signature recording](../api.md#artifact-signature-recording).

`internal/domain` remains a compatibility DTO boundary at the HTTP,
persistence, and legacy-facade edges while remaining callers migrate in EVY-904
through EVY-906. It retains the existing JSON tags and public field shapes,
uses aliases where exact identity is safe, and uses explicit copying mappers
where validated values or local report projections differ.
`make domain-context-check` verifies unique ADR ownership, package import/tag
boundaries, field-by-field compatibility, stable field types, schema ownership,
and the required mappers. JSON round-trip tests and the unchanged public field
shapes cover the current API/persistence representation. No database migration
was required for the EVY-902 model split.

### Context ownership

The type lists are exhaustive for the exported production types currently in
`internal/domain/domain.go`. Supporting types and schema-version constants
belong to the row that owns the resource they support.

| Context | Owns these current domain types | Current implementation and port ownership |
| --- | --- | --- |
| Identity and access | `Actor`, `ResourceGrant`, `Tenant`, `Organization`, `HumanUser`, `RoleBinding`, `SSOProvider`, `UserIdentityLink`, `SSOSession`, `APIKey`, `ProviderVerification` | `internal/identity/app.Service`; `IdentityRepository`; identity portions of `EnterpriseRepository` and the Ledger DTO adapter are temporary. |
| Release catalog | `Product`, `Project`, `Release`, `ReleaseEvidenceFlow`, `ReleaseEvidenceFlowStep`, `Artifact`, `BuildRun`, `BuildOutput`, `BuildAttestation`, `ReleaseCandidate`, `ContainerImage` | `internal/release/app.Service`; `ReleaseCatalogRepository`, `BuildRepository`, and `SupplyChainRepository` except artifact-signature writes. Ledger query and DTO adapters remain transitional. |
| Evidence ingestion | `EvidenceItem`, `SubjectRef`, `EvidenceRef`, `EvidenceNotice`, `EvidenceLifecycleEvent`, `SBOM`, `SBOMComponent`, `SBOMComponentRecord`, `VulnerabilityScan`, `VulnerabilityFinding`, `VulnerabilityIdentity`, `VEXDocument`, `VEXImportIssue`, `VEXImportReport`, `VEXImportPreview`, `OpenAPIContract`, `OpenAPIOperation`, `SecurityScan`, `ManualSecurityDocument`, `SBOMDiff`, `DependencyChange`, `ContractDiff` | `internal/evidence/app.Service`; `EvidenceRepository` and `ObjectPayloadRepository`. Ledger query and DTO adapters and the evidence-facing methods of `RiskRepository` remain transitional. |
| Vulnerability decisions and governance | `VulnerabilityDecision`, `VulnerabilityDecisionCustomerSummary`, `VulnerabilityDecisionSummaryReport`, `Exception`, `PolicyEvaluation`, `PolicyCheck`, `CustomPolicy`, `PolicyRule`, `CustomPolicyEvaluation`, `Waiver`, `ApprovalRecord`, `ControlFramework`, `SecurityControl`, `ControlEvidenceRequirement`, `ControlEvidence`, `ControlFrameworkTemplatePack`, `VulnerabilityWorkflowRecord`, `ReleaseSecuritySummary`, `ReleaseSecurityProductSummary`, `ReleaseSecurityReleaseSummary`, `ReleaseSecurityMissingDecision`, `ReleaseSecurityApprovalSummary`, `ReleaseSecurityExceptionSummary` | `internal/risk/app.Service` owns decision, exception, waiver, approval, and readiness commands; `DecisionRepository`, `ControlRepository`, and remaining policy/query methods of `GovernanceRepository` and `RiskRepository` are compatibility paths. |
| Package and reporting | `CustomerPortalAccess`, `QuestionnaireTemplate`, `QuestionnaireQuestion`, `QuestionnairePackage`, `QuestionnaireResponse`, `QuestionnaireAnswerLibraryEntry`, `RedactionProfile`, `CustomerSecurityPackage`, `SecurityReviewPackageReport`, `HTMLReportPackage`, `PDFReportPackage`, `CustomReportTemplate`, `RenderedCustomReport`, `EvidenceBundle`, `EvidenceBundleImport`, `ReleaseBundle`, `EvidenceCitation`, `EvidenceSummary`, `QuestionnaireDraft`, `GraphNode`, `GraphEdge`, `EvidenceGraphSnapshot`, `ControlCoverageReport`, `ControlCoverageItem`, `CRAReadinessReport`, `CRAVulnerabilityHandlingReport`, `SecurityUpdateEvidenceReport`, `ReleaseReadinessReport`, `ReadinessSummary`, `ReadinessSection`, `ReadinessQuestion`, `BlockingFinding`, `IncidentReport`, `VulnerabilityPostureReport` | `internal/package/app.CustomerPackageCommands` owns customer-package creation; the compatibility `internal/package/app.Service` delegates creation and retains the other Package workflow entry points; `internal/package/query.AnswerLibrary` owns grant-filtered questionnaire draft reads, `internal/package/query.ReleaseBundles` owns bounded bundle and manifest reads, `internal/package/query.PortalAccess` owns grant-filtered portal-access pages, and `internal/package/query.VulnerabilityPosture` owns tenant/release-authorized scan aggregates in the PostgreSQL profile. Other `packageReportService`, `PackageRepository`, and specialized report/questionnaire paths remain compatibility paths. |
| Verification and signing | `AuditChainEntry`, `SigningKey`, `SigningProvider`, `Signature`, `ArtifactSignature`, `CosignVerification`, `MerkleBatch`, `TransparencyCheckpoint`, `ObjectRetentionPolicy`, `SigningCustodyReviewReport`, `BackupManifest`, `DSSETrustRoot`, `SigningOperation`, `VerificationResult`, `VerifyCheck` | `internal/verification/app.Service` owns signing-key lifecycle, verification receipts, DSSE/Cosign, Merkle/checkpoints, retention, custody, and backup workflows; `internal/verification/query.ArtifactSignatures` owns the PostgreSQL artifact-signature point read. `SignatureRepository`, `IntegrityRepository`, `VerificationRepository`, and remaining audit/query paths are compatibility adapters. Audit append is a required transaction side effect, not an authority to change another context's record. |
| Operations and incidents | `InstanceAdminSnapshot`, `LegalHold`, `RetentionOverride`, `RetentionReport`, `DeploymentEnvironment`, `DeploymentEvent`, `Incident`, `IncidentTimelineEvent`, `IncidentWebhookReceiver`, `IncidentWebhookEvent`, `RemediationTask` | `risk_workflows.go`, runtime/readiness, outbox administration and object reconciliation; `DeploymentRepository`. `AuditRepository`, `IdempotencyRepository`, and `OutboxRepository` are platform services owned here and used inside the caller's unit of work. |
| Integration ingestion | `Collector`, `CollectorRelease`, `CollectorHealthReport`, `SourceRepository`, `SourceCommit`, `SourceBranch`, `PullRequest`, `CommercialCollectorDefinition` | Collector, source-snapshot, and commercial-collector paths; `SourceRepository` and the collector methods of `BuildRepository`. |
| Experimental peripherals | `SaaSEditionProfile`, `PublicTransparencyLog`, `PublicTransparencyLogEntry`, `MarketplaceCollector`, `MarketplaceCollectorHealthReport`, `AnomalySignal`, `AnomalyReport` | `FutureExtensionsRepository` is a temporary quarantine port. These surfaces remain experimental until a named owning context accepts them; no new production dependency may target this port. |

`GovernanceRepository`, `RiskRepository`, `EnterpriseRepository`, and
`FutureExtensionsRepository` are explicitly transitional mixed ports. Their
row above assigns one accountable owner today. EVY-903 moved the Identity,
Release, and Evidence command capabilities it required. EVY-904 added focused
decision, package, and verification transaction ports while the legacy mixed
repository interfaces remain for compatibility. No new method may be added to
a mixed port.

### Public operations and internal work

`docs/reference/api-inventory.md` is the generated, exhaustive current
operation inventory. It contains 189 operations, each with one OpenAPI
`Owner` value. This table maps every possible current owner value to exactly
one target context; it is the route and public command/query assignment until
the generated OpenAPI owner labels are changed atomically with their handlers.

| Current OpenAPI owner (operation count) | Target context | Transition rule |
| --- | --- | --- |
| `identity-access` (15) | Identity and access | Direct mapping. |
| `release-catalog` (21) | Release catalog | Direct mapping introduced with the EVY-903 handler migration. |
| `evidence-ingestion` (27) | Evidence ingestion | Direct mapping introduced with the EVY-903 handler migration. |
| `release-ledger` (7) | Package and reporting, Vulnerability decisions and governance, or Operations and incidents | Remaining transitional query and operations label. Bundle reads, summaries, and graph/report creation go to Package and reporting; vulnerability workflow records go to Vulnerability decisions and governance; remediation tasks go to Operations and incidents. The route's resource selects the future service. |
| `integration-ingestion` (17) | Integration ingestion | Direct mapping. |
| `governance` (28) | Vulnerability decisions and governance | Direct mapping, except redaction and customer-package rendering, which move to Package and reporting. |
| `customer-delivery` (15) | Package and reporting | Direct mapping. |
| `reporting` (17) | Package and reporting | Direct mapping. |
| `integrity-verification` (24) | Verification and signing | Direct mapping. |
| `operations-incidents` (9) | Operations and incidents | Direct mapping. |
| `platform-operations` (9) | Operations and incidents | Direct mapping. |

The table above is intentionally a mapping, not a second handwritten route
catalog. The generated inventory remains the source of individual operation
IDs, paths, methods, auth, idempotency, and current labels. Its eleven counts
sum to 189. Later migration tickets must update a route's OpenAPI owner and
handler in the same compatible change; no handler may be silently re-owned.

Current non-HTTP commands and queries are assigned by the same owner rule:

| Current source surface | Owner | Required split outcome |
| --- | --- | --- |
| `internal/identity/app` with adapters in `internal/app/identity_service.go` and `identity_context_adapter.go` | Identity and access | Focused service owns commands; the old facade forwards and still supplies compatibility queries and DTO mapping. |
| `internal/release/app` with adapters in `internal/app/release_evidence_service.go`, `release_context_adapter.go`, and build paths | Release catalog | Focused service owns release/catalog/build commands; the old facade forwards during migration. |
| `internal/evidence/app` with adapters in `internal/app/evidence_context_adapter.go`, parser adapters, and remaining `vex.go` compatibility | Evidence ingestion, with decision effects emitted after commit | Focused service owns evidence/document commands and normalization; decision creation remains a separate decision command. |
| `internal/app/governance_packages.go`, `controls.go`, and policy paths | Vulnerability decisions and governance; Package and reporting for output/rendering | Policy mutation and read-only package rendering separate. |
| `internal/app/integrity_runtime.go`, audit chain, and verification profiles | Verification and signing | Provider adapters remain outside the application package. |
| `internal/app/risk_workflows.go` | Operations and incidents, Evidence ingestion, and Vulnerability decisions and governance | Split incidents, raw security evidence, and policy workflow methods. |
| `internal/app/package_report_service.go` and package/report portions of `enterprise.go` | Package and reporting | Use committed, tenant-scoped snapshots only. |
| `internal/app/outbox_admin.go`, runtime diagnostics, and reconciliation administration | Operations and incidents | Platform-only operator surface. |
| `internal/app/future_extensions.go` | Experimental peripherals | Keep isolated; graduate or remove each feature before it becomes stable. |

The persisted worker job kinds currently are assigned as follows:

| Job kind | Owner | Post-commit effect |
| --- | --- | --- |
| `finalize_payload`, `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract` | Evidence ingestion | Validate staged bytes and finalize or normalize evidence. |
| `parse_vex` | Evidence ingestion | Normalize VEX; it may request an idempotent Vulnerability decisions command after parsing. |
| `sign_bundle` | Verification and signing | Attach a signing receipt to an immutable package/bundle subject. |
| `verify_subject`, `verify_attestation` | Verification and signing | Append a verification receipt; never mutate the verified subject's core fields. |

### Repository and migration stewardship

Every field of `app.Repositories` has one accountable context. A caller may
use only its own business port plus the platform `Audit`, `Idempotency`, and
`Outbox` ports in the same unit of work.

| Repository field | Owner | Transitional note |
| --- | --- | --- |
| `WorkerProjection` | Operations and incidents — shared transaction/query platform | Temporary read-only bridge for worker-owned records needed by the Ledger compatibility model; it grants no mutation authority. |
| `Identity` | Identity and access | — |
| `Idempotency` | Operations and incidents | The platform owns expiry and replay mechanics; callers use it within their own transaction. |
| `ReleaseCatalog`, `Builds`, `SupplyChain` | Release catalog | `ArtifactSignature` moves from `SupplyChain` to Verification and signing. |
| `Evidence`, `Payloads` | Evidence ingestion | — |
| `Decisions`, `Controls`, `Governance` | Vulnerability decisions and governance | Redaction, legal-hold, retention, and DSSE methods leave `Governance`. |
| `Packages`, `Enterprise` | Package and reporting | Commercial-collector methods leave `Enterprise` for Integration ingestion. |
| `Signatures`, `Integrity`, `Verification` | Verification and signing | — |
| `Deployments`, `Audit`, `Outbox` | Operations and incidents | Audit and outbox are mandatory cross-cutting transaction effects. |
| `Source` | Integration ingestion | — |
| `Risk` | Vulnerability decisions and governance | Incident methods move to Operations; raw document/diff methods move to Evidence ingestion. |
| `Future` | Experimental peripherals | Split or delete before any stable API commitment. |

Migration ownership below is stewardship of the forward-only schema change,
not a claim that every table touched by an early aggregate migration belongs
to its steward. This makes each current `.up.sql` migration accountable to
exactly one context while preserving existing data and migration history.

| Migration | Steward context |
| --- | --- |
| `20260527000100_initial_ledger`, `20260527000200_runtime_foundation`, `20260528000200_increment_6_15`, `20260528000300_increment_16_25`, `20260528000400_increment_26_35`, `20260528000500_increment_36_45`, `20260528000600_increment_46_55`, `20260528000700_increment_56_65`, `20260528001600_remaining_relational_recovery_columns` | Operations and incidents — historical platform transition. |
| `20260527000300_vex_decisions_exceptions`, `20260528000100_controls_reports`, `20260601000100_vulnerability_decision_customer_fields`, `20260601000200_vulnerability_decision_evidence_ids`, `20260601000300_vex_import_reports`, `20260601000600_vulnerability_decision_review_times`, `20260601000700_vulnerability_decision_sbom_context`, `20260601000800_vulnerability_decision_supporting_refs`, `20260601000900_vex_import_report_failures`, `20260904000100_vulnerability_decision_active_unique`, `20260929000600_vulnerability_decision_query_indexes` | Vulnerability decisions and governance. |
| `20260527000400_collectors_builds_attestations`, `20260528001400_release_core_relational_columns` | Release catalog. |
| `20261002000100_vulnerability_decision_supersession` | Vulnerability decisions and governance — append-only supersession relationships and constrained active-head projection. |
| `20260815000100_vulnerability_scan_adapter_identity` | Evidence ingestion. |
| `20261001000300_evidence_verification_indexes` | Verification and signing — bounded reads of evidence-owned parser facts. |
| `20260528000800_customer_portal_access_counters`, `20260528001500_package_retention_relational_columns`, `20260601000400_customer_portal_nda_answer_library`, `20260601000500_customer_portal_reviewers`, `20261003000100_customer_portal_token_lookup` | Package and reporting. |
| `20260528001000_signed_incident_webhooks` | Operations and incidents. |
| `20260528001100_static_oidc_jwks`, `20260528001200_saml_provider_certificates`, `20260528001300_sso_trust_material_timestamp`, `20260529000200_sso_session_groups` | Identity and access. |
| `20260528000900_future_extensions_and_partial_closures` | Experimental peripherals. |
| `20260529000100_object_retention_object_key`, `20260531000100_object_retention_legal_hold`, `20260722000100_verification_assurance_taxonomy`, `20260722000200_object_retention_verification_truth`, `20260724000100_audit_chain_integrity_v2`, `20260726000100_provider_signature_receipts`, `20260815000100_dsse_attestation_verification_profiles`, `20260815000200_cosign_verification_receipts`, `20260815000300_signing_operation_canonical_receipts`, `20260815000400_signing_key_lifecycle` | Verification and signing. |
| `20260726000200_idempotency_state_machine`, `20260726000300_idempotency_safe_replay_responses`, `20260727000400_audit_sequences_and_resource_revisions`, `20260727000500_outbox_dead_letter_controls`, `20260728000100_object_payload_lifecycle`, `20260728000200_object_reconciliation_receipts`, `20260728000300_object_reconciliation_receipt_schema_version`, `20260822000100_cursor_pagination_indexes` | Operations and incidents — shared transaction/query platform. |

### Dependency, event, and transaction rules

`internal/evidence/domain.CanonicalEvidenceOrigin` is an evidence-owned typed
value used to reconstruct legacy canonical relationships. It is a support
model, not a new persisted record or public JSON schema; versioned lifecycle
detail decoding remains at the verification application boundary.

The only allowed business dependency direction is:

```text
Identity and access ────────► all context entry points (actor and grant checks)
Release catalog ────────────► Evidence ingestion
Evidence ingestion ─────────► Vulnerability decisions and governance
Release catalog + decisions ─► Package and reporting
Evidence/catalog/package ───► Verification and signing
Any committed context event ─► Operations and incidents
Integration ingestion ──────► Release catalog or Evidence ingestion
Experimental peripherals ───► no production context
```

An arrow permits a tenant-scoped ID reference, a read-only query through an
explicit port, or a committed versioned event. It does not permit importing a
foreign aggregate, mutating its repository, or calling back from the target.
Package/report generation reads a committed snapshot and may persist only its
own package/report/receipt record. Verification appends a receipt and cannot
edit the subject it verified. Operations consumes diagnostics and events; it
does not become an alternate business-write path.

The target event vocabulary is `EvidenceAccepted`, `PayloadFinalized`,
`SBOMParsed`, `VulnerabilityScanParsed`, `OpenAPIContractParsed`, `VEXParsed`,
`VulnerabilityDecisionRecorded`, `ReleaseStateChanged`, `PackageGenerated`,
`BundleGenerated`, `VerificationRecorded`, and `IncidentRecorded`. These are
design names, not a claim that a stable event schema already exists. Until the
schema is introduced, the persisted outbox job kinds in the prior table are the
only implementation truth. Every event must contain schema version, event ID,
tenant ID, subject type/ID, occurrence time, causation ID, and canonical
request or subject digest as applicable.

Every command performs its required scope and tenant preflight before opening a
unit of work. Resource coordinates already resolved at that point are also
authorized during preflight. When a uniqueness lookup or concurrent row read
discovers the exact existing resource inside the transaction, the command
revalidates tenant ownership, relationships, and resource authorization against
that transaction-local record before returning it or writing dependent state.
This transaction-local revalidation does not replace the earlier scope
preflight. The owner validates its invariants, writes its data plus the required
audit/idempotency/outbox effects, commits, then publishes. Cross-context effects
are requested by an outbox event after commit. A command requiring an atomic
change to two business owners must be redesigned around one owning record or a
durable saga; it must not create a cross-context repository write.

`Repositories.WorkerProjection` is a temporary read-only compatibility port for
records that an outbox worker may commit after an API process built its local
Ledger read model. A PostgreSQL unit of work binds this port to the same
transaction as the command repositories. The adapter constrains every
projection query by tenant and coordinates a stable snapshot with a per-tenant
advisory fence: standalone read-only refreshes use a repeatable-read transaction
and shared fence, while transaction-bound projection reads, worker projection
mutations, and audit appends use the exclusive fence. Audit append takes the
projection fence before its audit-chain sequencing lock. This prevents a
worker/API mutation from interleaving between a transaction-local projection
read and the command's dependent write or audit append. It protects the legacy
read bridge; it does not replace the EVY-904 decision/package/verification
service split or complete the EVY-905 database-backed query migration. The detailed
runtime contract is in [Worker Outbox Contract](../reference/worker-outbox.md).

The EVY-903 focused command-service migration has exactly three temporary
synchronous cross-context write exceptions. Tenant bootstrap is the first:
the focused Identity service owns tenant and initial API-key preparation and
writes, while the composition adapter invokes Verification-owned initial
signing-key preparation and commit in the same unit of work. This preserves
the existing all-or-nothing bootstrap and bearer-secret issuance contract;
Identity has no signing-key repository capability.

PostgreSQL API first-start bootstrap now uses
`wiring.BuildTenantBootstrapCommands` directly, before any transitional Ledger
construction. `identity/app.TenantBootstrapCommands` receives only tenant,
API-key, and audit writes; `verification/app.InitialSigningKeyCommands` receives
only its key factory, clock, and initial-key writer. Both legacy service facades
delegate to these same implementations. The installation-wide empty-table
guard and all writes share one top-level startup transaction, with no ambient
command or Ledger publication. The guard selects only a boolean and uses a
tenant-table lock that also fences ordinary inserts. Public identity and secret
are returned only after commit; existing installations receive neither.
Local-memory bootstrap remains explicit compatibility behavior. This removes
bootstrap's production aggregate dependency, not the remaining Ledger startup
or handler composition. See [First-Tenant Bootstrap](../reference/configuration.md#first-tenant-bootstrap)
for operator bounds, lock-wait, output, and key-custody limitations.

Build-attestation upload is the second exception. The public compatibility
contract atomically creates a release-owned `BuildAttestation` and its
evidence-owned `EvidenceItem`; the attestation repository requires the evidence
identifier to resolve in the same transaction. Splitting the operation during
EVY-903 would either expose a partially created upload, violate ADR 0001, or
require a new saga and API/persistence state model. The focused Release service
therefore receives only a transaction-scoped,
`BuildAttestationEvidenceWriter` capability for this one evidence shape. It
does not receive `EvidenceRepository`, evidence aggregates, or any other
evidence mutation. EVY-906 must replace this bridge with a durable
`BuildAttestationAccepted` ingestion saga (including an explicit pending state
and compatible API transition), then remove the capability before the
architecture boundary check becomes mandatory. No other release command may
use this exception.

Deployment recording is the third exception. Its existing public contract
returns a deployment event whose evidence identifier is immediately readable,
and persistence validates both sides of that deployment/evidence back-reference
inside one transaction. The operations-owned command may therefore create only
the fixed `deployment/event` evidence shape and insert it with the deployment
event in the shared compatibility unit of work. This bridge does not permit an
operations command to accept arbitrary evidence fields or mutate existing
evidence. EVY-906 must replace it with a durable `DeploymentRecorded` ingestion
saga, an explicit pending-evidence state, and a compatible API transition before
the architecture boundary check becomes mandatory. No other operations command
may use this exception.

Environment creation and deployment recording now use native durable HTTP
execution with Operations-owned current-identity/grant guards before reservation
and replay. These guards never read natural-name reuse metadata, generate
evidence or allocate clock/ID values. The shared writer fence precedes tenant
and referenced ownership locks held through the outer transaction. Environment
creation retains natural-name reuse; deployment recording retains this fixed
evidence capability, artifact duplicates and timestamp semantics. Local-memory
guards remain explicit compatibility utilities, not production composition.
This migration does not complete EVY-905 startup/remaining-wrapper work or the
EVY-906 saga transition.

Custom report template creation and materialization use native durable HTTP
execution with focused tenant/template scope lockers, not Ledger replay.
Current tenant-wide report permission and ownership are checked without
definition metadata, subject dereferencing or output generation during replay.
Fresh rendering preserves the inert allowed-label contract and normalized
string-output hash. The Service transaction bridge remains compatibility-only
and cannot serve native HTTP replay guards; startup retirement remains EVY-905.

Generic evidence creation uses native durable HTTP execution and a focused
transaction guard for current tenant/parent/recognized-subject ownership and
grants. Completed replay neither prepares a new evidence record nor checks the
old declared artifact digest; fresh preparation retains payload/digest checks.
The existing staged-payload capability remains internal, and safe replay still
omits opaque payload references. This does not finish other wrappers or startup
Ledger retirement in EVY-905.

Portable evidence-bundle import now uses native durable HTTP execution and a
Package-owned target-tenant scope locker. Every retry checks current
tenant-wide bundle permission and holds the tenant lock after the shared
writer fence through the outer replay transaction, without manifest hashing
or receipt clock/ID allocation. Source identities and signatures are labels,
not authorization coordinates. Fresh work commits only a receipt and caller
audit, never supplied evidence, manifest metadata, or signature trust. The
Service bridge remains a local compatibility path and cannot satisfy native
replay guards; startup retirement remains EVY-905 work.

Evidence-bundle export also uses native durable HTTP execution with bounded
Package-owned scope guards. The requested root/explicit references are checked
before reservation; a matching completed replay additionally checks the saved
server-selected IDs inside the same outer transaction. It takes the shared
writer fence before tenant/selected-parent locks and never reruns snapshot,
hashing or signing work on replay. Fresh work retains committed snapshots and
commit-time coordinate/signature lifecycle validation. HTTP callbacks cannot
bind a Ledger. The local-memory compatibility path explicitly guards the actual
response before disclosure and is not a durable ownership transaction. These
changes do not finish startup retirement or the remaining EVY-905 final gates.

Go dependency cycles are prohibited. A context domain package may depend only
on standard library and small shared value/event packages. An application
package may depend on its own domain and inward-facing ports. Adapters and
`cmd/*` depend inward only. Neither domain nor application may import HTTP,
PostgreSQL, object-store, worker, or provider adapters. The future
`architecture-check` from EVY-906 will enforce these rules.

### Migration and retirement sequence

Each step is additive and must leave the repository buildable, testable, and
API-compatible.

1. EVY-902 created context-owned packages and adapters/types at the new paths.
   Old `internal/domain` names remain type aliases or compatibility mappers;
   persisted and OpenAPI DTOs remain at adapter boundaries.
2. EVY-903 moved identity, release, and evidence commands to focused services
   and their handlers behind context-specific interfaces. `Ledger` is now a
   deprecated forwarding facade; no new command behaviour is added to it.
3. EVY-904 moves decision, package, and verification workflows, splits mixed
   repository methods, and makes package reads transaction-consistent.
4. EVY-905 installs one composition root and database-backed context query
   services. HTTP and worker wiring then receive only focused services.
   Collector health now reads the tenant-owned collector and latest/pinned
   release records under one PostgreSQL snapshot. Instance-admin counts now
   come from a single aggregate database snapshot guarded by an explicit
   instance scope; other Ledger-compatible reads remain transitional until
   their focused queries are installed.
5. EVY-906 removes production `Ledger` construction and its forwarding
   methods, deletes obsolete aliases only after every caller has moved, and
   makes an import-graph violation fail the build gate.

Schema changes stay forward-only. A context adds new columns/tables and maps
old records before a later release removes obsolete compatibility reads. A
commit moving a route changes its handler, generated OpenAPI ownership,
contract tests, and compatibility notes together. No commit may require a
consumer to import both a new aggregate and its legacy `internal/domain`
implementation.

## Consequences

This decision gives each existing type, operation, repository field, migration,
and worker job a current accountable owner without pretending that the code has
already reached the target package tree. It also makes mixed ports and
experimental surfaces visible technical debt with a removal or graduation path.

EVY-902 and EVY-903 implemented the model boundary and the first three focused
command-service boundaries. Until the later tickets land, `internal/domain`,
the compatibility portions of `internal/app`, and `*app.Ledger` remain
transition paths, not examples for new production dependencies.
