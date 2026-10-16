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

Added a private native API registry for HTTP and provider counters and duration
histograms (EVY-1211, in progress). Existing tenant metrics and JSON values
remain available; only explicit `instance:admin` text scrapes include the
process-wide measurements. Fixed labels, a hard series budget, bounded text
output and canary tests protect the operational boundary. Metrics responses are
not proxy-cacheable, and failed snapshots return no partial data or raw errors.
The recorder does not change provider results or resource ownership. Worker
scraping and database/queue/storage signals remain pending in this ticket.

Added `/v1/startup` and shared bounded dependency snapshots for startup,
readiness and instance-admin diagnostics (EVY-1203). Public liveness remains
independent of application quotas and dependency-probe saturation;
startup/readiness use a separate bounded pool. Responses are not proxy-cacheable,
and unavailable probes preserve retry metadata. The synthetic `ledger: ok` row
is removed because it performed no evidence check. Outbox readiness detects
overdue eligible work and expired worker leases without claiming jobs.
Configuration readiness detects process-environment drift and an optional
projected desired revision. Revision symlink targets must stay inside their
configured parent directory; in-directory projection aliases remain supported.
Helm maps distinct API lifecycle probes and rolls
both daemons on chart configuration changes; external Secret changes still
require an operator rollout. Production signer readiness now reads native cloud
key metadata or an explicitly configured same-origin gateway readiness endpoint
without creating signatures. Additional metadata permissions and gateway/default
key settings require operator preparation; metadata health does not prove
signing authorization. API shutdown publishes draining state before listener
shutdown while preserving admitted-request completion. Worker lifecycle probes
now query a private running-daemon listener and share configuration freshness
checks with the API. Helm supplies distinct worker modes, revision projection,
and runtime Secret loading with optional daemon-specific identities. Local
validation and compatibility limits are recorded in the EVY-1203 backlog entry.

Added structured process, HTTP, provider, command and worker diagnostics
(EVY-1202). API, worker and migration commands default to JSON on stderr, with
validated levels and an optional text format. Fixed events and typed fields
exclude arbitrary errors and request/evidence payloads; identifiers use opaque
references. Dedicated outbox columns preserve correlation across claims without
changing evidence or idempotency inputs. Audit receipt observations follow a
confirmed commit. Existing plaintext log consumers must adopt the documented
schema; stdout command results and explicit local bootstrap-secret output keep
their existing contracts.

Completed bounded resource cleanup and deployment termination controls
(EVY-1201, EVY-1209). Partial startup and normal shutdown close owned database,
object and provider resources once under a shared deadline, preserve borrowed
clients/transports and retain writer ownership through forced process exit.
Helm rejects invalid termination budgets and uses `Recreate` for the single API
writer, with planned rollout downtime; workers can scale and roll normally.
Deployment checks render the actual chart and resolve Compose.

The release-artifact gate now requires four real SIGTERM cases with PostgreSQL
lock barriers, durable receipts and matching binary hashes. They verify API
completion/rollback and idempotent restart, plus worker completion or fenced
native retry. The complete local production gate passed on 2026-10-16. This is
release-style binary evidence; live cluster rollout, external-provider
interoperability and published operator assets remain separate proof.

Fixed API listener failure shutdown (EVY-1208) to drain admitted requests
before returning the serve error. Signal shutdown retains request contexts
until completion or the configured deadline; forced closure cancels unfinished
requests and reports failure. Listener ownership and safe lifecycle status have
explicit regression tests. Routes, authentication and ingress limits retain
their existing contracts.

Added bounded worker shutdown (EVY-1207): stop claiming and starting batch jobs
on a signal, drain the active job and its acknowledgement within one configurable
budget, and leave uncertain claims for fenced lease expiry/reclaim. Graceful
shutdown succeeds; deadline expiry fails without waiting indefinitely for pool
cleanup. This does not promise exactly-once job execution.

Expanded deterministic contention validation (EVY-1105) to retain the existing
idempotency cases and exercise native tenant commands, audit ordering, signing
rotation, customer packages, credential replacement and worker replicas under
the race detector with three scheduler settings. Missing or skipped evidence
fails the gate. The full local production gate passed on 2026-10-15, including
all 510 default stress passes. Hosted Production Check, Race and Stress, and
CodeQL passed on published commit `d77b612bc721`. On 2026-10-16, approved
branch-protection changes added Race and Stress while retaining the existing
Actions bindings and up-to-date requirement. Administrator bypass remains
possible. Validation covers the single-writer API and contending workers.

Added independent per-client failure budgets for authentication, public SSO
and portal actions (EVY-1011), with bounded state, opaque keys, concurrency
reservations and non-cacheable `429` responses. The general request-limit
override does not disable failure protection. The full local production gate
passed on 2026-10-15; configuration documents process-local scope and recovery
behavior. This does not establish external identity-provider interoperability.

Added tenant-owned SAML recipient/NameID bindings and separate bounded login
initiation, with standard signed-assertion session exchange (EVY-1010). API and
browser delivery bind to server-owned state; browser state uses its own cookie.
Verification, replay consumption, sessions and audits commit together. Signed
session deadlines and selected-certificate proof expiry are enforced across
transaction waits. Historical custom assertions cannot issue exchange sessions;
clients must migrate to the [unreleased SAML contract](docs/reference/api-versioning.md#evy-1010-saml-login-contract-unreleased).
Standalone SAML receipts now require API-delivered request/state and the same
standard signed profile, with atomic consumption and no session issuance.
The full local production acceptance gate passed on 2026-10-15. These checks establish no real-provider
interoperability, external approval or release publication.

Added server-owned OIDC login state and nonce with atomic single-use proof
consumption (EVY-1009). Clients first create an authentication request, then
exchange a matching signed ID token and state within five minutes; unbound,
replayed, stale-trust and wrongly scoped proofs fail. Strict JWT JSON, audience,
authorized-party, time, algorithm and public-key usage checks apply. API delivery
returns the session secret once in JSON and sets no cookie; explicit OIDC
browser delivery uses host-only state and session cookies with same-origin
protection and omits the JSON secret. The exact prerelease compatibility record
adds that optional response property to the preceding unchanged 205-entry set;
it is not an external approval or a published release. The new guarded migration
preserves historical identity/evidence records; backup metadata uses frozen
v4 semantics while retaining v1/v2/v3 reproduction. The subsequent SAML and
failure-budget entries record their completed local validation. See the
[rollout policy](docs/reference/upgrade-compatibility-policy.md#oidc-login-binding-rollout).

Hardened the SSO credential transport boundary (EVY-1007): authenticated routes
use the required toolkit's strict Bearer parser, reject ambiguous headers
without cookie fallback, and reserve cookies for issued human SSO sessions.
API/collector keys cannot authenticate through a session cookie. Unsafe cookie
Origins are checked before verification or cleanup; unauthorized cookies expire
with the existing secure attributes. SSO credential responses are `no-store`.
CSRF regressions now issue real human sessions while retaining their original
status, replay and denied-effect assertions. The subsequent lifecycle, OIDC/SAML
and failure-budget entries complete the local EVY-1005 acceptance checks.

Added bounded session lifecycle behavior (EVY-1008): issuance captures finite
absolute/idle policy, authentication checks current identity/grants under locks
and commits monotonic last use without extending expiry or replacing a secret.
Cookie and Bearer paths reject idle, expired, revoked, inactive-user/provider
and over-lifetime sessions. Session schema v1.1.0 adds policy/activity metadata;
the migration preserves historical core fields and does not revive old idle
sessions. See the [configuration and upgrade limits](docs/reference/configuration.md#sso-session-lifecycle-unreleased).
The subsequent OIDC/SAML and failure-budget entries cover request/proof binding
and failure limits. This change is not a release or a broader security-readiness
claim.

Backup metadata commitments now use `tenant-relational-state.v3` to include
the captured session policy and activity fields. Frozen v1/v2 vocabularies and
hash vectors are retained for historical reproduction; manifest field layout,
credential exclusions and stored historical manifests are unchanged.

Recorded EVY-1002's exact repository-controlled prerelease API compatibility
review: the unchanged `v0.1.0-rc.7` artifact is compared with 205 selected
differences, retaining all 135 previously reviewed entries and adding 70
explicit schema/idempotency corrections and input constraints. Clients must
regenerate from current OpenAPI, use the supported security-upload enum names,
supply nonblank required fields and candidate-transition reasons, and stop
requiring catalog fields that were never returned by the runtime. The read-only
evidence-flow query no longer advertises mandatory idempotency. See the
[exact review and migration record](docs/reference/api-versioning.md#evy-1002-prerelease-contract-reconciliation).
The exception is digest/count/rule/baseline bound and rejects any altered set;
no runtime behavior, stored schema, immutable hash, or historical record is
changed by this reconciliation. This is not blanket approval of other transport
or authorization restrictions, a stable release, or independent review.

Added centralized typed action/resource authorization across focused application
services, with distinct tenant, resolved-resource, instance, static-catalog,
self-session and verified public-credential boundaries. Tenant wildcard or
resource grants do not imply instance administration. Generated policy contracts
and an executable positive/negative matrix cover all 189 API operations; a
separate check rejects missing or unregistered scenarios. Memory fixtures and
controlled external I/O are not storage-durability or provider proof. Route
methods, response schemas and immutable persistence formats are unchanged.
EVY-1002's required full-suite and production validation passed on 2026-10-11
for clean source `50f4ad37`: full unit/race/live PostgreSQL/MinIO, security,
migration-prefix, black-box and local signing checks passed. Coverage was 86.3%
overall and 85.1% critical, above the unchanged 80%/81% floors. See the
[completion record](.EVYDENCE_CODEX_BACKLOG.md#x-evy-1002-centralize-authorization-policy-and-prove-route-coverage)
for exact commands, compatibility and local-evidence limits. No new release,
hosted CI, external-provider controls or general security conclusion is implied.

Centralized SSO credential-exchange authority as a verified-identity action.
Session issuance now requires a passed assessment, completed fully passed
credential checks, bound active identity and capabilities; pending, skipped or
missing proof no longer acquires session authority. Requested session expiry
is rechecked after snapshot locks. Post-commit cancellation withholds results
and secrets without undoing committed records/audits. Local OIDC/SAML crypto,
safe denial receipts, repeat valid issuance, token/cookie/schema/hash formats
and historical rows are unchanged. This migration is included in EVY-1002's
validated source; it does not establish live-provider or token single-use proof.

Centralized signed incident-webhook authority as a receiver-signature action,
with bound current incident/evidence scope. API scopes cannot replace a receiver
signature. Deliveries that age outside the existing five-minute window during
blocking reads now fail before fresh writes or receipt replay; providers can
re-sign the same event ID and exact body to retry. Post-commit cancellation
withholds receiver/receipt results without undoing committed records or audits.
Ed25519 framing, raw-body/hash formats, schemas and natural replay identities
remain unchanged. This migration is included in EVY-1002's validated source;
provider controls and release publication are not inferred from local checks.

Centralized customer-portal token authorization with separate read/download
actions and exact current package ownership, expiry, and required acceptance.
API scopes and human grants cannot stand in for a verified package token. The
data-free static form is separately labeled in generated authorization metadata.
Post-commit request cancellation now withholds the package result while retaining
already committed acceptance/counters/audits. Token and hash formats, redaction,
response schemas, denial auditing and five-failure revocation are unchanged.
These routes participate in the complete authorization matrix; EVY-1002's
required final gates passed on source `50f4ad37` with the limits recorded above.

Constrained collector attribution on generic evidence and build creation,
including completed replay. Caller-supplied collector identity must match the
authenticated binding; conflicting, malformed or unbound claims now return
generic `403` before writes. Unrelated metadata, valid bound credentials,
schema/hash formats and historical rows are unchanged. See the
[unreleased collector attribution boundary](docs/reference/api-versioning.md#unreleased-collector-attribution-boundary)
for client migration and compatibility limits. This migration is included in
EVY-1002's validated source.

Completed EVY-906's production Ledger retirement and required local validation
on 2026-10-10 for source commit `3c2f1037`. Architecture, full unit/race, live
PostgreSQL/MinIO, migration compatibility, black-box restart/release-style
binary flows and signing smoke passed. Coverage was 86.1% overall and 85.0%
for critical packages, above the unchanged 80.0%/81.0% floors. This is local
engineering evidence, not hosted CI, publication, external-provider verification
or host-reboot/power-loss durability proof. Earlier pending notes below describe
incremental migration checkpoints and are superseded by this completion record.

Fixed native package-preparation pool exhaustion under concurrent idempotent
commands. Committed bundle/customer-package snapshots and local signing-key
reads use an independent read-only pool capped at four connections, or the
primary pool limit if smaller, without changing their SQL, row/byte budgets,
tenant predicates, signature format or write-time validation. Store shutdown
closes both pools; operators must account for the additional bounded connections.
Added saturated-single-connection regressions for committed-only reads, foreign
scope rejection, signature validity, cancellation and connection release. The
existing 16-caller replay/count test and its 45-second deadline are unchanged.
Required full-ticket validation subsequently passed without changing that test.

Removed the physical Ledger aggregate, configuration/constructor, mutable
maps/locks and all 52 remaining receiver methods from production source. Snapshot
cloning, cached authorization, persistence forwarding and compatibility replay
remain historical test-only implementations with their existing behavior tests.
Shared native transaction/replay, object lifecycle, key formats, constant-time
credential comparison, scope constants and persistence utilities retain their
algorithms. HTTP fixture inputs are test-local; authorization inventory follows
the same retired policy body. Architecture and generated persistence reference
now describe source retirement rather than a runtime aggregate fallback. API,
storage and immutable hash contracts are unchanged. Source removal alone
did not close EVY-906; the required full/race/production and live SQL gates
subsequently passed.

Removed the remaining PostgreSQL fixture dependencies on Ledger and its
constructor/configuration adapter. Compound catalog setup takes the actual
transaction factory; atomic replay and independent concurrent callers use native
idempotency without aggregate snapshots or caches. Existing live SQL effect,
original-response and rollback assertions remain, with additional memory-backed
compound commit, exact replay, foreign-parent, cancellation and final-commit
failure regressions. The historical concurrency test name remains wired to the
critical-behavior matrix/stress gate. Runtime contracts are unchanged. Live SQL
cases are not proven by skipped tests; application aggregate/state retirement
and full/race/production validation still keep EVY-906 open.

HTTP test fixtures no longer construct or accept the application Ledger. Their
locator contains only a transaction factory and replay clock; actual focused
commands, current guards and saved-selection replay share the native unit of
work, with no aggregate snapshot/cache clone or in-memory fallback. Historical
fingerprint/response assertions remain; a cache-only positive replay test now
uses a real factory. Missing-repository fixtures keep a separate real cache
canary and still fail closed. Added no-whole-state-access, shared-transaction,
current-authority, response-guard and final-commit rollback regressions. Runtime
API and persistence contracts are unchanged. Remaining PostgreSQL legacy setup,
aggregate/state retirement and full/race/live gates keep EVY-906 open; these
memory-backed fixture checks are not SQL durability evidence.

Retired cached worker inventory hydration, parser-normalization cache
publication, cached audit/checkpoint inspection, backup counts and cached context
authorizers from production source. Historical implementation and behavioral
assertions remain test-only; native selected-record shape/conflict helpers and
immutable parser-normalization validation retain their algorithms. Additional
characterization covers accepted/queued SBOM, scan and attestation records,
OpenAPI/VEX records, tenant/evidence identity, malformed parsed shapes and parent
relationships. Production contracts and native worker behavior are unchanged.
Fixture/replay locator, aggregate state/snapshot retirement and full/race/live
validation remain EVY-906 work; these tests are not SQL durability evidence.

Retired the broad Verification aggregate adapter, its Service field and
constructor wiring, and Ledger backup-generation facade from production source.
Historical characterization remains test-only and constructs the adapter on
demand; stateless audit hashing and profile translation retain their algorithms.
HTTP backup fixtures now exercise the native v2 generator with real current
audit/authority/writes and an explicitly synthetic commitment-port test double.
They do not claim a complete memory commitment. Additional regressions cover
read-only guards, replay without regeneration, detached stored results,
foreign/invalid commitments, cancellation and commit rollback. Production API,
storage, immutable hash and recovery contracts are unchanged. Remaining
worker/state/snapshot retirement and required full/race/live gates keep EVY-906
open; no SQL durability or restore claim follows from these fixture tests.

PostgreSQL recovery fixtures now generate backup manifests with the focused v2
command and actual complete commitment/audit readers, not the Ledger facade.
Their release setup uses the transaction factory directly; two unused Ledger
constructions are removed. Existing restore assertions remain unchanged, with
additional v2 schema, tenant and evidence/bundle count checks. A regression
rejects incomplete memory commitment capabilities without returning a manifest
or writing state; no partial snapshot is labeled a full backup profile.
Production contracts are unchanged. Remaining aggregate cleanup keeps EVY-906
open; live recovery validation is still required.

Retired the broad Identity aggregate adapter, its Service field and constructor
wiring, and Ledger bootstrap/authentication facades from production source.
Historical behavior remains in test-only oracles, constructed on demand; real
stateless SSO verification/assurance adapters and shared detached value mappings
remain unchanged runtime dependencies. PostgreSQL setup now uses focused
Identity/initial-signing commands and native Store authentication. Memory-backed
regressions cover real identity/audit/signing commits, current tenant ownership,
activity writes, wrong peppers, cancellation, secret-safe metadata and final
commit rollback. Existing assertions, API, storage and credential contracts are
preserved. Remaining Verification, worker/state and aggregate cleanup plus
required full/live validation keep EVY-906 open; compilation is not SQL restore
or durability evidence.

HTTP fixture setup no longer calls aggregate bootstrap/authentication facades.
Shared scope seeds and direct setup callers use focused Identity/initial-signing
commands and current-row authentication with explicit credentials and time.
Factory and root-context executor setup share core preparation/commit logic;
failed commits, missing repositories and cancellation return no identity or
one-time secret and publish no partial state. Fixture rebinding preserves explicit
authentication ports. Cache-only negative fixtures retain genuine stored rows
without gaining repositories or a fallback; their selected cache is not a full
backup. Existing assertions and production API/storage behavior are unchanged.
Remaining aggregate retirement and full-ticket validation keep EVY-906 open.

Retired Ledger-backed API-key/session credential adapters and its hash method
from production source; the remaining Identity adapter uses the context-owned
HMAC capability. Historical format oracles pin prefixes, 32-byte URL-safe token
encoding, stored hashes and comparison behavior. The common HTTP fixture now
uses native repository bootstrap, and session authentication no longer falls
back to cached API keys. Wrong-pepper, cancellation and activity-commit failure
regressions return no principal or partial state. Dedicated cache-only negative
fixtures and existing transport assertions are retained. Wire/storage contracts
are unchanged; remaining Identity/Verification, bootstrap and aggregate cleanup
keep EVY-906 open, with no new SQL locking or durability claim.

Moved the common repository-backed HTTP fixture bootstrap and authentication
onto focused Identity/initial-signing-key commands and current rows. Credentials
and clocks are explicit; derived servers inherit configured authenticators
without changing cookie, origin, bearer-precedence or error assertions.
Regressions cover cold-instance authentication, wrong peppers, secret-safe
public metadata and atomic bootstrap failure. Retired two unused cached API-key
creation helpers from production. This is a prerequisite for the remaining
Identity/Verification aggregate retirement under EVY-906, not its completion or
new live PostgreSQL evidence; production startup and wire contracts are unchanged.

Retired 25 cached readiness, control-report, VEX decision/finding and build-policy
authority routines, the old control-report DTOs, and unused OpenVEX wrappers
from production source. Historical behavior remains characterized in test-only
oracles; AST checks prevent reintroduction. Native bounded readers, shared domain
policies and real VEX parsers are unchanged. Only detached time/reference copies
remain in the VEX value boundary. This does not change report, API, persistence
or immutable hash contracts, or retire the remaining Identity/Verification,
bootstrap, worker and aggregate state paths under EVY-906.

Retired the broad Release aggregate adapter, its Service field and constructor
wiring, fourteen command/read facades, three workflow input DTOs and cached
candidate-reference validator from production. Historical characterization
remains test-only; shared pure value mappings and still-used authorizers remain
explicit. HTTP and PostgreSQL test setup uses focused commands rather than
aggregate mutation facades. Signed attestation fixtures retain real explicitly
bound object resources, and missing-repository tests load genuine cached rows
without adding a fallback. Existing API, storage, replay and hash contracts are
unchanged. Remaining Identity, Verification, state and worker aggregate cleanup
and required live validation keep EVY-906 open.

Retired cached artifact/image registration replay guards from production source.
HTTP fixtures compose focused Release commands over current identity, grant and
bounded metadata reads, retaining cookie/origin assertions. Regressions cover
cold instances, revoked grants, omitted existing image attachments, exact large
integer sizes, immutable duplicate reuse and final write-commit rollback. The
PostgreSQL queries, wire contracts and natural-key identities are unchanged;
memory fixtures do not prove database locks or durability. Remaining Release
adapter and aggregate retirement stay open under EVY-906.

Retired ten cached catalog, transition, build, candidate and attestation replay
guard declarations from production source. HTTP fixtures use the focused Release
commands and Evidence capability over current repository-only parents, retaining
tenant/grant checks, revision conflicts, cookie/replay assertions and atomic
write-commit rollback. Immutable build source identity now retains exact JSON
numbers through memory transactions, PostgreSQL's selected snapshot decoder
and attestation evidence creation. Null selected builds fail closed. Existing
API, schema, selection budgets and normalized hash profiles are unchanged.
Memory and pure-decoder tests are not live SQL or storage evidence; the remaining
Release adapter and aggregate cleanup stay open under EVY-906.

Retired the broad Evidence aggregate adapter, its Ledger Service field and
constructor wiring, local VEX decision processor, object-ingestion wrappers,
and generic creation/relationship/replay facades from production source.
Historical characterization stays test-only; real parsers and shared value
mappings remain. HTTP fixtures compose focused commands over current typed
ownership and bounded origins, with no cache publication. Evidence and lifecycle
JSON numbers survive memory transactions without rounding. Tenant/grant,
cancellation, exact-budget and real write-commit rollback regressions preserve
existing API, immutable hashes, redaction and storage contracts. Memory tests
do not prove SQL locks or durability; remaining aggregate removal is EVY-906 work.

Moved the immutable v1/v2 backup-commitment resource vocabulary into the
Verification application context. PostgreSQL consumes the same ordered fields
directly; frozen header vectors pin both profiles and caller copies cannot
mutate their definitions. The 97-resource v1 and 98-resource v2 declarations,
digest framing, SQL selection and response contracts are unchanged. This is an
architecture prerequisite, not backup-generation aggregate retirement or live
backup/schema/restore evidence; EVY-906 remains open.

Retired the generic Ledger verification facade from production source. Full-chain
and both signed-checkpoint HTTP fixtures use focused commands with current bounded
audit pages, public signing material and tenant-wide grants. Recovery verification
uses native readers. Fixed release-bundle replay ownership to consult release
records rather than evidence-export records, and preserved exact canonical audit
JSON integers through memory transactions and the PostgreSQL page decoder.
Release-manifest checkpoints accept exact JSON-number integers without rounding.
Replay, failed GET/POST and atomic rollback regressions retain existing profiles
and contracts; no external anchoring or SQL durability is claimed from memory
fixtures. Broader aggregate removal remains EVY-906 work.

Retired the Ledger DSSE verification and generic cache-based verification replay
guards from production source. Both DSSE HTTP fixture paths use focused commands,
current typed ownership/policies, explicit bounded object storage and finalized
payload bindings. Registered release-linked outputs remain the expected subjects;
parsed claims do not grant trust. Signed-envelope, conservative unconfigured-root,
replay and atomic rollback regressions preserve the existing offline assurance
profile and API/storage contracts. Historical memory fixtures are not SQL locking,
live-provider or worker-durability evidence; EVY-906 remains open.

Current source retires the `local_memory` API profile. Local evaluation now
requires `EVYDENCE_RUNTIME_PROFILE=postgres` and `EVYDENCE_DATABASE_URL`.
Startup rejects the retired profile before resources or credentials are opened,
and no longer constructs Ledger or `app.Config`. Existing payload files are not
deleted or imported. Fast in-memory unit-test fakes remain supported; the local
CI simulation uses an owned disposable PostgreSQL schema. See the
[configuration migration note](docs/reference/configuration.md#retired-local-memory-profile-unreleased).
Older published release binaries are not changed by this source update.

Customer-package access now preserves exact frozen JSON numbers and applies
the existing creation depth/collection limits to stored manifests. Counter
updates cannot overwrite frozen fields with a sanitized delivery view. The
aggregate access/report/archive facades are retired from production source;
routes and valid package contracts are unchanged. See [access compatibility](docs/reference/api-versioning.md#unreleased-customer-package-access-boundary).

Retired Ledger custom-report template/rendering and bundle-import facades,
cache-based replay guards and obsolete report input types from production
source. HTTP fixtures now exercise focused commands over current repositories,
preserving inert metadata reports, target-tenant import receipts and atomic
audit/rollback behavior. Native API and persisted contracts are unchanged;
remaining aggregate retirement is still EVY-906 work.

Retired Ledger release-bundle creation and replay-guard facades from production
source. Creation/verification fixtures now use current repository snapshots,
local signing keys and scoped public verification material, with atomic
signature/bundle/audit/job and receipt/audit/job effects. Recovery and concurrency
seeds also use focused creation. Native API and persisted contracts are unchanged;
memory fixtures remain test-only, and broader Ledger retirement is unfinished.

Retired Ledger evidence-bundle export and its cache-based replay guard from
production source. HTTP fixtures use focused commands over current repositories,
preserving grant-filtered selection, original-selection replay authorization,
local signature validation and atomic bundle/signature/audit effects. Existing
API and persisted contracts are unchanged. Memory fixtures remain test-only;
broader aggregate retirement remains unfinished under EVY-906.

Removed the aggregate Package adapter and its Ledger service field/constructor
wiring from production source. Historical characterization tests compose the
old reader/signer/transaction bridge only in test builds. Three still-used pure
DTO/error/signature-clone helpers retain their existing behavior. Native API
and storage contracts are unchanged; EVY-906 aggregate removal remains open.

Retired the aggregate Package metadata builders and static-template catalog
facade from production source. Customer/portal ZIP rendering now belongs to
the Package application package, with the existing access boundary, archive
bounds, privacy checks, fixed entries and HTML escaping. Static HTML now shows
stored JSON-number cells without floating-point rounding; regenerated ZIP
bytes/hash can therefore differ while frozen manifests/hash stay unchanged.
See [archive compatibility](docs/reference/api-versioning.md#unreleased-customer-package-access-boundary).
Other Ledger retirement remains EVY-906 work.

Retired Ledger key rotation/revocation/replay-guard and signing-provider/DSSE
trust-root creation facades, plus their obsolete input types, from production
source. HTTP fixtures now use focused commands over current repository rows,
with bounded public key metadata, ownership-only replay, real local key
generation, private-byte cleanup and atomic lifecycle/trust/audit effects.
Existing routes, JSON fields and key policy/storage formats are unchanged.
Memory fixtures remain test-only, not SQL locking or external custody evidence;
other aggregate retirement remains EVY-906 work.

Evidence canonical and detached artifact-signature metadata verification fixtures
now compose focused commands over current typed ownership/facts, not aggregate
maps. Evidence point/verification reads share detached exact-number provenance;
selected legacy origins retain the same combined byte/count limits. Signature
metadata reads select digest labels and presence only, not signature/algorithm
text, objects or trust roots. Product-scoped canonical grants and tenant-wide
detached-signature grants remain distinct; receipt/audit/job commit rollback has
regressions. The map-based evidence-creation guard and artifact-association matcher
are test-only. Existing canonical/hash profiles and metadata-only `limited` state
are unchanged; these fixtures are not SQL durability, payload-authenticity or
cryptographic-trust proof. EVY-906 remains open.

Retired the Ledger backup-manifest verification facade from production source.
GET and generic POST fixtures now use the focused recorded-check command over
current typed manifest facts, not an aggregate cache. Reads omit unused manifest
metadata, detach checks and preserve exact byte/count bounds; replay guards read
only ownership. Tests retain presence-only legacy receipts, failed direct/GET
receipts, failed POST rollback, current-grant replay checks and atomic commit
rollback. Existing profiles, checks, hashes and stored records are unchanged.
These fixtures prove neither live backup contents nor restoration or SQL
durability; remaining aggregate retirement stays EVY-906 work.

Retired Ledger object-retention creation/verification facades and their input
type from production source. HTTP fixtures compose the focused commands over
current tenant/policy repositories, bounded detached policy reads and explicit
provider observations. Ownership-only guards do not read receipt metadata or
contact providers; same-status observation races and policy/audit commit rollback
have focused regressions. No configured provider remains `not_verified`, and
unavailable-provider receipts omit raw errors. Policy fields, hashes, expiry and
no-outbox behavior are unchanged. These tests do not prove real-provider
enforcement or SQL durability; EVY-906 remains open.

Retired Ledger Merkle-batch creation/verification and recorded-checkpoint
creation facades and their input types from production source. HTTP fixtures
now use focused commands over current sequence/hash views, batch ownership/roots and local signing
rows, with private-material validation/cleanup and atomic signature/batch/audit
or checkpoint/audit effects. Existing ranges, hashes, Ed25519 format, JSON
contracts and creation no-outbox behavior are unchanged. Merkle verification
uses the current stored batch and selected public material, with receipt/audit/job
atomicity; the create-and-verify flow no longer depends on a stale aggregate cache.
Malformed stored ranges still reach negative inspection, not a validation-only
abort. Memory fixtures remain test-only, not SQL locking, external custody or
publication evidence; EVY-906 remains open.

Customer-visible vulnerability-decision summaries now fail closed above 4,096
selected decisions or an 8 MiB selected text/encoded-container budget, before
PostgreSQL transfers decision metadata. Oversized summaries return no partial
report. Current grants, active/customer-visible filtering and private-note
omission are preserved; see [summary limits](docs/api.md#3-upload-sbom-and-vulnerability-evidence).

Vulnerability-decision history pages now preflight the selected page plus
lookahead against an 8 MiB text/encoded-container budget before PostgreSQL
transfers metadata. Oversized windows fail without partial items or cursors.
Explicit parent-filter authority is checked before metadata selection; cursor
formats, response schemas, current grant filtering and the 500-record per-page
limit are unchanged. Remaining Ledger retirement is still EVY-906 work; see
[history page limits](docs/api.md#decision-history).

SBOM component paging now excludes artifact evidence/build associations whose
supplied release disagrees with the SBOM release, before applying page limits.
This prevents inconsistent associations from producing projection conflicts;
coherent current grants retain access. Public schemas, cursor binding and the
500-record per-page limit are unchanged. Test fixtures now use focused queries
and can traverse inventories larger than 500 components. EVY-906 remains open.

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

Readiness, metrics, instance-count diagnostics, outbox diagnostics and terminal
job replay handlers now require focused Operations ports. Six aggregate
fallbacks are removed without changing native response formats, instance-admin
authorization, dependency retry metadata or atomic PostgreSQL replay. Test-only
fixtures retain read/retry checks; external fixture operator calls are not
claimed to be rollback-safe SQL transactions. Remaining aggregate deletion is
still unfinished under EVY-906.

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

Organization creation, user creation/deactivation and role assignment now
require focused Identity commands. Four handler fallbacks and four broad
transport-interface methods are removed. Native validation, current authority,
atomic replay, session invalidation and public DTO contracts are unchanged.
Test-only adapters use actual focused preflight against transaction-owned
memory references and preserve real isolated writes, with complete rollback,
replay, tenant/parent, privacy and cancellation regressions. Affected references
now require PostgreSQL for evaluation. Other identity/session and aggregate
retirement remains unfinished under EVY-906.

SSO provider registration, trust rotation/discovery and identity linking now
require focused Identity commands. Four handler fallbacks and four broad
transport-interface methods are removed. Native public-trust validation,
current authority/ownership/email checks, replay and PostgreSQL transactions
are unchanged. Test-only guards use focused bounded memory readers and retain
real isolated writes, with rollback, public DTO replay, no-refetch, tenant,
privacy and cancellation regressions. Memory bridges do not prove SQL locking,
provider configuration or durability. Remaining session and aggregate cleanup
is still unfinished under EVY-906.

SSO session issuance, exchange, revocation and logout now require focused
Identity commands. Their four aggregate handler fallbacks and the entire broad
`identityAccess` Server field/interface are deleted. Native one-time secrets,
credential verification, current authority, replay, revocation and post-commit
cookie behavior are unchanged. Test-only memory readers and adapters preserve
real isolated writes and public exchange, with secret-free saved responses,
rollback, current-tenant/session, cancellation and cookie regressions. Affected
references require PostgreSQL for evaluation. Other aggregate retirement and
full-ticket validation remain unfinished under EVY-906.

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

Control/framework creation, starter installation, evidence linking and their
definition/catalog/link reads now require focused Risk ports. Eight handler
fallbacks and three aggregate-only input converters are removed. Native
validation, grants, atomic replay and public DTO/cursor contracts are unchanged.
Test-only fixtures retain real guards/isolated writes and add full-state
rollback/replay, complete-page tenant filtering, cancellation and detached
definition regressions. The legacy template-install command now records human
audit identity correctly; the production PostgreSQL command already did so.
Affected API descriptions no longer advertise local-memory evaluation.
Other aggregate dependencies remain unfinished under EVY-906.

Custom-policy creation/evaluation, vulnerability workflow annotation, release
security summary and vulnerability posture handlers now require focused ports.
Five aggregate fallback paths are removed; native guards, durable replay,
structured decoding and public DTOs are unchanged. Test-only regressions cover
full-state rollback/replay, current grants/foreign parents, report completeness,
privacy, cancellation and detached metadata. Historical custom-policy commands
now attribute human audits correctly; native PostgreSQL already did so.
The memory Risk test adapter now exposes identifier-only workflow ownership
reads, including release-less scans, without consulting vulnerability text or
historical reasons. It remains a test backend, not SQL locking evidence.
Affected API and architecture descriptions require PostgreSQL local evaluation.
Remaining aggregate cleanup and final ticket gates are still unfinished.

Artifact-signature recording and point reads now require focused Verification
ports; both aggregate handler fallbacks are deleted. Native authorization,
decoding, atomic replay, canonical payload references and digest query contracts
are unchanged. Test-only regressions use actual filesystem staging and cover
full repository rollback, no restaging on replay/denial, current grants/tenants
and complete public metadata without raw payload bytes. The legacy signature
command now records human audit identity correctly; native PostgreSQL already
did so. Affected API descriptions require PostgreSQL local evaluation.
Other aggregate cleanup remains unfinished under EVY-906.

Control coverage, CRA readiness/vulnerability handling, security-update,
missing-evidence and both release-bundle reads require focused queries. Seven
aggregate handler fallbacks are deleted; native filters, current grants/parents,
bounded SQL, errors and public DTOs are unchanged. Test-only report readers add
whole-state read-only, complete DTO, privacy, cancellation and nested metadata
detachment regressions. Missing-evidence fixtures use a pure readiness preview
and the existing renderer without creating policy evaluations or audits.
The memory repository now recognizes owned control-scoped exceptions while
rejecting foreign/missing controls. API descriptions require PostgreSQL local
evaluation. Remaining aggregate deletion and final ticket gates stay open.

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
