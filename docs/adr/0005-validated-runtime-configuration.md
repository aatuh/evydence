# ADR 0005: Validated Runtime Configuration

Status: accepted for the EVY-1214 immutable-input/schema/validation foundation
and EVY-1215 bounded project-secret resolution with explicit native SDK ownership,
reviewed and validated 2026-10-17. Command adoption and generated deployment
documentation remain EVY-1216 and EVY-1217. This is an explanation for developers
maintaining startup and configuration boundaries.

## Decision

Build the project-owned configuration schema and typed loader under
`internal/platform/config`. Capture the supplied process environment once,
without consulting ambient environment variables inside the input object.
Parsing must finish before an enabled runtime opens listeners, starts providers
or mutates storage. Secret resolution follows validated references and has an
explicit filesystem/provider owner.

The input foundation retains selected values privately and preserves explicit
empty values and raw whitespace for the eventual field-specific parser. It
captures `ENV`, `CI`, `EVYDENCE_*`, the AWS, Google, Azure and GitHub namespaces,
and declared native PostgreSQL, credential-discovery and host/transport names.
Unrelated host settings are not configuration values. Capture bounds total input
to 4096 entries and 8 MiB, selected settings to 1024, and selected names to 256
bytes. Project names use uppercase ASCII environment syntax internally. On Windows,
capture canonicalizes case-insensitive native names and project namespaces before
selection, duplicate detection and fingerprinting. Values and empty presence stay
exact; case collisions fail. On case-sensitive hosts, spellings remain distinct.
Exact declared native spellings also admit lowercase proxy fallbacks and Windows
`ProgramData`/`NoDefaultCurrentDirectoryInExePath`.
NUL and malformed UTF-8 selected input are rejected. Duplicate selected names fail instead of
depending on process-environment ordering.

The input's string, Go-syntax and JSON representations disclose neither names
nor values. Validation failures use fixed diagnostics. An internal fingerprint
supports change detection; it is not an evidence digest, credential identifier
or public configuration dump. Captured input and returned metadata remain owned
by the configuration package.

The code-owned catalogue currently records 109 project option definitions with process
roles, value kinds, defaults, secret classification, observed numeric bounds,
aliases and production restrictions. Conditional defaults remain explicit:
runtime profile selection is required, while PostgreSQL load mode has different
defaults inside and outside production. Public metadata access returns sorted
copies, including owned slices for allowed values and aliases.

`NativeDefinitions` extends the same metadata type with a native boundary,
target parameter and pinned source. Its PostgreSQL entries describe the complete
`parseEnvSettings` mapping in `github.com/jackc/pgx/v5 v5.9.2`. They share the
DSN parameter types, choice sets and bounds. Native inputs remain optional,
beneath explicit connection parameters. Capturing them preserves exact values,
explicit emptiness and fingerprint changes with the existing redaction,
duplicate, UTF-8, NUL and combined-size protections. Arbitrary `PG*` names remain
outside the selected input. Tests pin this metadata to the actual module
requirement and check owned copies independently.

The native catalogue now contains 107 definitions covering 114 distinct names:
22 PostgreSQL, 50 AWS, three Google, 21 Azure/MSAL/core and 18 host/transport inputs.
AWS includes the KMS, STS, SSO, SSO OIDC and Signin endpoint names computed from
service identifiers. The Google boundary includes metadata-host overrides and
the external executable opt-in; Azure includes transitive managed-identity inputs.
These declarations use the existing module pins and add no SDK initialization.

Transitive Azure core coverage includes `AZURE_SDK_GO_LOGGING` and Windows `OS`.
The shared logger installs a raw stderr listener at package initialization when
its value is exactly `all`. Input grammar accepts optional empty, `off` or `all`;
API production policy rejects `all`, including when another signer is selected.
The Windows OS telemetry label is bounded to 256 bytes and rejects control
characters. These are intentional earlier rejections. Native production policy
uses the same schema-owned restrictions as project options; returned metadata
cannot weaken it.

Capturing these inputs cannot undo SDK package initialization. Later provider
composition must explicitly own the process-global listener and telemetry before
SDK clients are used, so an earlier ambient value cannot bypass captured policy.
The pure parser neither changes SDK globals nor claims to make a provider ready.

The release script includes Windows builds. The host catalogue therefore includes
`PATHEXT` and `NoDefaultCurrentDirectoryInExePath`, reviewed against the pinned Go
Windows lookup implementation. `PATHEXT` uses a bounded semicolon-separated list,
lowercase suffixes with a leading dot, and skips empty items. Suffixes allow ASCII
letters, digits, dots, underscores and hyphens; path separators, colons, whitespace
and a bare dot fail earlier than native lookup. No extension defaults are added.
An effective empty list remains distinct from absent/empty input. The directory
switch depends on presence even when empty, so its consumer must use `Present()`.
This captures lookup inputs; it does not run or authorize credential helpers.

Ordered `Fallbacks` retain native precedence separately from conflict-checked
project aliases. Each supplied spelling remains independently captured, including
explicit empty values. In the pinned Go 1.26.9 transport, uppercase proxy values
precede lowercase fallbacks. The separately pinned `x/net` helper reverses that
order; using its ambient loader would change behavior. Proxy URLs are classified
as secrets because they can contain credentials. Host inputs now include native
credential directories, executable search paths and system TLS trust overrides.
Their captured values are never opened or executed by this phase.

The role-input evaluator now includes native primitive parsing. Private typed
state retains every supplied spelling and its exact bytes, including empty
values; selection uses the declared first-nonempty fallback order. Bounds,
UTF-8/NUL checks and fixed diagnostics reuse the shared scalar foundation.
Implicit formatting and JSON redact both raw and parsed native values.

Native case, empty-value and control-character rules belong to schema metadata.
PostgreSQL choices and AWS account endpoint modes remain case-sensitive. Azure's
`dev`/`prod` selector values are exact, while credential class names are
case-insensitive. An absent Azure selector is allowed; a present empty value
fails. Native booleans and numbers reject surrounding whitespace. Opaque secret
bytes remain unchanged; full authorization values can contain spaces but reject
control characters. This parsing performs no ambient reads or external resolution.

Malformed flags that previously fell back silently now fail: this includes AWS's
metadata-disable flag and Azure's certificate-chain flag. Native retry counts are
bounded to 2,147,483,647, seconds conversion checks overflow, and native file
references have a 4096-byte bound with blank/control-bearing paths rejected.
These tightening rules apply to the new private evaluator; command adoption is
still pending.

Native endpoint and list syntax now follows schema-owned policies. Native service
and identity-authority base URLs require HTTPS, matching project-owned KMS base
endpoints. Credential/metadata endpoints retain their HTTP/HTTPS forms, paths and
valid queries. Supplied literal HTTP addresses for AWS container credentials must
match its loopback/ECS/EKS ranges. Hostnames still require the native SDK's
DNS/destination checks during explicit resolution; parsing performs no lookup.
Google metadata overrides accept host/port authorities, and relative container
credential URIs cannot introduce a scheme, authority or fragment.

Proxy input retains host/port shorthand, HTTP/HTTPS and SOCKS5/SOCKS5H, including
userinfo credentials. Ignored proxy paths/queries now fail. Shared URL checks
reject ambiguous unbracketed IPv6, malformed brackets/ports, scoped IPv6,
fragments and invalid query escaping with input-free errors. The unbracketed-IPv6
fix also covers project-owned base URLs.

PostgreSQL native host/port lists are bounded to 16 entries, sharing the explicit
DSN host checks and retaining bare IPv6, Unix socket directories and leading-zero
ports. Other declared lists are bounded to 256 entries before splitting, with
4096-byte items. PATH uses the target platform separator; Unix certificate
directories use colons. Empty path-list entries retain native semantics. No-proxy
rules retain domain suffixes, wildcards, ports, IPs and CIDRs; malformed rules now
fail instead of being silently ineffective. Auth-scheme whitespace/empty handling
matches the pinned AWS helper; malformed additional-tenant entries fail. These
list bounds and earlier rejections are deliberate tightening rules. Parsed URLs,
ports and items stay private and redacted alongside exact supplied bytes.

Native default/service and credential resolution remain separate. Native
PostgreSQL defaults call OS user lookup and inspect home certificate files;
their resolution retains the explicit pgx owner documented below. EVY-1216 must
adopt validated input before entering that boundary. Capture performs none of
these operations and exposes no generic environment forwarder.

A source test scans production Go literals and fails when a selected environment
name is missing from the catalogue. A second AST guard resolves current project
`os.Getenv`/`os.LookupEnv` reads and injected string readers through constants,
bounded concatenation, local helper parameters across package files and finite
range lists. Every resulting name must belong to the project or native schema.
Unsupported expressions, unresolvable callers, reader aliases and escaping
global lists fail the guard. Constant initializers retain their lexical scope.

The guard explicitly recognizes existing reader forwarding to startup logging
and configuration-freshness probes. These exceptions authorize no new runtime
environment shim; EVY-1216 must replace the ambient reads. The guard supports a
small finite source grammar, not arbitrary Go evaluation or every transitive
SDK credential-chain option. New forms need explicit review and guard coverage.
Catalogue metadata alone does not change command behavior.

`testdata/native-boundary-review.json` commits 44 reviewed source records with
hashes, scope and findings. Their hashes were checked against the actual checkout
and pinned SDK/toolchain files. Tests require every native schema source to have
a review record, pin the reviewed dependency versions, and check repository-owned
boundary hashes without fetching SDK source or invoking loaders. This records the
currently wired credential paths, including their transitive environment reads;
it does not assert that arbitrary SDK APIs or subprocess environments are covered.
For example, explicit `AzurePipelinesCredential` is outside the current default
Azure chain. Existing process-credential inheritance, external helper execution,
file-backed profiles, metadata access and native defaults retain the SDK owners
documented below. Command adoption must enter those boundaries explicitly;
they are not additional parser side effects or project-file safety guarantees.

The package-owned scalar parser produces booleans, bounded integers/durations,
canonical choices, masked CIDR prefixes, decoded base64 bytes and UTC timestamps.
Errors use one fixed diagnostic and return no partially parsed value. Scalar
formatting and JSON are redacted, including for values not classified as secrets.
Raw string-like inputs remain unchanged for dedicated validation: PostgreSQL
accepts connection strings and S3 accepts `host:port`. Project paths have explicit
4096-byte bounds and reject nonempty blank values and control characters before any
filesystem access. Optional empty values remain valid, including PostgreSQL TLS
path clearing. The shared path grammar also checks DSN file parameters.
Otherwise path bytes, spaces and relative-path support are
preserved; this phase does not establish existence, file permissions or reference
containment. Earlier rejection of control characters and migration/object paths
above 4096 bytes is intentional tightening. Scalar parsing performs no file or network access and
does not enforce required roles, aliases, production or cross-field constraints.

The schema retains the existing 65,536-byte tenant-name and 1 MiB decoded Sigstore
limits. The new parser deliberately limits proxy CIDRs to 256 entries before
allocation. Explicit booleans accept only `true` or `false`, case-insensitively
with surrounding whitespace; other spellings fail. Malformed or out-of-range
numeric inputs fail instead of silently falling back, and seconds conversion
checks duration overflow. These tightening rules are not adopted by command
startup until EVY-1216. Missing optional values and dynamic defaults remain the
responsibility of the role-aware loader rather than this scalar primitive.

The role-input evaluator applies process requirements and schema defaults,
including production/non-production PostgreSQL modes and the credential-dependent
worker metrics address. It rejects conflicting nonempty aliases, unknown
`EVYDENCE_*` names in production, production-forbidden booleans and disallowed
production choices. Diagnostics and returned input remain redacted, with no
partially resolved result after failure. Only options belonging to the selected
role are parsed; inactive provider options within that role are still checked.
AWS/Google/Azure/GitHub namespace inputs remain captured for their explicit native
SDK/CI boundaries rather than being treated as unknown project settings.

This is a private intermediate representation, not a public environment accessor.
Typed configuration now projects all 109 schema options into runtime, API, worker,
storage, provider and CLI settings. Settings are returned as value copies; CIDRs
and decoded trust material use accessors that clone slices. Credentials use an
opaque `Secret` with explicit `Reveal`/`IsSet` access. Every settings container and
secret redacts string, Go-syntax and JSON formatting. Projection supplies no
defaults and does not retain mutable parser slices. Tests check each declared
field's source independently, so identical defaults cannot conceal missing or
misrouted values.

Native settings now project all 107 native definitions into PostgreSQL, AWS,
Google, Azure and host groups. Each field has an explicit type and schema tag;
source-by-source tests check complete coverage and correct scalar/list/URL reads.
`NativeOption` distinguishes absent input, supplied empty input and an effective
first-nonempty value. Explicit zero and false remain effective values. Projection
adds no SDK defaults or new requirements, and preserves role filtering and native
fallback order.

All native groups/options redact formatting and JSON. Secret values use `Secret`;
parsed URLs use a redacted `NativeURL` with explicit `URL()` access, protecting
proxy userinfo during ordinary formatting. Lists are copied during construction
and on `Value()` access. URL access returns a value copy; its userinfo type is
immutable. Configuration also retains owned copies of all private database input
layers for later bounded resolution.

The public `Parse(Environment, Role)` now composes role parsing/validation with
owned typed projection. It returns zero settings on failure and reads no ambient
environment, clock, files or providers. Public-API tests parse captured values
while ambient inputs are poisoned and reference nonexistent credential/service
files. Parsed configuration is input validation, not proof that references are
resolved or a runtime is ready. Native optional/fallback behavior stays intact:
partial credentials can be completed or bypassed by the SDK's later file/profile
chain, so parsing does not invent unconditional credential requirements.

Local validation rejects SSO idle time beyond the maximum lifetime, blank
bootstrap names, unsupported API address syntax, multiple production writers,
the existing development pepper in production, unpaired or malformed revisions,
and invalid private worker listener configuration. Revision files and metrics
credentials are syntax-checked without opening them. Metrics and health cannot
bind the same address/port, including equivalent IPv4-mapped forms. The existing
metrics address/file bounds are in the schema; revision paths additionally have
a 4096-byte bound. API numeric port zero remains valid for ephemeral listeners.
An AST characterization test ties the transitional pepper rejection to the
existing identity-owned compatibility constant without coupling this package to
application code. EVY-1216 must retire duplicate startup policy during adoption.

HTTP endpoints now carry schema-owned policies: TLS base endpoints for native
KMS, guarded gateway endpoints, same-origin gateway readiness endpoints, and
HTTP/HTTPS base URLs for the self-hosted CLI. URL credentials, fragments, malformed
ports/escapes, scoped IPv6 and non-IP bracketed hosts fail with fixed diagnostics.
KMS/CLI base endpoints reject query strings; ordinary gateways retain valid query
parameters. Readiness rejects query delimiters as well as query values.

Gateway validation calls `httpclient.ValidateStaticEndpoint`, sharing the existing
request policy's scheme and prohibited literal-address rules. HTTP loopback still
requires its explicit non-production override. DNS is not resolved during parsing;
hostnames must pass DNS/rebinding checks again at request time. Native KMS endpoints
retain operator-controlled HTTPS endpoints, including private emulator endpoints,
rather than acquiring the gateway policy's destination restrictions.

The signing, identity-validation and transparency gateway constructors also use
the shared policy for their HTTP exception. This replaces prefix-based loopback
checks, accepts normalized localhost and mapped IPv4 loopback forms, and rejects
hostnames such as `127.evil.invalid`. Their HTTPS construction contract remains
unchanged; request-time destination policy still applies to every request.

Signing validation requires the selected profile's region/key, GCP key-version
resource, Azure vault/key/version, or external/HSM gateway as applicable. Provided
inactive endpoint/key settings are still syntax-checked; unused gateways do not
acquire required credentials or trigger resolution. Gateway verification keys must
be 32-byte Ed25519 public keys. Header-bound tokens reject internal whitespace and
control characters. Readiness must match the signing URL's scheme, host and
effective port. A missing readiness URL remains constructible, preserving the
existing signing-only contract; it does not establish operational readiness.

These constraints intentionally reject malformed inactive endpoints, native base
URL queries, noncanonical key-resource paths and invalid header credentials earlier
than adapter construction. The Azure algorithm uses the schema's `ES256` choice.
Whitespace-only text normally uses its code-owned default; explicit raw-input
metadata preserves tenant names, S3 credential bytes and projected revision/metrics
inputs. In particular, blank projected-file input fails rather than silently
disabling the feature. This avoids hidden adapter defaults for blank version/status
settings without normalizing credential bytes.

S3 configuration now shares the adapter's endpoint/TLS/region policy under this
package. The adapter maps validation failures back to its existing application
error; configuration failures retain fixed, input-free diagnostics. Both paths
use the pinned MinIO SDK's pure domain and basic bucket-name validators without
constructing a client. This preserves the existing legacy bucket grammar rather
than silently replacing it with the SDK's stricter optional grammar.

Selecting `s3` or `minio` requires its endpoint, bucket and both credential fields.
Provided inactive endpoint/region/bucket settings are still validated; inactive
storage does not acquire missing credentials or contact a service. Credentials
retain their exact bytes. Existing private/loopback/cluster cleartext exceptions
and public TLS/region requirements remain explicit. The public-IPv6 cleartext
bypass is fixed by classifying IP literals before the single-label hostname
exception; unspecified, multicast and other non-private IPv6 no longer inherit
that exception. Malformed bracketed/unbracketed IPv6 and SDK-invalid domains fail
before SDK construction. This phase does not establish bucket existence,
provider identity or retention configuration.

Database DSNs now have a dedicated schema kind and pure grammar adapted from the
pinned pgx URL/keyword parsers. The upstream MIT notice is retained in
`internal/platform/config/database_dsn.LICENSE`. This layer preserves supported
quoted/escaped values, Unix sockets, multi-host URLs, `dbname` mapping and URL
query overrides without consulting driver defaults, environment or files.
Native URI handling retains the pinned driver's `net/url` compatibility limits.
Parsed settings redact formatting and JSON; errors return neither input nor
partially parsed settings.

Runtime roles now keep separate owned native, explicit-DSN and pre-service
candidate layers. Individual values are checked before merging; DSN settings
override captured `PG*` values. Explicit empty passwords clear native passwords,
while empty DSN users retain pgx's ignored-empty-user behavior. Known certificate/
key and protocol relationships are checked after the merge, so a certificate in
the DSN can pair with a captured `PGSSLKEY`. The merged parameter set is bounded
to 128 entries as well as the explicit parser's 128-pair bound.

A selected service marks this private input as unresolved. Its settings belong
between native and explicit layers and can fill missing fields or override native
values. The pure evaluator still rejects contradictions fully specified by the
DSN; it leaves unknown service-supplied relationships for native pgx resolution.
It never opens a service file or claims that this candidate is a complete
driver configuration. Standalone DSN validation retains its strict complete-pair
checks. Native numeric/duration fields reject surrounding whitespace, including
inside quoted DSN values, matching the pinned driver/pool parsers.

The grammar limits explicit pairs to 128 and hosts/ports to 16, before allocating
large query/host collections. Conflicting repeated settings, invalid escapes,
decoded NUL/malformed UTF-8, fragments and truncated quoted/backslash input fail.
The structured keyword scanner bounds escape/closing-quote access. Known explicit
connection/pool/cache/TLS/protocol settings use shared scalar types and bounds;
native choices remain case-sensitive. Timeout multiplication cannot overflow,
pool/cache counts cannot be negative, health periods must be positive, supplied
minimum pool counts cannot exceed a supplied maximum, and TLS cert/key references
must be paired. Unknown `pool_`/`ssl` controls fail; other runtime GUCs remain
driver/server-owned. These are deliberate tightening rules, not driver defaults
or proof of an accepted live connection.

Sigstore trust parsing uses the pinned library's JSON and public-key parsers
without file access, TUF refresh, network discovery or live trust updates. Each
supplied root/key is bounded to 1 MiB; the required version label is bounded to
256 bytes and rejects malformed UTF-8 and control characters. Version labels
alone do not enable verification. Public keys must contain exactly one PKIX
`PUBLIC KEY` PEM block, without headers, ignored prefixes, extra blocks or trailing
content. Supplied bytes are copied before parsing. The opaque result redacts
formatting/JSON and exposes material explicitly to the trusted adapter; library
causes never enter configuration diagnostics.

The offline Sigstore adapter now uses this shared parser, intentionally rejecting
previously ignored PEM content and malformed labels. Existing offline bundle
verification tests retain their digest, identity, signature and inclusion-proof
checks. A valid parsed root does not prove that it contains the trust anchors
needed by a particular bundle or that any evidence has been verified. New receipt
metadata identifies the actual pinned `sigstore-go.v1.3.0` dependency, correcting
the stale `v1.1.4` label without rewriting historical receipts. A module-pin test
guards this metadata against future drift.

Known supplied syntax, project production restrictions and local relationships
are checked without external resolution. Relationships that depend on service,
profile or credential files remain explicitly unresolved. Native
default/credential/file resolution retains the SDK owners documented below;
EVY-1216 must adopt validated settings before entering them. A parsed value
cannot establish native credential or provider readiness.
The pinned `github.com/jackc/pgx/v5 v5.9.2` parser reads 22 `PG*` environment
settings and can read service, passfile and TLS material while parsing. The
current PostgreSQL adapter enters that path through `pgxpool.New`. Reusing its
parser directly in this pure phase would introduce ambient reads and file I/O;
the native SDK/file boundary still needs explicit ownership. Pure syntax checks
do not apply ambient defaults or open referenced pass/service/TLS files.
Build-start time remains absent until the command applies its clock. Worker probe
and offline commands must use their applicable configuration scope during adoption
rather than acquire unrelated runtime dependencies.

## Required Toolkit Boundary

The pinned `github.com/aatuh/api-toolkit/contrib/v3 v3.1.2` configuration helper
was inspected before choosing this boundary. Its `NewLoader` binds the default
ambient environment adapter. Its boolean, integer, duration and enum errors can
include the supplied value; its generic application settings also use a different
environment-variable contract. It does not supply Evydence's role-aware schema,
generated operator references, secret-reference policy or pre-startup validation
of the entire applicable configuration.

Using that loader would therefore preserve ambient reads and permit sensitive
configuration in errors. The project-specific input/validation layer addresses
those requirements with standard-library capture/parsers and existing pure
MinIO identifier and Sigstore trust parsers; no module dependency is added.
The pinned MinIO
helpers used here have standard-library-only implementations and perform no
credential, file or network access. The Sigstore entry points used here likewise
parse supplied bytes only; its file/TUF/live helpers are not used. This decision
does not replace the required
toolkit HTTP foundation, middleware,
ports, Problem Details or route/OpenAPI contract facilities.

## Secret File Resolution Primitive

EVY-1215 uses a package-private reader beneath explicit public resolution.
Input parsing and preflight remain free of filesystem access.
The primitive accepts a clean absolute path of at most 4096 bytes and an explicit
content bound, capped by the existing 8 MiB input ceiling. The operator owns the
configured parent directory. Files must be nonempty and regular, with no execute,
group-write or other-user permission bits; group-read private files remain
supported.

Access uses a pinned `os.Root` directory handle. Relative Kubernetes projections
and absolute aliases are accepted only when their resolved target stays inside
that parent. Metadata and the opened inode are checked before reading, and the
inode, permissions and size are checked again afterward. Unix opens are
nonblocking, so a FIFO substituted between stat and open cannot wait for a peer.
The bounded reader consumes at most the configured limit plus one sentinel byte,
discards partial failures, and returns an owned redacted `Secret` with exact raw
bytes. Format-specific whitespace and credential validation belong to later
schema-selected resolution.

Cancellation is checked between local filesystem steps and bounded reads. It
does not spawn a goroutine to abandon an uninterruptible kernel filesystem call.
Handles close on every return; failures contain no path, contents or underlying
filesystem error. The current private permission policy is POSIX-specific and
fails closed elsewhere; no portable ACL support is claimed. Tests cover private
modes, bounds, cancellation during reads, partial I/O errors, contained/escaping
symlinks, atomic projection swaps and nonblocking FIFO opens.

The eight project-secret definitions now declare their explicit `FileOption`
alternatives in the same metadata. A package-private pure planner validates
role-scoped paths, byte bounds and nonempty inline/file conflicts, including
aliases. It keeps paths in owned redacted records and performs no file access.
An empty file alternative remains unset; an empty inline value can be replaced
by a selected file, while a nonempty whitespace value still conflicts. Native
credential references retain their separate SDK ownership boundary.

Public `Prepare` validates applicable captured settings and reference declarations
without I/O. Only the value checks for fields backed by valid, nonconflicting file
references are deferred; required inline endpoints, keys and other settings still
fail before reads. Its opaque, owned, redacted `PreparedInput` exposes no startup
settings. `Parse` remains a pure inline convenience and rejects applicable nonempty
file alternatives with a fixed unresolved-reference diagnostic.

`Resolve(ctx, prepared, enabled)` requires valid preflight input and a nonnil,
live context. Disabled resolution returns zero settings without file access.
Enabled resolution reads only schema-selected active references: object-store
credentials for S3/MinIO, signing-gateway tokens for a configured gateway without
a native KMS signer, and validation/transparency tokens for configured gateways.
Applicable inactive references still receive lexical and source-conflict checks,
but are not opened. API pepper, database DSN and CLI API-key references follow
their declared process roles.

Materialized files share an 8 MiB byte budget and each field's tighter bound.
The effective captured input is bounded again, then undergoes complete validation
before typed settings are returned. Partial reads, malformed loaded values,
production violations and size failures return zero settings with fixed errors;
cancellation retains its standard context error. Opaque S3 credentials preserve
exact bytes, while DSNs, API secrets and header tokens retain their existing
field-specific whitespace rules. No supplied file path or content enters errors,
formatting or JSON. No ambient environment mutation, shell execution or network
secret fetcher is added.

This boundary resolves project-secret files only. Native SDK/default/credential
resolution retains the explicit owners below. Command adoption and SDK-global
policy isolation remain EVY-1216; these helpers do not authorize unresolved
native credentials or establish provider readiness.

Worker metrics use their existing explicit token-file option rather than an
inline/file alternative. Enabled `Resolve` reads at most 129 bytes within the
remaining materialization budget, accepts exactly `evymetrics_` plus 64 lowercase
hexadecimal characters and one optional final LF, and retains only SHA-256.
`WorkerMetricsTokenHash` returns a copied digest and a successful-resolution flag;
pure `Parse` never sets that flag. Disabled metrics and other process roles do not
read the file. The shared reader adds inode rechecks and nonblocking Unix opens.
The new preflight also rejects noncanonical metrics paths, and resolution rejects
executable secret-file modes; these are intentional tightening of the old command
reader. EVY-1216 will remove that duplicate reader during command adoption.

## Native Credential Ownership

Native references are separate from project `_FILE` alternatives. The config
package validates their supplied types, path/URL syntax and input bounds, retains
their declared precedence, and returns owned typed native settings. Project-secret
resolution does not open native profiles, consume refresh tokens, initialize
credential chains or claim that an unresolved PostgreSQL service is complete.
Nonexistent-file tests cover this separation for each native signing mode.

The current external-resolution owners are:

| Boundary | Resolution owner | Lifetime owner |
| --- | --- | --- |
| PostgreSQL native inputs, service, passfile, TLS material and OS defaults | The pinned pgx parser, entered explicitly by `internal/adapters/postgres.PreparePoolConfig` through `pgxpool.ParseConfig` | The adapter owns opaque prepared settings and both pools. Opening a prepared configuration copies it through `pgxpool.NewWithConfig`; native parsing is not a connection-readiness claim. |
| AWS profiles, shared credentials, web identity, metadata, process/SSO/login credentials | The pinned AWS default chain, currently entered by `internal/adapters/signing/awskms.New` through `config.LoadDefaultConfig` | The executor owns its explicitly constructed HTTP transport and closes it on failed construction or once on close; injected SDK clients remain borrowed. |
| Google application-default files, external accounts and metadata | The pinned Google ADC loader, currently entered by `internal/adapters/signing/gcpkms.New` through `google.FindDefaultCredentials` | Native token sources retain SDK ownership; the executor owns its cloned KMS HTTP client. Injected token sources remain borrowed. |
| Azure certificate/workload identity files, managed identity and developer credentials | The pinned Azure default chain, currently entered by `internal/adapters/signing/azurekeyvault.New` through `azidentity.NewDefaultAzureCredential` | The SDK owns credential internals; the executor owns its cloned KMS HTTP client. Injected credentials remain borrowed. |

These SDK references retain native file/discovery/process policies. The project
reader's private-file permissions, symlink containment and content-byte bounds
apply to the project-secret files it actually reads; they are not guarantees about
arbitrary SDK profiles, caches, helper subprocesses or remote credential services.
No project `_FILE` alternative is implicitly added for a native credential.
Underlying SDK causes must remain behind the adapters' fixed diagnostics.

Worker runtime modes and the migration command now prepare PostgreSQL's native
configuration before opening pools, and runtime composition accepts that owned
result without repeating native resolution. The wrapper redacts formatting and
JSON, exposes no credentials or driver mutation API, and matches its explicit
DSN before runtime use. The pinned driver retains native environment/file/default
resolution; it has no environment-snapshot option. This phase therefore does not
claim a replacement parser or project-file guarantees for native references.
Cancellation is checked before resolution and after successful parsing. The
native parser is synchronous and has no context API; no detached I/O is used.

The adapter rejects zero/negative ports, invalid pool minima, negative lifetime/
idle/jitter values and nonpositive health periods in resolved structures before
pool construction. Native service files can otherwise reach SDK-accepted unsafe
maintenance settings outside the pure explicit-input evaluator. Prepared opens
retain the existing separately capped read-only package pool and Store-owned
cleanup. The legacy adapter `Open` entry point delegates to preparation and
prepared open; unadopted runtime callers also enter that explicit owner. API
startup also prepares the database configuration before provider constructors.

EVY-1216 must adopt validated configuration before entering these explicit SDK
boundaries, remove project-owned ambient reads, and own the Azure global
logging/telemetry policy before provider use. This ownership record does not
assert that command adoption, SDK-global isolation or live provider verification
has already happened.

## Delivery And Compatibility

EVY-1214 owns the inventory, schema, typed parsing and safe diagnostics.
EVY-1215 owns bounded secret references. EVY-1216 must adopt those definitions in
all applicable commands and retire duplicate defaults, parsers and hot-path
ambient reads. EVY-1217 owns generated examples/references, deployment parity and
the final runtime evidence required by parent EVY-1205.

Migration startup now captures its environment once, prepares the migration
role and explicitly resolves project secrets before logging process start or
entering PostgreSQL. It passes owned typed settings into the operation and uses
the schema's directory/logging defaults. Invalid input emits one fixed JSON
rejection record without configuration or driver details. Missing/malformed
settings now retain the shared fixed error classes instead of the old local
variable-specific diagnostics. The command's local environment-default helper
is removed; native pgx defaults and references retain their documented owner.

The source guard recognizes direct `config.Capture(os.Environ())` calls in the
reviewed `run` and worker `runWorkerWithContext` entry points, and in the owned
cold health observer `confighealth.ProcessSource`. Snapshots that escape through raw variables or
helpers, shadow package imports, repeat in loops, or run asynchronously remain
rejected. Other startup entry points need explicit guard review when adopted.

The shared logger has an explicit configured lifecycle entry point and a fixed
startup-rejection operation. Its legacy environment entry point remains for
commands not yet adopted; retiring it is part of EVY-1216. CLI adoption and
SDK-global policy are still incomplete.

Typed configurations also retain a private fingerprint of their original captured
source. Its opaque `SourceIdentity` exposes only equality against another bounded capture;
secret-file materialization preserves the original declaration's identity. The
typed health entry point `confighealth.NewConfigured` retains only this identity
and revision fields, then compares the source without
reparsing or reloading runtime settings, then applies the existing desired-revision
file checks. Source failures remain fixed diagnostics, and cancellation is checked
before observing the source. This path uses the complete shared capture selection,
including native PostgreSQL and host inputs. API and worker startup now use this
typed health path. Retiring the unused legacy constructor and its separate
selector/digest remains part of EVY-1216.

API startup now captures once, prepares the API role, resolves active project
secret files and prepares PostgreSQL before configured logging invokes runtime
composition. Providers, storage and the listener cannot be constructed through
that callback until preflight succeeds. Typed values supply ingress/rate controls,
session policy, bootstrap input, storage and provider clients. The API's legacy
environment/default/scalar/CIDR/base64 parsers and separate startup policy are
removed. Component-test fixtures use the same parser and typed projections.
The durable native bootstrap, actor/tenant boundaries and shutdown/owned-provider
cleanup paths retain their existing composition. Malformed explicit values now
fail with fixed shared errors; unknown local writer modes are rejected, and direct
cloud modes require their configured key references. SDK-global logging/telemetry
ownership, CLI adoption and remaining shared legacy retirement are still due.

The worker daemon now uses shared preflight and explicit resolution before
logging startup or opening runtime resources. Typed settings supply its database,
object store, polling, batch, payload, shutdown, cleanup and listener options.
Metrics use only the resolved hash and the shared token grammar; the old daemon
metrics-file, integer and shutdown parsers are removed. Invalid explicit values
now fail with shared fixed error classes instead of local diagnostics or silent
fallbacks. Worker health observes source drift through `ProcessSource` on cached
refreshes while runtime settings remain frozen.

The healthcheck client now has an explicit `WorkerProbe` schema role. It shares
the daemon's address definition and loopback validation, and uses configured
logging, without parsing or resolving unrelated runtime or native SDK settings.
The command dispatch captures once in the same reviewed worker entry point;
the duplicate ambient address parser and default are removed. Production's
unknown-project-option check still applies. See the
[configuration reference](../reference/configuration.md#runtime-variables) for
the applicable inputs and probe modes.

Parser-replay and reconciliation now select `WorkerReplay` and
`WorkerReconcile` scopes at that same dispatch boundary, after parsing their
operator arguments. Both use shared database/storage validation and explicit
project-secret resolution before opening resources. Only the selected
operation's timeout applies; daemon listener, polling, metrics and revision-file
settings are not dependencies. Their immutable runtime settings include the
cleanup budget. Replay now returns cleanup failures and closes partial runtime
ports when a cleanup callback is available. The worker's ambient runtime builder,
duration/default helpers and legacy logging entry point are removed; legacy
object-store construction fixtures remain only in tests. Actor/tenant scoping,
append-only derived records and durable idempotency remain in the existing
operation paths.

The native worker processor owns an explicit immutable payload-byte budget.
Jobs pass it through bounded object replay instead of rereading the environment.
Legacy processing fixture helpers live in test files and choose an explicit
budget. The shared
schema and processor deliberately reject `MaxInt64`: the existing bounded object
readers require room for a sentinel byte and already reject that unusable value.

Commands not yet adopted retain their existing parsing. An input helper
alone does not prove that startup validates every field or that generated docs
match production behavior. Changes to accepted values, defaults, aliases or
production constraints require characterization tests and explicit compatibility
notes. Offline verification, help and version commands must remain independent
of unused live dependencies.

The canonical operator reference remains
[`docs/reference/configuration.md`](../reference/configuration.md). This ADR
records the implementation boundary rather than duplicating its variable table.
