# ADR 0005: Validated Runtime Configuration

Status: accepted for the immutable-input, schema-metadata, scalar-parsing,
role-input, typed-projection and local-validation foundation of EVY-1214,
with HTTP/signing/S3/database-syntax/Sigstore validation reviewed 2026-10-17.
Complete schema/SDK coverage,
secret resolution, command adoption and generated deployment documentation remain
pending in EVY-1214 through EVY-1217. This is an explanation for developers
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
bytes. Project names use uppercase ASCII environment syntax. Exact declared
native spellings also admit lowercase proxy fallbacks and Windows `ProgramData`.
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

The native catalogue now contains 103 definitions covering 110 distinct names:
22 PostgreSQL, 50 AWS, three Google, 20 Azure/MSAL and 15 host/transport inputs.
AWS includes the KMS, STS, SSO, SSO OIDC and Signin endpoint names computed from
service identifiers. The Google boundary includes metadata-host overrides and
the external executable opt-in; Azure includes transitive managed-identity inputs.
These declarations use the existing module pins and add no SDK initialization.

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

Native default/service resolution, credential resolution and
complete transitive/computed-read coverage remain required. Native
PostgreSQL defaults call OS user lookup and inspect home certificate files;
their resolution needs an explicit owner in EVY-1215/EVY-1216. Capture performs
none of these operations and exposes no generic environment forwarder.

A source test scans production Go literals and fails when a selected environment
name is missing from the catalogue. This guards the current source inventory;
it does not prove complete data-flow coverage of computed names or every SDK
credential-chain option. Those boundaries and the typed loader remain required
before EVY-1214 can close. Catalogue metadata alone does not enforce its rules
or change a command's current behavior.

The package-owned scalar parser produces booleans, bounded integers/durations,
canonical choices, masked CIDR prefixes, decoded base64 bytes and UTC timestamps.
Errors use one fixed diagnostic and return no partially parsed value. Scalar
formatting and JSON are redacted, including for values not classified as secrets.
Raw string-like inputs remain unchanged for later dedicated validation: PostgreSQL
accepts connection strings, S3 accepts `host:port`, and paths require different
rules from HTTP endpoints. Scalar parsing performs no file or network access and
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

Native settings now project all 103 native definitions into PostgreSQL, AWS,
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
layers for later bounded resolution. Construction remains package-private until
the remaining validation and coverage work is complete.

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
DSN; it leaves unknown service-supplied relationships for bounded resolution in
EVY-1215. It never opens a service file or claims that this candidate is a complete
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

Pure validation of native inputs, remaining path checks and complete
dynamic-name/SDK coverage remain required before EVY-1214 closes. Native
default/credential/file resolution belongs to EVY-1215 and command adoption
to EVY-1216.
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

## Delivery And Compatibility

EVY-1214 owns the inventory, schema, typed parsing and safe diagnostics.
EVY-1215 owns bounded secret references. EVY-1216 must adopt those definitions in
all applicable commands and retire duplicate defaults, parsers and hot-path
ambient reads. EVY-1217 owns generated examples/references, deployment parity and
the final runtime evidence required by parent EVY-1205.

Current commands retain their existing parsing until adoption. An input helper
alone does not prove that startup validates every field or that generated docs
match production behavior. Changes to accepted values, defaults, aliases or
production constraints require characterization tests and explicit compatibility
notes. Offline verification, help and version commands must remain independent
of unused live dependencies.

The canonical operator reference remains
[`docs/reference/configuration.md`](../reference/configuration.md). This ADR
records the implementation boundary rather than duplicating its variable table.
