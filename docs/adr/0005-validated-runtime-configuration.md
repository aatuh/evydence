# ADR 0005: Validated Runtime Configuration

Status: accepted for the immutable-input, schema-metadata, scalar-parsing,
role-input, typed-projection and local-validation foundation of EVY-1214,
with HTTP/signing validation reviewed 2026-10-17. Database/S3/trust-material
validation, complete schema/SDK coverage,
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
captures `ENV`, `CI`, `EVYDENCE_*` and the AWS, Google, Azure and GitHub namespaces.
Unrelated host settings are not configuration values. Capture bounds total input
to 4096 entries and 8 MiB, selected settings to 1024, and selected names to 256
bytes. Selected names use uppercase ASCII environment syntax; NUL and malformed
UTF-8 selected input are rejected. Duplicate selected names fail instead of
depending on process-environment ordering.

The input's string, Go-syntax and JSON representations disclose neither names
nor values. Validation failures use fixed diagnostics. An internal fingerprint
supports change detection; it is not an evidence digest, credential identifier
or public configuration dump. Captured input and returned metadata remain owned
by the configuration package.

The code-owned catalogue currently records 109 option definitions with process
roles, value kinds, defaults, secret classification, observed numeric bounds,
aliases and production restrictions. Conditional defaults remain explicit:
runtime profile selection is required, while PostgreSQL load mode has different
defaults inside and outside production. Public metadata access returns sorted
copies, including owned slices for allowed values and aliases.

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
misrouted values. Construction remains package-private until dedicated validation
is complete.

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

Database/S3 endpoint and credential checks, Sigstore trust-material validation,
remaining path checks and complete dynamic-name/SDK coverage remain required
before EVY-1214 closes.
The pinned `github.com/jackc/pgx/v5 v5.9.2` parser reads 22 `PG*` environment
settings and can read service, passfile and TLS material while parsing. The
current PostgreSQL adapter enters that path through `pgxpool.New`. Reusing its
parser directly in this pure phase would introduce ambient reads and file I/O;
the database syntax and SDK/file boundary still need explicit ownership.
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
those requirements with the standard library and adds no dependency. This
decision does not replace the required toolkit HTTP foundation, middleware,
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
