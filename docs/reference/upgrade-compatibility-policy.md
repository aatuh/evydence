# Upgrade And Compatibility Policy

This reference defines upgrade expectations for Evydence release candidates and
future stable releases. It is an operator compatibility policy, not legal
compliance proof, certification, complete SBOM proof, authoritative scanner
coverage, or a secure-release guarantee.

## Supported Upgrade Paths

| Source | Target | Policy |
| --- | --- | --- |
| `v0.1.0-rc.N` | later `v0.1.0-rc.M` | Supported after reading release notes, verifying release artifacts, backing up PostgreSQL and object storage together, and applying all committed migrations. |
| `v0.1.0-rc.N` | stable `v0.1.0` | Supported only after the stable exit criteria pass for the promoted candidate. |
| stable `v0.1.0` | later patch release | Intended to be forward-compatible for `/v1` API clients and migration history unless release notes document a security or correctness exception. |
| any release | older release | Not a normal upgrade path. Restore the matching PostgreSQL and object-store backups together instead of trying to run old binaries against newer data. |

Operators should upgrade one release line at a time. Do not skip release notes,
OpenAPI checksums, migration checksums, backup manifests, or production-check
evidence.

## Migration Expectations

- Migrations are forward-only release evidence.
- Do not edit committed migration history.
- Apply all committed migrations before starting API or worker processes.
- Production startup must fail when committed migrations are pending unless an
  operator-controlled migration job has already applied them.
- `make migration-compatibility-check` verifies that every committed migration
  prefix can upgrade to the current schema in a disposable PostgreSQL schema.
- Rollback after a migration writes new state requires restoring the matching
  PostgreSQL and object-store backups together.

## Structured Log Rollout (Unreleased)

EVY-1202 changes API, worker and migration diagnostics from free-form text to
JSON by default. Update collectors/parsers to the
[operational log schema](observability.md#process-diagnostics), or select the
structured text format. Stdout command results and the explicit local bootstrap
credential interface retain their existing contracts.

Apply `20261016000100_outbox_log_correlation` before updated workers start.
Existing jobs retain empty references; new jobs capture correlation separately
from payloads and deduplication keys. No historical evidence or audit hash is
rewritten. Budget the ordinary `ALTER TABLE` lock during the operator-owned
migration window. Diagnostic columns are not historical backup commitments;
restoring earlier backups may lose correlation. The isolated round-trip test
covers representative old rows, not a live production-volume migration or a
supported release downgrade.

## Lifecycle Probe Rollout (Unreleased)

EVY-1203 adds `/v1/startup`; `/v1/health` remains dependency-free liveness and
`/v1/ready` retains its readiness status/check envelope. Configured dependency
names are process-specific; the synthetic `ledger: ok` row is removed because
it performed no evidence check. Do not use that row as an integrity signal.
Startup/readiness/diagnostics share a short-lived dependency snapshot, so allow
the documented refresh/cache window before expecting an outage or recovery to
appear. Responses use `no-store`, and unavailable probes preserve the catalog
retry policy. Canonical lifecycle probes use admission separate from ordinary
application requests; this does not exempt other routes from their limits.

The API now reports configuration freshness and outbox progress as readiness
dependencies. Overdue eligible work or an expired worker lease can change
readiness to `503`. Helm adds a startup probe and projects a desired non-secret
configuration revision; chart configuration changes replace both daemons.
The revision variables are optional outside Helm, but configuring only one,
or starting with a mismatched/unreadable revision file, fails before runtime
resources open. This mechanism does not hot-reload settings or watch external
Secret updates; those require an operator rollout.

Production `signing_config` now checks the actual signing dependency. Gateways
need `EVYDENCE_SIGNING_EXECUTOR_READINESS_URL` with the documented read-only
response contract. Native cloud modes need metadata-read permission; GCP and
Azure additionally require configured default key/version values for that
process probe, even when tenant signing requests supply their own key reference.
Missing probe configuration or provider failure leaves readiness unavailable
while dependency-free liveness continues. These metadata reads create no test
signatures and do not establish every key's signing authorization.

The worker's `healthcheck`/`--healthcheck` command now requires a running worker
on `EVYDENCE_WORKER_HEALTH_ADDR` (default `127.0.0.1:8081`). It is no longer an
unconditional-success utility. Use `--startup` and `--liveness` for distinct
lifecycle checks. Pick a separate loopback port for each worker sharing a
network namespace; an occupied port prevents claims. Helm provides the three
exec modes, projects the configuration revision into both daemons, and loads
runtime Secret variables. Optional per-daemon Secret overrides allow the API
and worker to use different credentials. Chart safety settings take precedence
over Secret variables; inspect existing Secret keys before upgrading.

See [observability](observability.md#endpoints) for endpoint semantics and
freshness bounds. Instance diagnostics still require explicit `instance:admin`.
No evidence, audit, idempotency or backup format changes accompany this HTTP
probe transition.

## API Compatibility

### OIDC Login Binding Rollout

Migration `20261013000100_oidc_authentication_requests` adds short-lived
server-owned login state with provider/tenant ownership, unique state/nonce
hashes, bounded time fields and consumption markers. It does not rewrite
providers, identity links, sessions, evidence, verification receipts or audits.
Plan for the provider-table constraint/DDL lock. Apply the migration before
starting the updated API and stop older API writers during rollout: older
binaries can issue sessions without these new proof checks.

OIDC clients must first create `/v1/sso/authentication-requests`, send its nonce
in the external provider's authorization request, and exchange a matching ID
token with request ID and API state or browser state cookie. Existing unbound
OIDC exchange bodies now return `401`. Existing sessions remain subject to
their captured lifetime, idle, revocation and current identity/grant checks;
new login state is not backfilled for old tokens. API exchange delivers secrets
only in JSON; OIDC browser delivery requires explicit `delivery: browser`,
HTTPS same-origin checks and cookie state, and omits the JSON secret.

EdDSA/Ed25519 and RS256 remain supported with the documented key/time/input
bounds. Additional audiences, unsupported key usage/algorithms, ambiguous JWT
JSON and access-token types fail. Provider metadata/trust rotation invalidates
outstanding login requests; clients must restart the flow after rotation.
No redirect UI, authorization-code exchange, discovery network request or live
provider verification is introduced by login initiation/exchange.

The guarded down migration refuses to discard any retained request, including
consumed or expired rows. Use a forward fix; running older binaries against
this schema does not retain the new authentication protections. The new
OIDC backup metadata profile is `tenant-relational-state.v4`, which adds non-secret
request metadata and excludes state/nonce hashes. Historical v1/v2/v3 profiles
and recorded commitments remain unchanged; the manifest envelope stays
`backup-manifest.v2.0.0`.

SAML standard assertion binding/replay and authentication failure telemetry
remain separate backlog work. These rollout notes do not claim real-provider
interoperability or completion of those features.

### SAML operational state (unreleased)

Migration `20261013000200_saml_authentication_state` adds tenant-owned SP
bindings, five-minute authentication requests and assertion replay markers.
It preserves existing providers, sessions, identity links and audit/evidence
history. Recipient/NameID settings live in a separate binding record, so the
existing OIDC provider snapshot and pending-request fingerprint remain unchanged.
Replay markers retain a scoped assertion hash through its signed expiry,
including when that deadline outlives its login request. Expired operational
rows use bounded cleanup; retained requests count toward provider capacity.

The guarded downgrade refuses any retained binding, request or replay marker.
Use a forward fix; do not discard configured bindings or replay protection to
run older writers. Backup `tenant-relational-state.v5` commits their non-secret
metadata and excludes SAML state hashes. Frozen v1–v4 vocabularies and vectors
remain reproducible; the manifest envelope stays `backup-manifest.v2.0.0`.
Runtime SAML login integration and its API rollout remain EVY-1010 work until
the complete acceptance gate passes. These storage notes do not prove real
provider interoperability.

The public API is `/v1`. Within a stable release line:

- existing operation IDs, paths, required scopes, idempotency requirements, and
  response envelope shapes should remain compatible;
- new optional request fields, response fields, query filters, and endpoints
  may be added;
- errors continue to use RFC 9457 Problem Details with stable `code`,
  `request_id`, and documented retry fields;
- secrets, token hashes, private keys, raw evidence payload bytes, and
  object-store paths must not become public response fields.

Release candidates may still make breaking API or schema changes when needed
for correctness, tenant isolation, evidence integrity, safe error handling, or
security. They require the exact prerelease exception, migration note, and
Unreleased changelog treatment defined in
[API Versioning And Deprecation](api-versioning.md). Stable-line breaking
changes are blocked except documented security emergencies; `make
openapi-breaking-check` enforces both rules against a release-artifact baseline.

## Data And Evidence Compatibility

- Historical evidence, audit entries, vulnerability decisions, approvals,
  release bundles, package records, and lifecycle events remain append-only.
- Corrections use supersession, amendments, redaction events, tombstones,
  replacement packages, or new verification receipts rather than silent edits.
- Parser versions, schema versions, and package versions must be retained in
  stored records so old evidence can be interpreted after upgrades.
- If a new release cannot interpret older evidence safely, release notes must
  document the limitation and the affected verification path.

## Pre-Upgrade Checklist

Before changing binaries, images, Helm values, or migrations:

1. Verify the target release artifacts and signed manifest.
2. Read release notes and this policy.
3. Back up PostgreSQL and object storage together.
4. Verify or generate a backup manifest.
5. Confirm the target still supports one API writer replica unless a later
   reviewed design explicitly changes that contract.
6. Confirm production secrets are externalized and local plaintext signing-key
   mode is not used in production.

For the command-oriented procedure, use
[Upgrade runbook](../runbooks/upgrade.md).
