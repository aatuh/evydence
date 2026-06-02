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

## API Compatibility

The public API is `/v1`. Within a stable release line:

- existing operation IDs, paths, required scopes, idempotency requirements, and
  response envelope shapes should remain compatible;
- new optional request fields, response fields, query filters, and endpoints
  may be added;
- errors continue to use RFC 9457 Problem Details with stable `code` and
  `request_id` fields;
- secrets, token hashes, private keys, raw evidence payload bytes, and
  object-store paths must not become public response fields.

Release candidates may still make breaking API or schema changes when needed
for correctness, tenant isolation, evidence integrity, safe error handling, or
security. Breaking changes must be documented in release notes, reflected in
`openapi.yaml`, and covered by `make openapi-check`.

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
