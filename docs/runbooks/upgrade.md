# Upgrade Runbook

Use this runbook when moving a self-hosted Evydence deployment to a new release
candidate or release. It is a technical upgrade guide, not an assurance or
certification statement.

Read [Upgrade and compatibility policy](../reference/upgrade-compatibility-policy.md)
before changing binaries, images, Helm values, or migrations.

## Before Upgrade

1. Read the release notes and known limitations for the target version.
2. Review the supported upgrade path and breaking-change notes in the
   compatibility policy.
3. Verify release artifacts:
   `SHA256SUMS`, signed release manifest, OpenAPI checksum, migration checksum,
   release SBOM metadata, and release provenance metadata.
4. Back up PostgreSQL and object storage together.
5. Generate and verify a backup manifest.
6. Confirm the target profile still uses one API writer replica unless a later
   release explicitly documents a reviewed multi-writer design.
7. Check that production secrets are externalized and that local plaintext
   signing-key mode is not used in production.

## Upgrade

1. Stop API writers.
2. Let workers finish or stop them after recording pending outbox counts.
3. Apply migrations with `make migrate` or `evydence-migrate` using the target
   release artifacts.
4. Start one API writer.
5. Start worker replicas.
6. Verify `/v1/ready`, a release-readiness report, an audit-chain verification,
   a release bundle verification, and a representative package/export.

## Rollback Or Forward Fix

Evydence migrations are treated as forward-moving release evidence. Prefer a
forward fix when a migration has written new state. If an operator must restore
an older version, restore the matching PostgreSQL and object-store backups
together and record the data cut timestamp.

## Evidence To Keep

- Previous and target release artifact manifests and signatures.
- Migration checksum file.
- Backup manifest before upgrade.
- Upgrade command transcript with secrets redacted.
- Post-upgrade verification outputs and known limitations.
