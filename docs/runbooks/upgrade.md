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

## Current Prerelease API Contract Correction

The current unreleased prerelease contract removes request fields that the
server never persisted: `project_id` from `POST /v1/releases`, and `release_id`
and `subject_ref` from `POST /v1/artifacts`. Artifact registration now requires
`media_type`. Before upgrading a client, remove those fields, provide a media
type, and use the release-scoped evidence, build, or release-candidate routes
to make associations. No database migration or historical-evidence rewrite is
required because the removed fields never had durable storage.

The same correction applies to `POST /v1/builds`: replace obsolete
`completed_at` with `finished_at`, replace `github` with `provider_metadata`,
and use the documented top-level CI identity fields (`repository`,
`workflow_ref`, `run_id`, `run_attempt`, `job_id`, `actor`, `ref`, and
`oidc_subject`) when applicable.

## Parser Upgrade and Replay

Parser upgrades do not rewrite historical evidence. Before changing a parser
version, run `make parser-corpus-check` and retain its output with the upgrade
record. The corpus manifest pins fixture hashes, source/provenance records,
redistribution rights, limits, and expected normalized summaries; a mismatch
requires an intentional golden update and a `CHANGELOG.md` entry.

To create a new, auditable interpretation of one immutable payload, use the
worker command with a tenant scope and explicit confirmation:

```sh
evydence-worker parser-replay \
  --tenant ten_example \
  --evidence ev_example \
  --parser-version spdx-json.v2.0.0 \
  --actor operator_change_ticket \
  --apply
```

The command verifies the stored payload’s tenant and digest before parsing. It
appends a `parser_normalization` evidence item and audit-chain entry linked to
the source evidence. Repeating the identical replay is idempotent. It does not
edit the source evidence, its parser metadata, or raw payload. If a deployment
must roll back, keep both derived versions and restore the matching binary only
for future interpretations; do not delete historical derived records.

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
