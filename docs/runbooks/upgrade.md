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

Migration entries ending in `.up.sql` must be regular files. A matching symlink,
directory or other non-regular entry rejects catalog discovery before migration
SQL runs; the error does not return a partial migration list. Other entries,
including `.down.sql` files, are not applied. Catalog discovery accepts at most
1,024 up files and 8,192 total directory entries. Applying migrations reads every
up file into an owned snapshot before acquiring the database lock or running
SQL, with limits of 4 MiB per file and 32 MiB combined SQL. An unreadable,
non-regular or oversized input, or a detected change during loading, rejects
that snapshot without applying any file.
Files edited, removed or added after snapshot loading do not change that run.

Keep the migration directory read-only during loading and verify the release
checksums as above. The loader pins its directory, checks opened file identity
and type, and bounds reads. It does not create an atomic filesystem snapshot or
authenticate release files. Local filesystem calls can still wait on the kernel;
cancellation is checked between bounded operations. Catalog discovery and
snapshot loading do not verify recorded database history or enforce a target.

Updated migration runners targeting the same database schema serialize their
work. Each file still commits in its own transaction: a later failure preserves
earlier completed versions and rolls back the current file. Lock waits respect
the command context. Uncertain lock cleanup returns an error and discards the
database session, even when a version has already committed. Keep using the
writer/worker stop procedure below; older runners do not participate in this
coordination protocol. The verified-input command path below adds explicit
target selection and checksum comparison; ordinary automatic migration still
uses the full catalog.

When `EVYDENCE_SKIP_MIGRATIONS=true`, startup checks use read-only version queries
and wait for an updated runner to finish. Other checks can read concurrently.
Missing tracking metadata reports the local catalog as pending; checking does
not create the table or apply SQL. Readiness uses the same check. Results cover
the configured schema and preserve local catalog order without returning
unrelated recorded versions. These are version-name checks, not schema-content
or checksum verification. Automatic migration settings otherwise retain their
existing behavior; a dedicated release migration job is still required for the
deployment cutover.

## Explicit Target And Verified Inputs

After verifying the release artifacts, the migration command can consume the
release's `migrations.sha256` with an explicit version. Both settings are
required together. For the current source catalog, an example is:

```sh
EVYDENCE_MIGRATION_TARGET=20261028000100_outbox_trace_context \
EVYDENCE_MIGRATION_CHECKSUMS_FILE=/srv/evydence/release/migrations.sha256 \
EVYDENCE_MIGRATION_TIMEOUT_SECONDS=120 \
evydence-migrate
```

Choose the reviewed target for your intended release; omit `.up.sql`. Configure
the database and migration directory through the
[configuration reference](../reference/configuration.md). The timeout covers
input preparation, database opening, coordinator waits and SQL. Its default
remains 30 seconds, with a supported range of 1 through 900 whole seconds.

The command prepares the verified plan before opening its database pool. The
checksum file must be regular, at most 64 KiB, and contain at most 256 unique
records in the existing release checksum format (`sha256sum` text or binary
markers, with logical `migrations/<filename>.sql` names). Every local up file,
including files beyond the target, must match a record. Every other listed SQL
file is also checked but is not applied. SQL inputs retain the 4 MiB per-file
limit; this path bounds all checked SQL together to 32 MiB. File changes after
preparation cannot change the owned SQL executed by that plan.

Under the runner lock, existing versions must form a prefix of the selected
target catalog. Newer, unknown or gapped history rejects the run before
application migration SQL. Only the missing suffix through the target is
applied, with each SQL file and its version record in one transaction. A version
recording conflict fails that transaction. Repeating the same completed plan is
a no-op. Earlier committed versions survive a later SQL failure as described
above.

This compares input bytes with an operator-trusted checksum file; the file does
not authenticate itself. Existing version rows and timestamps are preserved.
They do not contain historical SQL checksums, so matching their names does not
verify what SQL was previously executed. Stored checksum provenance and an
explicit legacy-history policy remain part of EVY-1206. Without the paired
target/checksum settings, the command retains its full-catalog behavior.
Mandatory production job separation and deployment cutover also remain pending;
keep stopping writers and workers as below.

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
