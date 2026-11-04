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
coordination protocol. Production API and worker startup requires
`EVYDENCE_SKIP_MIGRATIONS=true` (the production default); an explicit false
value fails before opening providers or storage. Production migration commands
require the paired target and checksum settings below. Non-production isolated
startup can still apply the full catalog automatically; use a separate job and
skip mode when running multiple development processes against one schema.

Every updated API/worker runtime holds a shared schema migration lease from
startup validation through processing and drain. Startup waits for an active
updated runner; an active runtime prevents new migration SQL. Multiple workers
can hold shared leases concurrently. Readiness reuses its exact pinned session,
so a waiting migrator cannot block the runtime behind a second lock acquisition
and a healthy replacement pool connection cannot hide a lost lease. Standalone
version checks use temporary shared leases and remain read-only.
Missing tracking metadata reports the local catalog as pending; checking does
not create the table or apply SQL. Startup/readiness also check the managed
operation marker when present, as described below. Version results cover
the configured schema and preserve local catalog order without returning
unrelated recorded versions. These are version-name checks, not schema-content
or checksum verification. Cleanup waits for database work and closes owned
provider/object resources before releasing the migration and API writer leases.
A cleanup timeout retains ownership until process exit; do not reuse that
runtime. Production API pools need at least three connections (two pinned
leases plus work), and worker and migration pools need at least two. Smaller
resolved pools fail before dialing. This is minimum capacity, not sizing advice.

## Explicit Target And Verified Inputs

After verifying the release artifacts, the migration command can consume the
release's `migrations.sha256` with an explicit version. Both settings are
required together and mandatory for `ENV=production`. For the current source catalog, an example is:

```sh
EVYDENCE_MIGRATION_TARGET=20261104000100_migration_operation_audit \
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
applied, with each SQL file, version record, execution checksum and database
principal in one transaction. A version recording conflict fails that
transaction for both ordinary and verified execution. Repeating a completed plan is
a no-op. Earlier committed versions survive a later SQL failure as described
above.

This compares input bytes with an operator-trusted checksum file; the file does
not authenticate itself. Without the paired target/checksum settings, the
command retains its full-catalog behavior. Both paths reject a mismatch with
any recorded checksum before applying pending SQL. Ordinary execution continues
to accept unknown legacy history for compatibility; the verified path requires
the acknowledgement below.

## Recorded Checksums And Legacy History

Updated runners record `checksum_sha256` over the exact owned SQL bytes and
`applied_by` from PostgreSQL's authenticated `session_user`, alongside the
existing version and application timestamp. Existing version rows keep their
timestamps and receive null checksum/principal fields. These fields expand the
operational tracking table before application SQL, like its initial table
bootstrap, independently of the selected application target. Expansion can
remain after a rejected or canceled run. The additive migration
`20261029000100_migration_execution_checksums` declares the same nullable shape
for older runners; older writers still insert version-only rows.

A verified plan encountering a version-only row stops with the fixed log event
`migration_legacy_history_required`. Review the deployment's prior release
artifacts, backups and migration records through your protected database
connection. This bounded query distinguishes recorded execution metadata from
unknown history:

```sql
SELECT version, applied_at, checksum_sha256, applied_by
FROM schema_migrations
ORDER BY version
LIMIT 1024;
```

To proceed with unknown history after that operator review, repeat the paired
target/checksum command with `EVYDENCE_MIGRATION_ALLOW_LEGACY_HISTORY=true`.
This acknowledgement leaves old checksums and principals null; it does not
backfill or verify historical SQL. The setting defaults to false and requires
the paired plan settings. Never fill old fields merely to silence the check.

A stored mismatch stops with `migration_checksum_mismatch`, including when
legacy acknowledgement is enabled. Check the intended release, artifact
checksums and database history; use a forward fix or the paired restore
procedure. The metadata downgrade refuses to erase any recorded execution
checksum/principal. These database records rely on database access controls;
they are not an external attestation or protection against a privileged database
administrator changing records. Migration metadata stays outside the frozen
tenant evidence commitments.

For a schema with managed operation history, startup/readiness additionally
require its latest operation to have succeeded for the authenticated runtime
role, local catalog target and embedded role-policy digest. They reject
effective schema-create or migration-metadata write permissions. Missing or
empty operation history preserves the legacy version-check behavior; this does
not prove role separation. Configure the migration/runtime identities using
the [database role procedure](../how-to/database-roles.md).

`EVYDENCE_MIGRATION_RUNTIME_ROLE` selects managed validation, append-only
operation audit and runtime grants under the existing coordinator. This path
requires the paired target/checksum inputs. Once activated, ordinary migration
execution cannot bypass it by omitting the role option. Failed, interrupted or
uncertain operations block runtime even when no SQL remains pending. Review and
repair the cause, then rerun the managed plan; never clear or rewrite audit rows.
The runner bootstraps `schema_migration_operations` before application SQL; the
additive `20261104000100_migration_operation_audit` declares the same shape for
other runners. Its downgrade refuses to erase recorded operation events.

The production-like Compose stack runs its migration service before either
daemon. The Helm chart runs a pre-install/pre-upgrade migration Job with the
selected image's `/app/migrations.sha256` and an operator-selected target. Stop
existing API and worker pods before upgrading: Helm runs pre-upgrade hooks
before updating Deployments, and an active runtime intentionally prevents the
job from migrating. See [Kubernetes deployment](../kubernetes.md#install-or-upgrade).
Role provisioning, existing-schema adoption, worker operations and broader
deployment hardening are still pending in EVY-1206. The lock protocol does not
protect against older binaries or a database administrator bypassing it.

## Upgrade

For the separate database-identity rehearsal, use the
[database role procedure](../how-to/database-roles.md). With the optional role
selected, the Helm/Compose migration command commits grants and operation audit
before daemons restart. The policy never transfers ownership or changes
legacy execution metadata.

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
