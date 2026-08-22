# Backup And Restore Runbook

This runbook is for self-hosted operators. It describes the evidence needed to
trust a restore rehearsal; it is not legal compliance proof or a disaster
recovery guarantee.

## Scope

Back up PostgreSQL and object storage as one logical unit. Evydence backup
manifests record counts, hashes, and verification checks, but they are not
backups by themselves. A paired backup generation must identify both the
PostgreSQL backup and the object-store generation before either is used for a
restore.

## Backup Procedure

1. Record the Evydence commit, release tag, image digest, `openapi.sha256`, and
   migration set used by the deployment.
2. Pause API writes or run the backup under an operator-approved consistency
   window. Worker replicas may continue only if the backup procedure captures a
   consistent database and object-store point.
3. Generate an application consistency checkpoint with
   `POST /v1/backup-manifests` and retain its ID and state hash with the backup.
4. Back up PostgreSQL with the operator's standard tool, such as `pg_dump`, a
   base backup, or a managed service snapshot.
5. Back up the object-store bucket/prefix containing the tenant-prefixed raw
   payloads and package/export bytes from the same consistency window.
6. Create the external paired-generation manifest. For a filesystem backup and
   `pg_dump` archive, the repository helper is:

   ```sh
   python3 scripts/paired_backup_manifest.py create \
     --database-dump /backups/database.dump \
     --objects-dir /backups/objects \
     --migrations-dir migrations \
     --release-commit "$RELEASE_COMMIT" \
     --checkpoint-id "$BACKUP_MANIFEST_ID" \
     --checkpoint-state-hash "$BACKUP_STATE_HASH" \
     --output /backups/paired-backup.json
   ```

   The paired manifest contains backup identities, SHA-256 digests, counts,
   migration/release identity, and the application checkpoint. It does not
   contain database rows or raw object payloads.
7. Store the paired manifest, application backup manifest, release artifact
   manifest/signature, database backup identifier, and object-store backup
   identifier as one recovery record.

## Restore Preflight And Rehearsal

Do not start Evydence against a restored database/object pair until generation
preflight succeeds.

1. Restore or stage the candidate PostgreSQL backup and object-store backup in
   isolated locations. Do not combine artifacts from different backup times to
   make an apparently complete restore.
2. Verify the external paired-generation manifest before normal startup:

   ```sh
   python3 scripts/paired_backup_manifest.py verify \
     --manifest /backups/paired-backup.json \
     --database-dump /backups/database.dump \
     --objects-dir /backups/objects \
     --migrations-dir migrations \
     --release-commit "$RELEASE_COMMIT"
   ```

   A database-newer, objects-newer, migration-set, release-commit, manifest, or
   inventory mismatch is a stop condition. Select another trusted paired
   generation; do not use reconciliation to merge inconsistent backup points.
3. Restore PostgreSQL into a clean database and object payloads into a clean
   bucket, prefix, or filesystem root.
4. Verify that the restored database has no pending migrations for the recorded
   release before opening the application.
5. Start one API writer and the required worker replicas, then verify
   `/v1/ready`.
6. Verify the application backup checkpoint with
   `GET /v1/backup-manifests/{id}/verify`.
7. Verify representative audit-chain entries, release bundles, object payload
   digests, customer package manifests/exports, idempotency state, and pending
   outbox jobs from the restored deployment.
8. Run tenant-scoped object reconciliation in dry-run mode only after a matching
   trusted pair has been selected. Reconciliation is a consistency/recovery
   tool inside one generation, not a substitute for backup pairing.
9. Record restore start/end time, selected recovery point, database/object
   backup identifiers, paired generation ID, failed checks, and limitations.

## Recovery Point And Rollback Boundary

The recoverable point is the consistency window/checkpoint represented by the
selected paired generation. Writes committed after that point are outside that
backup and may be lost when restoring it. Evydence does not infer or guarantee
an operator RPO from this mechanism; operators must choose backup frequency and
consistency windows that meet their own recovery objectives.

Partial rollback is unsupported. Do not run an older database backup with newer
objects, newer database state with older objects, or an older binary/migration
set against a newer generation. Restore a matched database/object generation
and use the release commit/migration set recorded in its manifest. If the pair
cannot be proven, keep the service stopped and investigate or select another
trusted backup.

## Repository Rehearsal Evidence

The repository-owned live rehearsal requires a real PostgreSQL target and the
native PostgreSQL backup tools. It does not silently fall back to memory:

```sh
EVYDENCE_TEST_DATABASE_URL='postgres://...' sh scripts/restore_rehearsal.sh
```

The broader project target also includes the application characterization
rehearsal and the native PostgreSQL rehearsal:

```sh
EVYDENCE_TEST_DATABASE_URL='postgres://...' make restore-rehearsal-check
```

The native test creates clean source and target databases, uses `pg_dump` and
`pg_restore`, copies a real filesystem object-store generation, and requires
paired-generation preflight before the restored ledger is opened. It verifies
the restored consistency checkpoint, audit chain, release bundle, object digest,
customer package manifest/export, completed idempotency record, and queued
outbox job. It also proves database-newer and objects-newer artifacts are
rejected before startup.

Failure-recovery coverage additionally exercises kill points after provider
upload, metadata/finalizer commit, provider finalization, audit append before
transaction commit, and outbox claim. The expected outcomes are conservative:
provider-only uploads are reported rather than deleted, verified finalizations
resume deterministically, uncommitted audit work rolls back, and expired outbox
leases are reclaimed while stale lease tokens remain fenced.

These checks are repository proof for the tested PostgreSQL/filesystem profile.
They do not replace an operator rehearsal against the target managed PostgreSQL
service, S3/MinIO snapshot mechanism, KMS/HSM configuration, network policy,
backup scheduler, or incident process.

## Failure Handling

- Paired-generation mismatch: do not start Evydence and do not combine the
  artifacts. Select another trusted database/object pair and repeat preflight.
- Missing object payloads within a verified generation: keep affected evidence,
  package, or report verification failed until valid bytes are restored; begin
  with dry-run reconciliation.
- Migration failure: stop startup, preserve logs, and use the release/migration
  identity recorded with the paired generation for recovery review.
- Hash mismatch: do not regenerate historical evidence silently. Record the
  verification failure and investigate database/object-store pairing or object
  corruption.
- Secret loss: rotate affected API keys, collector keys, SSO sessions, customer
  portal tokens, and signing provider credentials. Do not place replacement
  secrets in backup manifests or public issues.

## Evidence To Keep

- PostgreSQL backup identifier and database-dump digest.
- Object-store backup identifier and inventory digest.
- Paired backup generation ID and verification output.
- Application backup-manifest/checkpoint ID and state hash.
- Evydence release commit/artifact manifest and signature.
- OpenAPI and migration checksums/identity.
- Restore rehearsal notes, selected recovery point, assumptions, failed checks,
  and limitations.
