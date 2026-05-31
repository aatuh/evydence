# Backup And Restore Runbook

This runbook is for self-hosted operators. It describes the evidence needed to
trust a restore rehearsal; it is not legal compliance proof or a disaster
recovery guarantee.

## Scope

Back up PostgreSQL and object storage as one logical unit. Evydence backup
manifests record counts, hashes, and verification checks, but they are not
backups by themselves.

## Backup Procedure

1. Record the Evydence commit, release tag, image digest, `openapi.sha256`, and
   `migrations.sha256` used by the deployment.
2. Pause API writes or run the backup under an operator-approved consistency
   window. Worker replicas may continue only if the backup procedure captures a
   consistent database and object-store point.
3. Back up PostgreSQL with the operator's standard tool, such as
   `pg_dump`, base backups, or managed service snapshots.
4. Back up the object store bucket/prefix that contains tenant-prefixed raw
   payloads and package exports.
5. Call `POST /v1/backup-manifests` after the backup completes and store the
   returned manifest with the backup metadata.
6. Store the release artifact manifest and signature next to the backup record.

## Restore Rehearsal

1. Restore PostgreSQL into a clean database.
2. Restore object payloads into a clean bucket or prefix.
3. Apply committed migrations for the target release.
4. Start one API writer and the required worker replicas.
5. Verify `/v1/ready`.
6. Verify the latest backup manifest with `GET /v1/backup-manifests/{id}/verify`.
7. Verify a representative audit chain, release bundle, readiness report, and
   customer package from the restored deployment.
8. Record restore start/end time, data cut timestamp, object-store source,
   database backup source, failed checks, and limitations.

## Repository Rehearsal Evidence

The repository-owned rehearsal checks exercise the same restore invariants with
non-sensitive local data:

```sh
make restore-rehearsal-check
```

Expected result: the app-layer rehearsal verifies restored ledger state,
tenant credentials, object payload digest availability, backup-manifest
verification, SBOM metadata, and release-bundle verification. When
`EVYDENCE_TEST_DATABASE_URL` is set, the PostgreSQL rehearsal restores into a
clean schema and repeats the same database/object-store checks. When the
variable is unset, the PostgreSQL test reports an explicit skip.

This command is repository proof for restore mechanics. It does not replace an
operator rehearsal against the target PostgreSQL backup tool, object-store
bucket, KMS/HSM configuration, network policy, or incident process.

## Failure Handling

- Missing object payloads: treat affected evidence, package, or report
  verification as failed until the object backup is restored.
- Migration failure: stop startup, preserve logs, and use the previous release
  artifact/migration set for recovery review.
- Hash mismatch: do not regenerate evidence silently. Record a verification
  failure and investigate database/object-store pairing.
- Secret loss: rotate affected API keys, collector keys, SSO sessions, customer
  portal tokens, and signing provider credentials. Do not place replacement
  secrets in backup manifests or public issues.

## Evidence To Keep

- PostgreSQL backup identifier.
- Object-store backup identifier.
- Evydence release artifact manifest and signature.
- OpenAPI and migration checksums.
- Backup manifest and verification output.
- Restore rehearsal notes with assumptions and limitations.
