# Object Store Recovery Runbook

Use this runbook when raw evidence payloads, customer package exports, release
artifacts, or object metadata may be missing, corrupted, incorrectly scoped, or
restored from the wrong point in time. It is an operator recovery guide, not a
disaster-recovery guarantee.

## Scope

PostgreSQL stores metadata and object references. Object storage stores raw
payload bytes and package/export bytes. A trustworthy recovery must restore the
database and object storage as one logical unit.

Repository-owned checks can verify tenant-prefixed object keys, expected
payload hashes, backup-manifest consistency, release-bundle verification, and
package verification. Operator-owned checks must cover provider snapshots,
bucket policy, object-lock/WORM configuration, IAM, encryption, lifecycle, and
regional availability.

## Triage

1. Preserve the failing verification output and relevant request IDs.
2. Do not regenerate or overwrite historical evidence to hide a missing object.
3. Pause affected API writes and worker jobs if database/object-store pairing
   may be inconsistent.
4. Identify affected tenant IDs, object prefixes, evidence IDs, package IDs,
   release IDs, and backup timestamps.
5. Confirm whether the failure is missing object, digest mismatch, wrong
   tenant prefix, wrong bucket/prefix, permission denial, provider outage, or
   metadata drift.

## Recovery Procedure

1. Restore the object-store bucket or tenant prefix from the backup matching
   the PostgreSQL restore point.
2. If the database was also restored, apply migrations for the Evydence release
   being recovered.
3. Start one API writer and the required worker replicas.
4. Verify `/v1/ready`.
5. Verify the latest backup manifest and representative release bundles,
   evidence payload hashes, readiness reports, and customer packages.
6. Resume worker jobs only after digest checks pass for the affected payloads.
7. Record object-store backup ID, database backup ID, restored prefixes,
   verification results, failed objects, and limitations.

## Repository-Owned Checks

Use the local rehearsal for non-sensitive restore mechanics:

```sh
make restore-rehearsal-check
```

Use package verification for customer package fixtures or exports:

```sh
go run ./cmd/evydence package verify \
  --archive examples/end-to-end-release-evidence/sample-customer-package.zip \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example
```

For a live deployment, use equivalent API verification endpoints and retain
sanitized outputs with backup evidence. Do not paste object keys, raw payload
bytes, bearer tokens, private keys, database URLs, or customer data into public
channels.

## Forward Fix Or Restore

Prefer restoring the correct object bytes when historical evidence is missing
or mismatched. If an object cannot be recovered, do not mutate historical
evidence. Record the missing object as a verification failure, create new
evidence for any replacement payload, regenerate affected packages, and include
the limitation in customer-facing reports.

## Evidence To Keep

- Database backup identifier and restore timestamp.
- Object-store backup identifier, bucket, prefix, and restore timestamp.
- Evydence release tag, commit, OpenAPI checksum, and migration checksum.
- Backup manifest and verification output.
- List of affected object refs or evidence IDs, sanitized for sharing.
- Package, bundle, readiness, and audit-chain verification results.
- Operator notes about provider-side IAM, encryption, lifecycle, object lock,
  and retention assumptions.
