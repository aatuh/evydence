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

## Payload Reconciliation

Run reconciliation after a restore, an object-store incident, a provider
migration, or an unexpected payload verification failure. It checks one tenant
at a time. PostgreSQL payload metadata is checked with direct object reads;
provider listing is used only to report candidate provider objects without a
database owner. A listing omission is never treated as proof that a final or
staged object is missing.

Set the normal worker database and object-store environment first, then start
with the non-mutating command:

```sh
go run ./cmd/evydence-worker reconcile \
  --tenant tenant-id \
  --limit 100 \
  --provider-limit 1000
```

The command prints one receipt containing counters and numeric resume cursors;
it does not print object keys, digests, payload bytes, or provider error text.
Retain that receipt and its linked `object_payload.reconciled` audit entry with
the recovery record. When either `next_metadata_cursor` or
`next_provider_cursor` is non-zero, repeat the command with the corresponding
`--metadata-cursor` or `--provider-cursor` value. Repeating a page is safe:
the reconciliation actions are idempotent and no provider-object deletion is
available through this command.

By default, a dry run reports final-object absence, staging-object absence,
digest/metadata mismatch, recoverable finalization, old staging, and advisory
provider-orphan candidates. A staged record is reported as old after 24 hours
unless a different `--orphan-staged-after` value is supplied. Review provider
access failures separately; do not treat an incomplete list as a clean result.

After reviewing the dry-run receipt, an operator may apply lifecycle-only
quarantine and recovery. The age threshold is required explicitly and must be
at least one hour:

```sh
go run ./cmd/evydence-worker reconcile \
  --tenant tenant-id \
  --apply \
  --orphan-staged-after 24h
```

`--apply` never deletes provider data. A missing final object or missing/old
staging object is marked `orphaned`; a digest or metadata mismatch is marked
`failed`; a verified final object for a previously staged record is marked
`finalized`. Failed and orphaned payload metadata is rejected by package and
verification readers until an operator restores valid bytes and runs the
appropriate recovery/reconciliation flow. Provider-only candidates remain
reported for review or separately governed cleanup; they are not deleted by
Evydence merely because a provider listing showed them.

The authenticated `/v1/metrics` endpoint also exposes tenant-scoped
reconciliation receipt counters when PostgreSQL receipt metrics are configured.
Those metrics contain counters and receipt age only, never object identifiers
or raw evidence.

## Retention Observation Review

After the object store is available, run the retention verification endpoint for
each affected policy and retain its sanitized result with the recovery record.
The record separates configured intent from provider evidence:

- `configured` has not yet been checked.
- `not_verified` means no verifier is configured, an observation was
  unavailable or incomplete, or the provider evidence did not support a
  positive result.
- `not_enforced` means the provider observation completed but reported that the
  requested retention condition was not enforced.
- `verified` means the ledger recorded the provider, bucket, mode, duration,
  applicable sample-object/legal-hold evidence, observation time, and a
  currently valid maximum age.
- `stale` means a previously positive observation exceeded that configured
  maximum age and must be refreshed.

Use the policy's `verification_observed_at` and
`max_verification_age_hours`/`verification_expires_at` fields to schedule
rechecks. Keep bucket and object identifiers in protected operator evidence;
customer packages intentionally omit object-store paths. Never treat a local
policy record, a successful API call, or a stale observation as proof that a
provider will prevent all deletion or that a retention obligation is legally
satisfied.

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
  retention assumptions, and the time of the last provider observation.
