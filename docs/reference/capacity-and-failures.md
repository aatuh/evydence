# Capacity And Failure Modes

This reference gives starting guidance for the controlled self-hosted
production candidate profile. It is not a benchmark claim.

## Supported Concurrency Profile

- API writer replicas: `1`.
- Worker replicas: may scale horizontally when PostgreSQL outbox locking is
  enabled.
- Single API writer mode is an intentional supported profile for controlled
  self-hosted deployments with reviewed recovery procedures and worker scaling.
- API multi-writer HA remains unsupported until a reviewed concurrency design
  replaces or extends the current single-writer stance. It is a blocker for any
  future broad production or hosted SaaS claim, not for the current controlled
  self-hosted production candidate profile.

## Single-Writer Decision

Evydence keeps one API writer as the supported long-term profile for the
current release line. This is acceptable for small internal deployments and
design-partner pilots when the operator has:

- a supervised API process managed by systemd, Kubernetes, or equivalent;
- a working PostgreSQL writer lease and startup refusal for extra writers;
- worker replicas scaled separately for parser, signing, and report backlog;
- backups and restore rehearsals for PostgreSQL and object storage;
- documented maintenance windows for API upgrades and migrations;
- monitoring on readiness, outbox backlog, database connectivity, and object
  storage failures.

The multi-writer backlog remains technical hardening work: finish focused
repository decomposition, add optimistic concurrency or transaction-scoped
resource locks where needed, test concurrent writes per resource family, and
re-run the production exit review before changing the supported HA claim.
The detailed decision record is [HA strategy](ha-strategy.md).

## Practical Sizing Inputs

Operators should measure these values in their own environment:

- average and maximum uploaded payload size;
- object-store latency and error rate;
- PostgreSQL connection pool usage;
- outbox backlog age and retry counts;
- release bundle generation time;
- report generation time;
- customer package export size;
- audit-chain verification time for the largest tenant.

## Starting Configuration

- Keep API writer replicas at one.
- Set worker replicas based on outbox backlog and parser/signing/report load.
- Use external PostgreSQL with backups and tested restore.
- Use S3/MinIO-compatible object storage for shared deployments.
- Keep reverse-proxy request body limits aligned with Evydence upload limits.
- Monitor `/v1/ready`, admin metrics, outbox backlog, failed jobs, database
  connection errors, and object-store errors.

## PostgreSQL Pool Budgets

Each PostgreSQL Store has its ordinary command/query pool and a separate
package-preparation pool. The latter serves committed release/evidence-bundle
and customer-package snapshots, plus local package signing-key reads. It uses
the same database, TLS and session scope configuration, with read-only sessions,
zero minimum/idle-reserved connections and a maximum of
`min(primary pool_max_conns, 4)`. Connections are opened on demand; Store shutdown
closes both pools.

Budget up to `primary pool_max_conns + min(primary pool_max_conns, 4)` connections
per Store, not just the primary URL's pool limit. The writer lease consumes a
primary-pool connection. Package preparation needs independent read capacity
because concurrent commands can occupy the primary pool while waiting on the
winning idempotency reservation. Its manifest inputs still come from a separate
committed, read-only repeatable-read view; reading the pending write transaction
would change that contract. Row/byte budgets, tenant predicates, signing-key
revalidation and command atomicity are unchanged. Saturation of the read pool
honors the caller's cancellation/deadline; this is not a throughput guarantee.

## Built-In Output Budgets

The application applies these fixed output and diagnostic budgets. API
operations fail validation rather than returning a partial artifact; process
diagnostics use the explicit truncation behavior shown below:

| Operation | Budget | Behavior at limit |
| --- | --- | --- |
| Customer package HTML report | 4 MiB rendered bytes | Package export fails validation; no partial archive is returned. |
| CRA readiness HTML package | 4 MiB rendered bytes | Report creation fails validation. |
| PDF report package | 4 MiB rendered bytes | Report creation fails validation. |
| Evidence summary | 512 evidence records / 4 MiB serialized bytes | Summary creation fails validation. |
| Evidence graph snapshot | 4,096 nodes / 8,192 edges / 4 MiB serialized bytes | Snapshot creation fails validation. |
| Customer package archive | 10 MiB per entry / 40 MiB expanded / 32 MiB archive | Export fails validation rather than producing an archive the offline verifier would reject. |
| Process diagnostic | 64 KiB before redaction | Longer error and log diagnostics are truncated before bounded regular-expression redaction. |

These are resource-safety limits, not supported-capacity claims. Split the
scope or use a narrower package/report request when a review needs more
records.

Lifecycle-event reasons and detail maps use the same sensitive-field policy as
process diagnostics and customer artifacts. New records are sanitized before
persistence, and historical records are sanitized when projected through the
API. Customer-package VEX summaries omit author/contact data. Custom report
templates are stored as bounded data and select from an explicit allowed-field
list; Evydence does not execute tenant-provided regular expressions or template
programs.

## Failure Modes

| Failure | Expected Behavior | Operator Action |
| --- | --- | --- |
| Migrator starts while a runtime holds its schema lease | Coordinator waits within the migration deadline; no migration runs under an updated active daemon. | Use the [stop/drain procedure](../runbooks/upgrade.md#stop-and-restart-the-reference-deployment); verify every old process stopped before retrying the reviewed plan. |
| Managed migration ends failed/interrupted/uncertain | Startup/readiness rejects an unsatisfied managed operation even if version rows look current. | Inspect bounded [operation history](../how-to/database-roles.md#run-a-managed-migration), repair and rerun the managed plan; do not erase audit rows. |
| Empty/mismatched network allowlists | An enforcing CNI prevents intended database/storage/provider access; startup or readiness can fail. | Review [chart network peers](../kubernetes.md#network-and-disruption-policy), DNS and CNI observations; do not classify blocked reads as missing objects. |
| Non-root pod cannot read projected files | Private credential loading fails before normal processing. | Check numeric IDs, fsGroup, selected Secret keys and volume permissions; do not make credentials world-readable. |
| Node drain cannot evict the API | The default PDB retains the only available writer. | Coordinate the planned maintenance outage; explicit scaling and node failure are outside that budget's protection. |
| Dead-letter projection returns 409 | Unsafe/oversized stored metadata rejects the whole page. | Preserve the failure and investigate; do not edit historical rows or return partial diagnostics. |
| Second API writer starts | Production startup fails when writer mode or PostgreSQL advisory lease rejects it. | Keep one API writer replica and investigate deployment drift. |
| Worker crashes | Persisted outbox jobs remain claimable by another worker after retry/backoff. | Check worker logs and outbox metrics; restart worker after fixing configuration. |
| Object payload missing | Parser, verification, or package generation fails safely. | Restore object payload from backup and re-run verification. |
| Object digest mismatch | Payload is not trusted and verification fails. | Investigate database/object backup pairing before retrying. |
| PostgreSQL unavailable | API/worker startup or operations fail rather than silently using in-process state in production. | Restore database service and verify migrations/readiness. |
| Signing provider unavailable | Signing operation records failure without logging raw payload bytes or secrets. | Restore provider, rotate credentials if needed, and retry through an append-only operation. |
| Provider validation unavailable | Provider verification records failed/limited checks. | Retry after provider/gateway recovery; do not treat metadata capture as provider truth. |

## Benchmark Policy

Use [bounded operator receipts](../runbooks/incident-response.md#capture-bounded-operator-evidence)
for backlog and reviewed dead letters. Compare eligible/overdue/expired-lease
signals, database pool waits and object/provider outcomes through the
[observability runbook](../runbooks/observability.md); pending count alone does
not establish throughput or worker liveness. Drain preserves lease fencing and
replay requires an explicit audited operation after fixing the cause. Read-only
root filesystems use bounded disposable scratch, not durable evidence storage;
measure pod memory and ephemeral-storage usage against configured limits.

Do not publish broad throughput or scale claims without recording:

- Evydence commit/tag and release manifest;
- database and object-store versions;
- machine sizes and network shape;
- payload sizes and evidence mix;
- API and worker replica counts;
- pass/fail criteria and limitations.

For a repo-owned local regression benchmark that includes HTTP, PostgreSQL,
filesystem object storage, worker startup, release-readiness reporting, package
creation, and audit-chain verification, run:

```sh
EVYDENCE_TEST_DATABASE_URL=... make benchmark-check
```

The output under `tmp/production-benchmark/` is benchmark evidence for that
disposable environment only.
