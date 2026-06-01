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

## Failure Modes

| Failure | Expected Behavior | Operator Action |
| --- | --- | --- |
| Second API writer starts | Production startup fails when writer mode or PostgreSQL advisory lease rejects it. | Keep one API writer replica and investigate deployment drift. |
| Worker crashes | Persisted outbox jobs remain claimable by another worker after retry/backoff. | Check worker logs and outbox metrics; restart worker after fixing configuration. |
| Object payload missing | Parser, verification, or package generation fails safely. | Restore object payload from backup and re-run verification. |
| Object digest mismatch | Payload is not trusted and verification fails. | Investigate database/object backup pairing before retrying. |
| PostgreSQL unavailable | API/worker startup or operations fail rather than silently using in-process state in production. | Restore database service and verify migrations/readiness. |
| Signing provider unavailable | Signing operation records failure without logging raw payload bytes or secrets. | Restore provider, rotate credentials if needed, and retry through an append-only operation. |
| Provider validation unavailable | Provider verification records failed/limited checks. | Retry after provider/gateway recovery; do not treat metadata capture as provider truth. |

## Benchmark Policy

Do not publish broad throughput or scale claims without recording:

- Evydence commit/tag and release manifest;
- database and object-store versions;
- machine sizes and network shape;
- payload sizes and evidence mix;
- API and worker replica counts;
- pass/fail criteria and limitations.
