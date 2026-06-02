# HA Strategy

This reference records the current high-availability decision for Evydence
release candidates. It supports deployment planning only. It is not an uptime
guarantee, legal compliance proof, certification, complete evidence proof, or a
secure-release guarantee.

## Decision

Evydence is positioned as a single-writer self-hosted appliance for the current
controlled production-candidate release line.

The supported topology is:

- one API writer replica;
- one or more worker replicas using PostgreSQL outbox row locking;
- external PostgreSQL with backup and restore rehearsal;
- external S3/MinIO-compatible object storage with database/object backup
  pairing;
- supervised API restart through Kubernetes, systemd, or an equivalent process
  manager;
- deployment-specific recovery objectives accepted by the operator.

This is a deliberate product and engineering decision. Multi-writer API high availability is not supported
until the remaining concurrency work is
implemented, tested, and reviewed.

## Why Not Multi-Writer API Yet

The current code has focused relational write paths for high-risk resource
families, but it still keeps a large application ledger aggregate and some
cross-resource operations that are easier to reason about with a single API
writer. Scaling API writers before the remaining work is finished could create
hard-to-audit races around:

- audit-chain ordering and tenant chain continuity;
- release bundle generation and signature receipts;
- idempotency replay and conflict behavior under concurrent requests;
- evidence lifecycle append ordering;
- package/report generation from a moving release state;
- object-store metadata and database row pairing;
- remaining aggregate state synchronization for resource families not yet split
  into focused services.

The current supported stance favors clear recovery behavior over an unfinished
multi-writer design.
Use the [Persistence decomposition inventory](persistence-decomposition.md) to
inspect the current focused mutation paths, remaining broad relational-state
call sites, and next repository split order.

## Supported Recovery Boundaries

Evydence does not publish a generic SLO for all self-hosted deployments. The
operator owns the concrete target for recovery time, recovery point, support
coverage, alert routing, and maintenance windows.

For controlled self-hosted use, the expected recovery model is:

- the API process is restarted by the deployment platform if it exits;
- a second API writer should fail closed in production because startup rejects
  replica counts above one and the PostgreSQL advisory writer lease prevents a
  competing writer from taking over silently;
- worker replicas can continue or be scaled while the API is unavailable,
  subject to database and object-store availability;
- database and object-store restore must be rehearsed together before relying
  on the deployment for customer evidence workflows;
- any rollback or forward-fix procedure must preserve append-only evidence,
  audit-chain entries, signatures, packages, and object payload hashes.

## Before Multi-Writer API Is Supported

Do not change Helm defaults or production docs to advertise multi-writer API
support until all of these are true:

- all production write families have focused relational repository paths or an
  equivalent reviewed transaction design;
- tenant-scoped audit-chain appends are protected by reviewed transaction or
  resource-lock behavior;
- idempotency records are protected by transaction-backed uniqueness and replay
  tests under concurrent requests;
- release bundle, package, report, evidence lifecycle, exception, approval, and
  signing operations have concurrent write tests;
- object-store writes and database metadata writes have failure and retry tests
  that preserve digest pairing;
- `make production-check`, `make test-race`, live PostgreSQL concurrency tests,
  black-box restart tests, and restore rehearsals pass under the proposed
  topology;
- Kubernetes values, production docs, release notes, and the pilot checklist
  are updated to state the new supported topology and limitations.

## Operator Checklist

- Keep `api.replicas=1` and `api.writerMode=single`.
- Keep `EVYDENCE_API_WRITER_MODE=single` and
  `EVYDENCE_API_WRITER_REPLICAS=1`.
- Scale workers based on outbox backlog and parser/signing/report latency.
- Monitor `/v1/ready`, API process restarts, outbox backlog age, worker
  failures, database availability, object-store failures, and signing-provider
  failures.
- Rehearse paired database/object-store restore and verify audit chains,
  release bundles, and customer packages after restore.
- Record the deployment's recovery assumptions in the
  [pilot deployment checklist](../how-to/pilot-deployment-checklist.md).

## Related References

- [Production readiness](production-readiness.md)
- [Capacity and failure modes](capacity-and-failures.md)
- [Hardened reference deployment](hardened-reference-deployment.md)
- [Kubernetes deployment](../kubernetes.md)
- [Backup and restore](../runbooks/backup-restore.md)
