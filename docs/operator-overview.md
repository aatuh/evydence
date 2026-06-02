# Operator Overview

This overview is for maintainers and self-hosted operators who need to run,
upgrade, monitor, back up, and validate Evydence.

Evydence is currently a controlled self-hosted production candidate. The
supported API deployment profile is one API writer replica with scalable worker
replicas through PostgreSQL outbox locking. See
[Production readiness](reference/production-readiness.md) and
[Production exit review](reference/production-exit-review.md) before using it
beyond evaluation.

## Primary Operator Path

1. Start with [Install and operate](how-to/install-and-operate.md) for local,
   durable, and production-like runtime modes.
2. Use [Configuration](reference/configuration.md) for environment variables
   and production-safety combinations.
3. Use [Kubernetes deployment](kubernetes.md) or
   [Air-gapped installation](air-gapped.md) only after the package and release
   evidence have been verified.
4. Run the gates in [Release validation](reference/release-validation.md) and
   [Production gate troubleshooting](reference/production-gate-troubleshooting.md)
   with sanitized logs.
5. Rehearse [Backup and restore](runbooks/backup-restore.md), follow the
   [Upgrade runbook](runbooks/upgrade.md) and
   [Upgrade compatibility policy](reference/upgrade-compatibility-policy.md), keep
   [Incident response](runbooks/incident-response.md) ready, and prepare
   [Key rotation](runbooks/key-rotation.md) plus
   [Object store recovery](runbooks/object-store-recovery.md).

## Operating Boundaries

- PostgreSQL is required for production-mode source of truth.
- Filesystem object storage is local/test oriented; S3-compatible object
  storage is the production target.
- API writers stay at one replica for the current release line.
- Worker replicas may scale through PostgreSQL outbox locking.
- API keys, collector keys, SSO sessions, portal tokens, private keys, object
  payloads, customer package contents, and raw evidence must not be logged or
  placed in public support reports.
- Release evidence supports reproducibility and engineering review, not legal
  compliance proof, certification, complete SBOM proof, authoritative scanner
  results, or a secure-release guarantee.

## Related References

- [Observability](reference/observability.md)
- [Capacity and failure modes](reference/capacity-and-failures.md)
- [External controls matrix](reference/external-controls-matrix.md)
- [Stable v0.1.0 exit criteria](reference/stable-v0.1.0-exit-criteria.md)
- [Source of truth](reference/source-of-truth.md)
