# Evydence v0.1.0-rc.1 Release Notes

Status: Controlled self-hosted production candidate.

This release candidate is intended for evaluation, pilots, and controlled
internal production after operator review. It is not legal compliance proof,
not a certification, not a secure-release guarantee, not complete SBOM proof,
not authoritative vulnerability coverage, and not auditor or regulator
acceptance.

## Supported Profile

- Self-hosted API, worker, PostgreSQL, and object storage deployment.
- Use a single API writer replica for the current production profile.
- Worker replicas may scale through PostgreSQL outbox row locking.
- External TLS, secret management, backup automation, monitoring, and incident
  response remain operator responsibilities.

## Evidence In This Release Package

- Passing `make production-check` evidence with live PostgreSQL.
- `release-check-summary.txt` from the same run.
- `coverage.out` and threshold evidence.
- `openapi.yaml` and `openapi.sha256`.
- `migrations.sha256`.
- `SHA256SUMS` for release archives and evidence files.
- Signed release artifact manifest and manifest signature.

## Install And Upgrade Notes

- Use PostgreSQL for durable runtime state.
- Use S3/MinIO-compatible object storage or the documented filesystem mode for
  local evaluation only.
- Set `ENV=production`, a non-default `EVYDENCE_API_KEY_PEPPER`, and
  `EVYDENCE_SIGNING_KEY_MODE=external` for production-profile startup.
- Apply all committed migrations before starting API or worker processes.
- For Kubernetes, set an explicit image tag or digest and keep API replicas at
  `1` until HA/multi-writer support is reviewed.

## Known Limitations

- Full repository decomposition remains hardening work; focused critical
  PostgreSQL writes cover the highest-risk runtime mutations, but not every
  resource family.
- HA/multi-writer API operation is not supported in this profile.
- Direct cloud KMS/HSM SDK adapters are not included.
- Live GitHub/GitLab provider API validation and external group
  synchronization remain deployment-dependent.
- Broader WORM/object-lock proof beyond configured S3/MinIO checks remains
  deployment-dependent.
- Operators must run backup and restore rehearsals for their target
  infrastructure before relying on this in production.
