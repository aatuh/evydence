# Pilot Deployment Checklist

This how-to is a copy-paste checklist for one narrow design-partner pilot
profile: a single self-hosted Evydence tenant, one API writer replica, scalable
worker replicas, external PostgreSQL, external S3/MinIO-compatible object
storage, reverse-proxy TLS, and operator-managed signing material.

Use it before a pilot starts and keep the completed copy with the deployment
record. The checklist supports deployment readiness review only. It is not legal
compliance proof, certification, complete SBOM proof, authoritative scanner
coverage, auditor acceptance, or a secure-release guarantee.

Use the [external controls matrix](../reference/external-controls-matrix.md) to
assign repo-owned, operator-owned, provider-owned, and legal/review-owned
controls before accepting pilot traffic.

## Required Before Pilot Traffic

### Environment

- [ ] Required: deployment owner named:
- [ ] Required: pilot tenant name and expected products/releases recorded:
- [ ] Required: `ENV=production` configured for the API and workers.
- [ ] Required: one API writer replica configured.
- [ ] Required: worker replicas configured and sized for the expected evidence
      upload volume.
- [ ] Required: `GET /v1/ready` returns ready after migrations and worker
      startup.
- [ ] Recommended: capacity assumptions recorded from
      `docs/reference/capacity-and-failures.md`.

### Database

- [ ] Required: external PostgreSQL is provisioned outside the application
      container.
- [ ] Required: `EVYDENCE_DATABASE_URL` is supplied from deployment secrets, not
      source control or logs.
- [ ] Required: migrations have been applied with the release artifact being
      deployed.
- [ ] Required: database backups are enabled and the backup location is known.
- [ ] Recommended: database restore rehearsal completed before pilot traffic.

### Object Storage

- [ ] Required: external S3/MinIO-compatible object storage is configured for
      raw payloads and package artifacts.
- [ ] Required: object paths are tenant-prefixed.
- [ ] Required: object storage credentials are supplied from deployment secrets.
- [ ] Required: object encryption and lifecycle policy are reviewed.
- [ ] Recommended: retention or object-lock policy is verified where the pilot
      requires WORM-style controls.

### API Keys And Access

- [ ] Required: bootstrap/admin API key is generated once, stored in a secret
      manager, and not retained in shell history.
- [ ] Required: collector API keys use least-privilege scopes.
- [ ] Required: revoked or unused pilot keys are removed before traffic starts.
- [ ] Required: support/debug access uses scoped keys and expires after the
      pilot window.
- [ ] Recommended: key rotation date recorded:

### Signing Mode

- [ ] Required: signing mode is documented:
- [ ] Required: production deployments do not use plaintext local signing-key
      storage.
- [ ] Required: signing verification command has been run against a generated
      release bundle or package manifest.
- [ ] Recommended: external KMS/HSM/gateway limitations are recorded if used.

### TLS And Reverse Proxy

- [ ] Required: public API access is behind TLS.
- [ ] Required: reverse proxy or ingress request body limits match the intended
      upload sizes.
- [ ] Required: rate limiting is configured for unauthenticated and token-heavy
      endpoints.
- [ ] Required: `/v1/metrics`, `/v1/audit-log`, and `/v1/admin/instance` are not
      publicly exposed without scoped authentication.
- [ ] Recommended: ingress logs redact authorization headers and cookies.

### Image Digest And Release Evidence

- [ ] Required: release artifact manifest and signatures were verified.
- [ ] Required: image digest or binary checksum is recorded:
- [ ] Required: OpenAPI checksum and migration checksum from the release
      evidence match the deployed artifact.
- [ ] Required: release notes and known limitations were reviewed with the pilot
      owner.

### Backups And Restore Rehearsal

- [ ] Required: PostgreSQL backup schedule recorded:
- [ ] Required: object-store backup or replication policy recorded:
- [ ] Required: signing material backup or recovery policy recorded:
- [ ] Required: restore owner and escalation path recorded:
- [ ] Recommended: restore rehearsal completed with audit-chain, bundle, and
      package verification after restore.

### Migrations And Upgrade

- [ ] Required: current migration version recorded before deployment:
- [ ] Required: target migration version recorded:
- [ ] Required: upgrade runbook reviewed from `docs/runbooks/upgrade.md`.
- [ ] Recommended: rollback or forward-fix decision policy recorded:

### Package Retention And Redaction

- [ ] Required: customer package expiry defaults are set.
- [ ] Required: redaction profile reviewed against the pilot's sharing scope.
- [ ] Required: raw evidence payload bytes, private keys, bearer tokens,
      database URLs, and provider credentials are excluded from shared packages.
- [ ] Required: package access scope and intended recipients are recorded.
- [ ] Recommended: sample package inspected in the local viewer before sharing.

### Support Contact

- [ ] Required: pilot support contact:
- [ ] Required: security reporting path from `SECURITY.md` shared with the
      pilot owner.
- [ ] Required: sanitized bug-report rules from `SUPPORT.md` shared with the
      pilot owner.
- [ ] Recommended: support response expectations documented for the pilot
      window.

## Final Pilot Go/No-Go

- [ ] Required: `make production-check` passed for the deployment evidence
      environment, or every failing check has a documented pilot-blocking
      decision.
- [ ] Required: `make release-acceptance` passed for the release artifact.
- [ ] Required: backup and restore responsibilities are accepted by the
      operator.
- [ ] Required: unsupported production profiles are understood: broad regulated
      production, hosted SaaS operation, and multi-writer API high availability
      remain outside this narrow pilot profile.

Record final decision:

- [ ] Go
- [ ] No-go
- [ ] Go with documented limitations:
