# Operations

This operator index points to the canonical references for running Evydence. Keep command details in the linked pages so startup, configuration, and release validation guidance do not drift.

## Operator Tasks

| Task | Canonical Doc | Expected Outcome |
|------|---------------|------------------|
| Choose local or durable runtime mode | [Install and operate](how-to/install-and-operate.md) | API and worker run with either in-process state or PostgreSQL-backed state. |
| Configure environment variables | [Configuration](reference/configuration.md) | Runtime variables are set from local untracked files or deployment secrets. |
| Wire observability | [Observability](reference/observability.md) | Readiness, admin metrics, Prometheus rules, and dashboard starter assets are reviewed for the deployment. |
| Run release validation | [Release validation](reference/release-validation.md) | `tmp/release-check-summary.txt` records pass and explicit skip lines. |
| Check production readiness | [Production readiness](reference/production-readiness.md) | Live PostgreSQL, coverage, release validation, and signed release artifact smoke checks pass before production positioning. |
| Operate outbox workers | [Worker outbox contract](reference/worker-outbox.md) | Workers claim persisted jobs and fail safely on missing state, hash mismatch, or unsupported jobs. |
| Integrate CI evidence | [Integrate CI collectors](how-to/integrate-ci.md) | CI jobs upload build, attestation, source snapshot, or collector evidence with scoped secrets. |
| Deploy on Kubernetes | [Kubernetes deployment](kubernetes.md) | API and worker deploy with external PostgreSQL, object storage, and external signing mode. |
| Build an offline package | [Air-gapped installation](air-gapped.md) | Package manifests and signatures are verified before import. |
| Review production hardening | [Production hardening review](production-hardening.md) | Unsafe defaults, backup gaps, diagnostics exposure, and customer package handling are reviewed. |

## Integrity Operations

- Use `GET /v1/ready` for low-detail readiness checks.
- Use `GET /v1/metrics` only with an admin API key; it returns safe tenant resource counts as JSON or Prometheus text when `Accept: text/plain` is sent, not raw evidence payloads or secrets.
- Use `GET /v1/admin/instance` only with an actor explicitly granted `instance:admin`. Tenant admin and ordinary wildcard tenant keys do not satisfy this instance-wide scope by themselves.
- Use `POST /v1/backup-manifests` after database and object-store backups complete. The manifest intentionally excludes raw payload bytes and private signing-key material.
- Use `POST /v1/merkle-batches` and `POST /v1/transparency-checkpoints` to record signed local checkpoints and optional external anchoring metadata.
- Use `POST /v1/public-transparency-log-entries/{id}/verify` when an operator has public-log inclusion proof material. Evydence verifies the supplied RFC6962-style proof locally and records checks and limitations; it does not fetch proof material from the provider.

## Token And Trust Boundaries

- API keys, collector keys, SSO session tokens, and customer portal access tokens are bearer secrets. Do not place them in logs, documentation, long-lived build output, or customer packages.
- Customer portal access tokens are returned once by `POST /v1/customer-portal/access`, expire, and are stored as hashes. Deployments should still use reverse-proxy or API-gateway throttling for the unauthenticated portal endpoint.
- Human SSO session records are admin-managed, authenticated SSO sessions can revoke themselves through API-first logout, and SSO credential exchange can set an HttpOnly session cookie after locally verifying an OIDC ID token or SAML assertion against tenant-configured trust material. OIDC group claim values can be captured on the session and mapped to configured roles without creating permanent role bindings from token claims. Current endpoints can refresh OIDC public JWKS from discovery metadata, but they do not implement live provider API validation or external group synchronization.
- Object-retention APIs record and verify retention intent for tenant-prefixed object paths. Enforcing WORM or object-lock settings remains the responsibility of the configured object store and deployment policy.

Evydence operations support evidence organization, review, and tamper-evident records. Operational checks do not replace external audit review, secret management, backup testing, or provider verification.
