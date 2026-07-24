# Operations

This operator index points to the canonical references for running Evydence. Keep command details in the linked pages so startup, configuration, and release validation guidance do not drift.

## Operator Tasks

| Task | Canonical Doc | Expected Outcome |
|------|---------------|------------------|
| Choose local or durable runtime mode | [Install and operate](how-to/install-and-operate.md) | API and worker run with either in-process state or PostgreSQL-backed state. |
| Rehearse production-like Compose | [Install and operate](how-to/install-and-operate.md) | API, worker, migrations, PostgreSQL, and MinIO start together with one API writer. |
| Configure environment variables | [Configuration](reference/configuration.md) | Runtime variables are set from local untracked files or deployment secrets. |
| Wire observability | [Observability](reference/observability.md) | Readiness, admin metrics, Prometheus rules, and dashboard starter assets are reviewed for the deployment. |
| Run release validation | [Release validation](reference/release-validation.md) | `tmp/release-check-summary.txt` records pass and explicit skip lines. |
| Check production readiness | [Production readiness](reference/production-readiness.md) | Live PostgreSQL, coverage, release validation, and signed release artifact smoke checks pass before production positioning. |
| Operate outbox workers | [Worker outbox contract](reference/worker-outbox.md) | Workers claim persisted jobs and fail safely on missing state, hash mismatch, or unsupported jobs. |
| Integrate CI evidence | [Integrate CI collectors](how-to/integrate-ci.md) | CI jobs upload build, attestation, source snapshot, or collector evidence with scoped secrets. |
| View packages locally | [View packages locally](how-to/view-packages.md) | Customer package and readiness JSON can be inspected without uploading data. |
| Deploy on Kubernetes | [Kubernetes deployment](kubernetes.md) | API and worker deploy with external PostgreSQL, object storage, and external signing mode. |
| Build an offline package | [Air-gapped installation](air-gapped.md) | Package manifests and signatures are verified before import. |
| Prepare a design-partner pilot | [Pilot deployment checklist](how-to/pilot-deployment-checklist.md) | One narrow pilot profile is reviewed for environment, database, object storage, access, signing, TLS, backups, migrations, redaction, and support. |
| Review production hardening | [Production hardening review](production-hardening.md) | Unsafe defaults, backup gaps, diagnostics exposure, and customer package handling are reviewed. |
| Rehearse backup and restore | [Backup and restore runbook](runbooks/backup-restore.md) | Database/object-store pairing and post-restore verification are recorded. |
| Upgrade a deployment | [Upgrade runbook](runbooks/upgrade.md) | Release artifacts, migrations, and post-upgrade verification are checked. |
| Respond to incidents | [Incident response runbook](runbooks/incident-response.md) | Secrets, tenant data, signing, provider, and package boundaries are handled without public leakage. |
| Review capacity and failure modes | [Capacity and failure modes](reference/capacity-and-failures.md) | Single-writer API limits, worker scaling, object-store failures, and retry behavior are understood. |
| Review benchmark evidence | [Benchmark results](reference/benchmark-results.md) | Local evidence-ingestion benchmark scope and limitations are clear. |
| Review release status | [Production exit review](reference/production-exit-review.md) | The controlled self-hosted candidate status and unresolved blockers are explicit. |

## Integrity Operations

- Use `GET /v1/health` for process liveness only. Use unauthenticated `GET /v1/ready` for low-detail dependency-backed readiness; it returns `503` when a required configured dependency is unavailable and never returns raw errors, credentials, paths, or tenant data. Use `GET /v1/admin/readiness` only with an explicit `instance:admin` actor for vetted per-check diagnostics.
- Use `GET /v1/version` to record API build identity with a release review. It reports source and release-input metadata, not an independent signature or deployment-trust conclusion.
- Use `GET /v1/metrics` only with an admin API key; it returns safe tenant resource counts as JSON or Prometheus text when `Accept: text/plain` is sent, not raw evidence payloads or secrets.
- Use `GET /v1/admin/instance` only with an actor explicitly granted `instance:admin`. Tenant admin and ordinary wildcard tenant keys do not satisfy this instance-wide scope by themselves.
- Use `POST /v1/backup-manifests` after database and object-store backups complete. The manifest intentionally excludes raw payload bytes and private signing-key material.
- Use `POST /v1/merkle-batches` and `POST /v1/transparency-checkpoints` to record signed local checkpoints and optional external anchoring metadata.
- Use `POST /v1/public-transparency-log-entries/{id}/verify` when an operator has public-log inclusion proof material. Evydence verifies the supplied RFC6962-style proof locally and records checks and limitations; it does not fetch proof material from the provider.

## Token And Trust Boundaries

- API keys, collector keys, SSO session tokens, and customer portal access tokens are bearer secrets. Do not place them in logs, documentation, long-lived build output, or customer packages.
- Customer portal access tokens are returned once by `POST /v1/customer-portal/access`, expire, and are stored as hashes. Access can require explicit NDA acceptance, and portal ZIP downloads can include non-secret distribution watermarks. Successful manifest exchanges, ZIP downloads, NDA acceptance events, and failed known-prefix attempts write audit-chain entries under the portal access record and relevant package record without storing the supplied token. Deployments should still use reverse-proxy or API-gateway throttling for the unauthenticated portal endpoint.
- Human SSO session records are admin-managed, authenticated SSO sessions can revoke themselves through API-first logout, and SSO credential exchange can set an HttpOnly session cookie after locally verifying an OIDC ID token or SAML assertion against tenant-configured trust material. OIDC group claim values can be captured on the session and mapped to configured roles without creating permanent role bindings from token claims. Current endpoints can refresh OIDC public JWKS from discovery metadata and can call a configured OIDC UserInfo endpoint or provider validation gateway for verification checks, but they do not implement direct provider-specific management API clients or external group synchronization.
- Object-retention APIs record and verify retention intent for tenant-prefixed object paths. S3/MinIO verification can check bucket defaults plus sample-object retention and legal hold where configured. Enforcing WORM or object-lock settings remains the responsibility of the configured object store and deployment policy.

Evydence operations support evidence organization, review, and tamper-evident records. Operational checks do not replace external audit review, secret management, backup testing, or provider verification.
