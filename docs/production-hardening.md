# Production Hardening Review

This is an explanation and operator checklist for production-readiness review.

Required before labeling a deployment production:

- PostgreSQL is external, backed up, monitored, and restored in a test environment.
- Object storage is external S3/MinIO-compatible storage with tenant-prefixed paths, encryption, lifecycle policy, and retention/object-lock policy where required.
- `ENV=production`, `EVYDENCE_DATABASE_URL`, non-default `EVYDENCE_API_KEY_PEPPER`, and `EVYDENCE_SIGNING_KEY_MODE=external` are set.
- API keys are scoped, rotated, and stored outside source control.
- Ingress terminates TLS and does not expose internal diagnostics.
- `/v1/metrics` and `/v1/audit-log` require admin API keys and are not public.
- Backups include PostgreSQL, object storage, OpenAPI/migration version, and release artifact manifests.
- Restore tests verify database/object consistency and audit-chain verification after restore.
- Collector releases are pinned and have signature, SBOM, and vulnerability scan evidence when available.
- Generated customer packages use explicit redaction profiles and expiry.

This checklist supports deployment hardening and evidence organization. It is not a certification, legal compliance determination, or secure-release conclusion.
