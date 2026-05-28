# Production Hardening Review

This is an explanation and operator checklist for production-readiness review.

## Configuration Gate

Before labeling a deployment production, verify:

- `ENV=production` is set.
- `EVYDENCE_DATABASE_URL` points to external PostgreSQL.
- `EVYDENCE_API_KEY_PEPPER` is a non-default random value.
- `EVYDENCE_SIGNING_KEY_MODE=external` is set.
- `EVYDENCE_PRINT_BOOTSTRAP_SECRET` is unset or false.

These checks are enforced by API startup. See [Configuration](reference/configuration.md).

## Deployment Checklist

- PostgreSQL is external, backed up, monitored, and restored in a test environment.
- Object storage is external S3/MinIO-compatible storage with tenant-prefixed paths, encryption, lifecycle policy, and retention/object-lock policy where required.
- S3/MinIO object-retention policy verification has been run for required tenant prefixes, and records show bucket versioning plus default object-lock mode/duration checks with documented limitations.
- Ingress terminates TLS and does not expose internal diagnostics.
- Edge rate limiting is configured at the reverse proxy or ingress. The optional `EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE` in-process limiter is a local safety net and keys by TCP remote address only.
- `/v1/metrics`, `/v1/audit-log`, and `/v1/admin/instance` are protected by server-side scopes and are not public.
- API keys and collector keys are scoped, rotated, and stored outside source control.
- Customer portal access tokens are short-lived, scoped to one package, and handled as bearer secrets.
- Generated customer packages use explicit redaction profiles and expiry.
- Collector releases are pinned and have signature, SBOM, and vulnerability scan evidence when available.

## Backup And Restore Checklist

- Backups include PostgreSQL and object storage from the same recovery point.
- Backup evidence records the OpenAPI version, migration version, release artifact manifest, and chart or deployment version.
- Restore tests verify database/object consistency after restore.
- Audit-chain verification and release-bundle verification are run after restore.
- `POST /v1/backup-manifests` is recorded after the database and object-store backups complete.

The repository includes local and live-PostgreSQL restore rehearsals. They save ledger state, copy object payloads, start a fresh ledger from the restored state or schema, verify a backup manifest, check payload digest availability, and verify a release bundle after restore. Deployment-specific restore tests still need to exercise the target backup tooling, S3/MinIO bucket policy, secrets, signing provider, and operator recovery procedure.

Backup manifests help compare recorded ledger state. They intentionally exclude raw payload bytes and private signing-key material, so they cannot replace matched database and object-store backups.

## Deployment Verification

Compose:

```sh
make compose-up
set -a; . ./.test.env; set +a
make live-postgres-check
make postgres-integration-test
```

Expected result: live PostgreSQL migration and integration checks pass, or the targets print explicit skip lines when `EVYDENCE_TEST_DATABASE_URL` is unset.

Helm:

```sh
helm upgrade --install evydence ./deploy/helm/evydence --dry-run
kubectl rollout status deploy/evydence-api
kubectl rollout status deploy/evydence-worker
```

Expected result: rendered manifests reference the configured secret and object store, and both deployments roll out.

Air-gapped packages:

```sh
./dist/evydence release verify --manifest evydence-release-manifest.json --signature evydence-release-manifest.sig.json
```

Expected result: manifest signature and referenced artifact hashes verify before import.

This checklist supports deployment hardening and evidence organization. It is not a certification, legal compliance determination, or release-security guarantee.
