# Configuration Reference

This is the canonical reference for current environment files and runtime variables.

## Environment Files

| File | Used By | Purpose | Commit Real Values? |
|------|---------|---------|---------------------|
| `.env.example` | `docker-compose.yml` | Local PostgreSQL and MinIO container credentials. | No |
| `.api.env.example` | API, worker, migration command | Local API runtime settings, durable database URL, object storage mode, bootstrap tenant, and local secret printing. | No |
| `.test.env.example` | Make targets for live PostgreSQL tests | `EVYDENCE_TEST_DATABASE_URL` and test-only API key pepper. | No |

Copy examples to local untracked files when needed:

```sh
cp .api.env.example .api.env
cp .test.env.example .test.env
```

The example secrets are placeholders. Replace them before using shared or production-like infrastructure.

## Runtime Variables

| Variable | Required | Default / Example | Notes |
|----------|----------|-------------------|-------|
| `ENV` | Production only | unset locally | Set `ENV=production` to enable production-safety checks. |
| `EVYDENCE_ADDR` | No | `:8080` | API bind address. |
| `EVYDENCE_API_KEY_PEPPER` | Production yes | `change-me-long-random-pepper` | HMAC pepper for API key, session, and portal-token hashes. Use a long random value. |
| `EVYDENCE_DATABASE_URL` | Production yes | `postgres://evydence:change-me@localhost:5432/evydence?sslmode=disable` | Enables PostgreSQL durable state, projections, migrations, and persisted outbox jobs. If unset, the API uses in-process state. |
| `EVYDENCE_POSTGRES_LOAD_MODE` | No | `snapshot_preferred` locally, `relational_preferred` when `ENV=production` | PostgreSQL state load mode. Supported values are `snapshot_preferred`, `relational_preferred`, and `relational_only`. Production defaults to relational-preferred startup reads while snapshots remain available for compatibility. |
| `EVYDENCE_OBJECT_STORE` | No | `filesystem` | Supported values are `filesystem`, `s3`, and `minio`. |
| `EVYDENCE_OBJECT_DIR` | Filesystem object store | `./tmp/objects` | Local raw payload storage root. |
| `EVYDENCE_S3_ENDPOINT` | S3/MinIO object store | `localhost:9000` | Endpoint for S3-compatible object storage. |
| `EVYDENCE_S3_BUCKET` | S3/MinIO object store | `evydence` | Bucket must already exist. |
| `EVYDENCE_S3_ACCESS_KEY_ID` | S3/MinIO object store | local example value | Store outside source control. |
| `EVYDENCE_S3_SECRET_ACCESS_KEY` | S3/MinIO object store | local example value | Store outside source control and logs. |
| `EVYDENCE_S3_REGION` | No | empty | Optional S3 region. |
| `EVYDENCE_S3_USE_SSL` | No | `false` locally, `true` in chart values | Use TLS for remote object storage. |
| `EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE` | No | `0` disabled | Optional in-process per-client request limit using the TCP remote address. Use reverse-proxy or ingress rate limiting for production edge controls. |
| `EVYDENCE_SKIP_MIGRATIONS` | No | unset | Set to `true` only when migrations are applied by a separate release process. API and worker startup still verify that no committed migrations are pending and fail closed if the database is behind. |
| `EVYDENCE_MIGRATIONS_DIR` | No | `migrations` | Migration directory for API startup and `cmd/evydence-migrate`. |
| `EVYDENCE_BOOTSTRAP_TENANT` | No | `Local Tenant` | Tenant name used when bootstrapping an empty store. |
| `EVYDENCE_BOOTSTRAP_DISABLED` | No | unset | Set to `true` to prevent startup bootstrap on an empty store. |
| `EVYDENCE_PRINT_BOOTSTRAP_SECRET` | Local only | `true` in `.api.env.example` | Prints the one-time bootstrap secret. Rejected when `ENV=production`. |
| `EVYDENCE_WORKER_POLL_INTERVAL` | No | `1s` | Worker outbox polling interval. |
| `EVYDENCE_WORKER_BATCH_SIZE` | No | `10` | Maximum outbox jobs claimed per polling cycle. |
| `EVYDENCE_WORKER_MAX_PAYLOAD_BYTES` | No | `20971520` | Maximum raw object payload size replayed by a worker job. |
| `EVYDENCE_SIGNING_KEY_MODE` | Production yes | `external` for production | Production rejects local plaintext signing-key mode. |
| `EVYDENCE_SIGNING_EXECUTOR_URL` | No | unset | Optional HTTPS signing gateway used by `POST /v1/signing-operations` when `external_signature` is omitted. The API sends subject metadata and `payload_hash`, not raw payload bytes. |
| `EVYDENCE_SIGNING_EXECUTOR_TOKEN` | Signing gateway | unset | Optional bearer token for the signing gateway. Store outside source control and logs. |
| `EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS` | No | `10` | Timeout for signing gateway requests. |
| `EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST` | Local only | `false` | Allows `http://localhost` or loopback signing gateway endpoints for local development and tests. Do not use for production. |
| `EVYDENCE_TEST_DATABASE_URL` | Live tests | `.test.env.example` value | Used by `make live-postgres-check`, `make postgres-integration-test`, and `make release-check`. |

## Production Rejection Checks

When `ENV=production`, the API refuses to start unless:

- `EVYDENCE_DATABASE_URL` is set.
- `EVYDENCE_API_KEY_PEPPER` is non-empty and not the local default.
- `EVYDENCE_SIGNING_KEY_MODE=external`.
- `EVYDENCE_PRINT_BOOTSTRAP_SECRET` is not `true`.

These checks reduce unsafe runtime defaults. They do not replace secret management, network controls, backup validation, or external signing operations.

When `ENV=production` and `EVYDENCE_POSTGRES_LOAD_MODE` is unset, API and worker
processes prefer reconstructing state from tenant-scoped relational rows before
falling back to the compatibility snapshot. Local development keeps
`snapshot_preferred` by default to preserve existing workflows. Use
`relational_only` only for controlled migration or recovery checks where a
missing relational row should fail closed instead of falling back to the
snapshot.

## S3/MinIO Object-Retention Verification

When `EVYDENCE_OBJECT_STORE=s3` or `minio`, object-retention policy verification
uses the same S3/MinIO client to check bucket versioning and default
object-lock settings. The resulting policy record includes verification checks
and limitations. The check is bucket-level: operators still need to review
bucket creation mode, IAM policy, lifecycle rules, backups, and any
deployment-specific WORM requirements.

## External Signing Gateway

When `EVYDENCE_SIGNING_EXECUTOR_URL` is set, signing operations can omit
`external_signature`. Evydence sends a JSON request containing tenant id,
provider id/type, key reference, subject type/id, and `payload_hash`. The
gateway returns a signature, optional provider key id, and optional algorithm.
Evydence records the signature receipt and verification checks; it does not
store production private key material or send raw evidence payload bytes.

## Related Commands

- Local operation: [Install and operate](../how-to/install-and-operate.md)
- Release validation: [Release validation](release-validation.md)
- Kubernetes secret wiring: [Kubernetes deployment](../kubernetes.md)
