# Architecture

Evydence follows a ports-and-adapters shape:

- `internal/domain` defines release-ledger resource types and schema version constants.
- `internal/app` owns tenant isolation, API key authorization, evidence immutability, canonical hashes, audit-chain entries, signing, release bundles, deterministic policy checks, and storage ports.
- `internal/adapters/httpapi` adapts the application service to HTTP and OpenAPI.
- `internal/adapters/postgres` provides the durable ledger-state store, migration runner, and persisted outbox.
- `internal/adapters/objectstore/filesystem` stores raw uploaded payload bytes under tenant-prefixed object keys for local and self-hosted deployments.
- `cmd/*` contains process entry points.

Core logic does not depend on HTTP routers, SQL drivers, object storage SDKs, queues, KMS providers, provider clients, or UI frameworks. PostgreSQL persistence currently stores a versioned ledger snapshot plus outbox rows; the relational tables remain in migrations as the stable schema direction for a later repository split.

## Security Boundaries

Tenant isolation is enforced in application methods before reads and writes return data. API keys are scoped, revocable, and stored as HMAC-SHA256 hashes with `EVYDENCE_API_KEY_PEPPER`. Evidence and release bundle records are append-only in behavior; changes are represented by supersession, links, verification receipts, or new audit-chain entries.

When `EVYDENCE_DATABASE_URL` is set, mutations are saved to PostgreSQL before successful responses return. Upload payload bytes are written to the configured filesystem object store with tenant-prefixed keys and SHA-256 digest checks before metadata is accepted. Outbox jobs are persisted in PostgreSQL and claimed by workers with `FOR UPDATE SKIP LOCKED`.

## Limitations

The in-process store remains available only when `EVYDENCE_DATABASE_URL` is unset. S3/MinIO runtime object storage, external signing-key providers, KMS/HSM support, and fully relational per-resource repositories remain roadmap work. `ENV=production` rejects the in-process store, default API-key pepper, and local plaintext signing-key mode.
