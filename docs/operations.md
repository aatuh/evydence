# Operations

## Configuration

Backend configuration is read from environment variables:

- `EVYDENCE_ADDR`: API bind address, default `:8080`.
- `EVYDENCE_API_KEY_PEPPER`: HMAC pepper for API key hashes. Use a long random value.
- `EVYDENCE_DATABASE_URL`: PostgreSQL connection string. When set, the API uses durable PostgreSQL state and persisted outbox jobs. Required for production.
- `EVYDENCE_OBJECT_DIR`: filesystem object-store root for raw uploaded payload bytes, default `tmp/objects` when PostgreSQL is enabled.
- `EVYDENCE_SKIP_MIGRATIONS`: set to `true` only when migrations are applied by an external release process.
- `EVYDENCE_MIGRATIONS_DIR`: migration directory, default `migrations`.
- `EVYDENCE_BOOTSTRAP_TENANT`: local bootstrap tenant name.
- `EVYDENCE_PRINT_BOOTSTRAP_SECRET`: set to `true` only for local development to print the bootstrap API key secret.
- `EVYDENCE_WORKER_POLL_INTERVAL`: worker outbox polling interval, default `1s`.
- `EVYDENCE_SIGNING_KEY_MODE`: production currently requires `external`; local plaintext signing keys are development-only.

Do not commit real `.env`, `.api.env`, or `.test.env` files.

## Local Dependencies

```sh
make compose-up
make compose-down
```

The current API can run without these dependencies because it uses an in-process store. PostgreSQL and MinIO are included for the persistence/object-storage implementation slice.

Run with durable PostgreSQL state:

```sh
make compose-up
set -a; . ./.api.env; set +a
make migrate
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true go run ./cmd/evydence-api
```

Run the worker in a separate shell with the same database environment:

```sh
set -a; . ./.api.env; set +a
go run ./cmd/evydence-worker
```

The current object-store implementation is filesystem-backed. MinIO is present in Docker Compose for the next S3-compatible runtime adapter slice.

## Production Caveat

The API refuses `ENV=production` unless PostgreSQL is configured, a non-default API key pepper is set, and local plaintext signing-key mode is disabled. External signing-key provider support is still roadmap work, so production mode intentionally fails closed until that provider is implemented.
