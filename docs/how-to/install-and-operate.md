# Install And Operate

Use this guide for a self-hosted development or evaluation deployment.

## Runtime Modes

- No `EVYDENCE_DATABASE_URL`: in-process state for local demos and unit tests.
- `EVYDENCE_DATABASE_URL` set: PostgreSQL-backed durable ledger snapshot, resource projections, migrations, and persisted outbox jobs.
- `ENV=production`: unsafe local defaults are rejected.

## Commands

```sh
make compose-up
set -a; . ./.test.env; set +a
make migrate
go run ./cmd/evydence-api
go run ./cmd/evydence-worker
```

## Checks

```sh
make live-postgres-check
make postgres-integration-test
make finalize
```

For release validation with live PostgreSQL evidence, start Compose, load `.test.env`, and run `make release-check`. The target writes `tmp/release-check-summary.txt`; the release validation reference explains the expected pass and skip lines.

Back up PostgreSQL and the configured object store together. Backup manifests help compare recorded ledger state, but restore confidence depends on matched database and object payload backups.
