# Evydence

Evydence is a self-hosted, API-first evidence ledger for software release evidence. It supports compliance readiness by organizing and verifying technical evidence, producing tamper-evident records, and showing gaps, assumptions, exceptions, and limitations.

It does not make legal compliance conclusions, certify releases as secure, prove SBOM completeness, or treat scanner findings as authoritative.

## Current Implementation

This repository now contains the release-ledger MVP scaffold:

- Go module `github.com/aatuh/evydence`.
- HTTP API under `/v1` using `github.com/aatuh/api-toolkit/v3` route contracts, OpenAPI generation, response helpers, and Problem Details.
- Multi-tenant scoped API keys with one-time secret output, HMAC-SHA256 storage, and server-side scope checks.
- Products, projects, releases, release candidates, artifacts, container images, artifact signatures, evidence search, evidence lifecycle events, CycloneDX SBOM upload, OpenVEX upload, generic vulnerability scan upload, vulnerability decisions, exceptions, OpenAPI upload, collectors, build runs, DSSE/in-toto build attestation upload, source repositories/commits/branches/pull requests, deployment environments/events, control frameworks, control evidence links, policy evaluation, missing-evidence, release-readiness, control-coverage and CRA-readiness reports, signing keys, signed release bundles, and verification endpoints.
- In-process store for local demos and unit-test execution when `EVYDENCE_DATABASE_URL` is unset.
- PostgreSQL-backed durable ledger state, tenant-scoped relational resource projection rows, and persisted outbox jobs when `EVYDENCE_DATABASE_URL` is set.
- Filesystem object storage for raw upload payload bytes, keyed under tenant-prefixed paths.
- Schema migrations applied by `make migrate` or by the API/worker startup path unless `EVYDENCE_SKIP_MIGRATIONS=true`.
- Docker Compose dependencies for PostgreSQL and MinIO.
- A polling `cmd/evydence-worker` process that claims persisted outbox jobs with PostgreSQL row locking and records retry or terminal status.
- A local `cmd/evydence` helper for hashing, manifest verification, and GitHub Actions build provenance upload.

## Local API

```sh
cp .api.env.example .api.env
set -a; . ./.api.env; set +a
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true go run ./cmd/evydence-api
```

The API listens on `EVYDENCE_ADDR`, defaulting to `:8080`. Local bootstrap output includes a one-time admin API key secret. Leave `EVYDENCE_DATABASE_URL` unset for in-process local demos, or set it to use PostgreSQL-backed durable state.

Use the secret as:

```sh
Authorization: Bearer <secret>
Idempotency-Key: <stable-create-key>
```

## Validation

```sh
make test
make openapi-check
make fast-check
```

PostgreSQL checks are opt-in so unit tests stay fast:

```sh
make compose-up
set -a; . ./.test.env; set +a
make live-postgres-check
make postgres-integration-test
```

`make finalize` runs the project-owned formatting, unit, OpenAPI, and docs gates.
