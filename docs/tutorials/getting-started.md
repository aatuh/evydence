# Getting Started

This tutorial runs the API locally and records a minimal release ledger flow.

## Prerequisites

- Go with the version declared by `go.mod`.
- Docker if you want PostgreSQL and object storage.

## Start Local Dependencies

```sh
make compose-up
set -a; . ./.test.env; set +a
make live-postgres-check
```

For an in-process demo, leave `EVYDENCE_DATABASE_URL` unset.

## Start The API

```sh
cp .api.env.example .api.env
set -a; . ./.api.env; set +a
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true go run ./cmd/evydence-api
```

Use the printed one-time bootstrap secret as a bearer token. Create and action requests require `Idempotency-Key`.

## Validate

```sh
make test
make openapi-check
```

The local flow organizes technical evidence and reports gaps, assumptions, and limitations. It does not make legal compliance or secure-release conclusions.
