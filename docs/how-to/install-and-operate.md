# Install And Operate

Use this guide for a local self-hosted development or evaluation deployment.

For operator evaluation, start from the current public release candidate
[`v0.1.0-rc.5`](https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.5).
Download the release archive for your platform, then verify `SHA256SUMS`,
`openapi.sha256`, `migrations.sha256`, and the signed release manifest before
starting the API or worker. Source checkout remains the local development path.
See [Release evidence index](../reference/release-evidence-index.md) for the
artifact map and exact verification commands.

## Runtime Modes

| Mode | How To Enable | Expected Use |
|------|---------------|--------------|
| In-process state | Leave `EVYDENCE_DATABASE_URL` unset. | Local demos and unit tests. State is lost when the process exits. |
| PostgreSQL state | Set `EVYDENCE_DATABASE_URL`. | Durable local or self-hosted operation with migrations and persisted outbox jobs. |
| Production checks | Set `ENV=production`. | Rejects unsafe local defaults before API startup. |

Configuration details live in [Configuration](../reference/configuration.md).

## Install From The Public Release Candidate

For a release-backed evaluation on Linux amd64:

```sh
mkdir -p dist/v0.1.0-rc.5
gh release download v0.1.0-rc.5 --repo aatuh/evydence --dir dist/v0.1.0-rc.5
(cd dist/v0.1.0-rc.5 && sha256sum -c SHA256SUMS)
(cd dist/v0.1.0-rc.5 && sha256sum -c openapi.sha256)
sha256sum -c dist/v0.1.0-rc.5/migrations.sha256
tar -C dist/v0.1.0-rc.5 -xzf dist/v0.1.0-rc.5/evydence_v0.1.0-rc.5_linux_amd64.tar.gz
./dist/v0.1.0-rc.5/evydence_v0.1.0-rc.5_linux_amd64/evydence release verify \
  --manifest dist/v0.1.0-rc.5/evydence-release-manifest.json \
  --signature dist/v0.1.0-rc.5/evydence-release-manifest.sig.json
```

Expected result: checksum verification exits successfully, manifest signature
verification prints `release manifest verified`, and the extracted directory
contains `evydence`, `evydence-api`, `evydence-worker`, and
`evydence-migrate`.

For the same verification from a clean temporary directory, use the checked
helper:

```sh
make public-release-verify TAG=v0.1.0-rc.5
```

Expected result: the helper downloads the public GitHub Release assets,
verifies `SHA256SUMS`, `openapi.sha256`, `migrations.sha256`, validates the
in-toto provenance statement shape, extracts the Linux amd64 CLI from the
downloaded archive, and prints `public release verified`.

To run a release-binary local demo instead of `go run`, use the extracted
`evydence-api` and `evydence-worker` binaries with the same environment
variables shown below. The in-process tutorial is still local-only; for durable
evaluation set `EVYDENCE_DATABASE_URL` and run migrations first.

## Start Local Dependencies

```sh
make compose-up
```

Expected result: Docker Compose starts PostgreSQL and MinIO containers using `.env.example` defaults unless local overrides are present.

Stop them with:

```sh
make compose-down
```

## Run The Production-Like Local Stack

For a fuller local rehearsal, use `compose.production-like.yml`. It starts
PostgreSQL, MinIO, bucket initialization, migrations, one API writer, and one
worker. It is still a local evaluation stack: replace every secret, use TLS at
the edge, back up PostgreSQL and object storage together, and keep production
API writer replicas at one for the current supported profile.

```sh
export POSTGRES_PASSWORD='replace-with-long-random-password'
export MINIO_ROOT_PASSWORD='replace-with-long-random-password'
export EVYDENCE_API_KEY_PEPPER='replace-with-long-random-pepper'
docker compose -f compose.production-like.yml up --build
```

Expected result:

- migrations complete before the API and worker start;
- MinIO bucket `evydence` is created when absent;
- the API listens on `http://localhost:8080`;
- `/v1/ready` returns `200` after startup.

This stack intentionally sets `EVYDENCE_PRINT_BOOTSTRAP_SECRET=false`. Create
or rotate production credentials through controlled operator procedures rather
than printing bootstrap secrets in shared logs.

## Run With PostgreSQL

```sh
cp .api.env.example .api.env
set -a; . ./.api.env; set +a
make migrate
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true go run ./cmd/evydence-api
```

Expected result:

- `make migrate` exits successfully after applying migrations from `migrations/`.
- API startup logs that it is using PostgreSQL state and the configured object store.
- If the store is empty and bootstrap is enabled, the API prints a one-time local admin secret.

Run the worker in a separate shell with the same environment:

```sh
set -a; . ./.api.env; set +a
go run ./cmd/evydence-worker
```

The worker validates persisted outbox jobs. See [Worker outbox contract](../reference/worker-outbox.md) for job kinds, idempotency, and safe logging rules.

## Verify The Local Runtime

```sh
curl -sS http://localhost:8080/v1/ready | jq .
make live-postgres-check
make postgres-integration-test
```

Expected result:

- `/v1/ready` returns `200` with low-detail status JSON.
- Live PostgreSQL checks run when `EVYDENCE_TEST_DATABASE_URL` is set.
- If `EVYDENCE_TEST_DATABASE_URL` is unset, the Make targets print an explicit skip message and exit successfully.

For the full release gate, use [Release validation](../reference/release-validation.md) as the canonical command reference.

## Backup Pairing

Back up PostgreSQL and the configured object store together. Backup manifests record ledger-state hashes and consistency checks, but they are not backups by themselves. Restore confidence depends on matched database and object payload backups plus the OpenAPI, migration, and release artifact versions used at the time of the backup.
