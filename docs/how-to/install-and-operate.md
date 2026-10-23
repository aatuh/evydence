# Install And Operate

Use this guide for a local self-hosted development or evaluation deployment.

For operator evaluation, start from the current public release candidate
[`v0.1.0-rc.7`](https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.7).
Download the release archive for your platform, then verify `SHA256SUMS`,
`openapi.sha256`, `migrations.sha256`, and the signed release manifest before
starting the API or worker. Source checkout remains the local development path.
See [Release evidence index](../reference/release-evidence-index.md) for the
artifact map and exact verification commands.

## Runtime Modes

| Mode | How To Enable | Expected Use |
|------|---------------|--------------|
| PostgreSQL state | Set `EVYDENCE_RUNTIME_PROFILE=postgres` and `EVYDENCE_DATABASE_URL`. | Durable local or self-hosted operation with migrations and persisted outbox jobs. |
| Production checks | Set `ENV=production`. | Rejects unsafe local defaults before API startup. |

Current source requires PostgreSQL for API evaluation; the former `local_memory`
profile is retired. This unreleased change does not alter already published
release binaries. See the [migration note](../reference/configuration.md#retired-local-memory-profile-unreleased).
Unit tests may still use in-memory fakes.

Configuration details live in [Configuration](../reference/configuration.md).
For production planning, use `.production.env.example` as a deployment-secret
checklist and translate it into your secret manager or Helm values; do not use
local `.api.env.example` defaults for production.

## Install From The Public Release Candidate

For a release-backed evaluation on Linux amd64:

```sh
mkdir -p dist/v0.1.0-rc.7
gh release download v0.1.0-rc.7 --repo aatuh/evydence --dir dist/v0.1.0-rc.7
(cd dist/v0.1.0-rc.7 && sha256sum -c SHA256SUMS)
(cd dist/v0.1.0-rc.7 && sha256sum -c openapi.sha256)
sha256sum -c dist/v0.1.0-rc.7/migrations.sha256
tar -C dist/v0.1.0-rc.7 -xzf dist/v0.1.0-rc.7/evydence_v0.1.0-rc.7_linux_amd64.tar.gz
./dist/v0.1.0-rc.7/evydence_v0.1.0-rc.7_linux_amd64/evydence release verify \
  --manifest dist/v0.1.0-rc.7/evydence-release-manifest.json \
  --signature dist/v0.1.0-rc.7/evydence-release-manifest.sig.json
```

Expected result: checksum verification exits successfully, manifest signature
verification prints `release manifest verified`, and the extracted directory
contains `evydence`, `evydence-api`, `evydence-worker`, and
`evydence-migrate`.

For the same verification from a clean temporary directory, use the checked
helper:

```sh
EVYDENCE_RELEASE_ALLOW_LEGACY_EVIDENCE=1 make public-release-verify TAG=v0.1.0-rc.7
```

Expected result: the helper downloads the public GitHub Release assets,
verifies `SHA256SUMS`, `openapi.sha256`, `migrations.sha256`, validates the
in-toto provenance statement shape, extracts the Linux amd64 CLI from the
downloaded archive, and prints `public release verified`.

To run a release-binary local demo instead of `go run`, use the extracted
`evydence-api` and `evydence-worker` binaries with the same environment
variables shown below. The in-process tutorial is still local-only; for durable
evaluation set `EVYDENCE_RUNTIME_PROFILE=postgres` and `EVYDENCE_DATABASE_URL`,
then run migrations first.

## Start Local Dependencies

```sh
make compose-up
```

Expected result: Docker Compose starts PostgreSQL and source-built MinIO
containers using `.env.example` defaults unless local overrides are present.
The first MinIO build downloads and compiles pinned upstream Go modules; later
builds reuse the local BuildKit module/compiler caches. Docker must be able to
reach Docker Official Images, the Go module proxy, and Go's checksum database.
MinIO API/console ports are bound to loopback only.

The source and base-image pins live in
`deploy/local-dependencies/Dockerfile`; `make local-dependency-images` builds
the server and bucket-initialization client without starting services.
Go checksum verification stays enabled. These are disposable CI/local
rehearsal fixtures, not published Evydence images or production object-store
recommendations. [Community MinIO is archived](https://github.com/minio/minio)
and its final releases have unresolved upstream advisories, including an
[unsigned-trailer authentication bypass](https://github.com/minio/minio/security/advisories/GHSA-hv4r-mvr4-25vw).
Use an operator-reviewed, maintained S3-compatible service for actual production
and keep test fixtures unreachable from untrusted networks.

Stop them with:

```sh
make compose-down
```

## Run The Production-Like Local Stack

For a fuller local rehearsal, use `compose.production-like.yml`. It starts
PostgreSQL, MinIO, bucket initialization, migrations, one API writer, and one
worker. It is still a local evaluation stack: replace every secret, use TLS at
the edge, back up PostgreSQL and object storage together, and keep production
API writer replicas at one for the current supported profile. PostgreSQL is
digest-pinned; the local MinIO fixtures use the pinned source/base-image build
above. The rehearsal does not pull floating `latest` dependencies.

The default `external` signing profile also requires an operator-provided HTTPS
signing gateway and its trusted Ed25519 public key. This Compose file does not
start a signer. Replace the endpoint and key placeholders below with real
values for your controlled rehearsal; the API rejects missing or invalid
settings before opening storage. See
[signing executors](../reference/configuration.md#signing-executors) for the
gateway request, readiness and trust contract. HTTP loopback signing overrides
remain forbidden in production mode.

```sh
export POSTGRES_PASSWORD='replace-with-long-random-password'
export MINIO_ROOT_PASSWORD='replace-with-long-random-password'
export EVYDENCE_API_KEY_PEPPER='replace-with-long-random-pepper'
export EVYDENCE_SIGNING_EXECUTOR_URL='https://signer.example.com/sign'
export EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64='<trusted-Ed25519-public-key-in-base64>'
# Set this too when your gateway requires a bearer credential:
export EVYDENCE_SIGNING_EXECUTOR_TOKEN='<gateway-credential>'
docker compose -f compose.production-like.yml up --build
```

Gateway settings and the API pepper are passed only to the API. The worker
receives its database and object-store credentials. An optional
`EVYDENCE_SIGNING_EXECUTOR_READINESS_URL` must use the signing endpoint's origin;
the timeout defaults to the runtime schema's value. Native KMS profiles need a
deployment override supplying their provider-specific configuration and
credentials; selecting a signing mode alone does not supply them. The migration
command also runs with `ENV=production`, so its applicable production checks
remain enabled before migration work starts.

API and worker containers receive `SIGTERM` on a Compose stop. The committed
365-second stop grace covers every supported drain budget (up to 300 seconds),
cleanup budget (up to 60 seconds), and a five-second margin. Normal stops finish
as soon as the process exits; Compose does not wait out unused grace. Configure
`EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS`,
`EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS`, and
`EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS` using
[Configuration](../reference/configuration.md). An explicit `docker compose stop
--timeout` overrides the file's grace; allow the configured drain plus cleanup
and margin. PostgreSQL and object storage must stay available while daemons drain.

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
