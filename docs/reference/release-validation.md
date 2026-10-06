# Release Validation

This reference describes the project-owned release validation profile. It is evidence for engineering review only; it does not prove legal compliance, certification, complete vulnerability detection, or secure releases.

## Live test package watchdogs

Complete Go test, race, coverage and PostgreSQL integration gates use a
thirty-minute per-package watchdog. Live schema/recovery suites can exceed Go's
default ten minutes in aggregate even when each test completes within its own
deadline. This changes no test selection, assertions, fixture deadlines or
coverage floors; a timed-out run remains a failed gate. Regression checks in
`scripts/test_gate_watchdogs.py` preserve those complete command surfaces.

`make production-check` appends `-p=1` to `GOFLAGS` before its nested gates.
Independent Go package test binaries therefore run sequentially against the
shared live database, avoiding competing schema/recovery fixture work. Other
Go flags are retained; a prior `-p` value is overridden. This does not limit
concurrency within a test, change `GOMAXPROCS` or the test `-parallel` setting, disable race instrumentation, or
extend fixture deadlines. Ordinary local checks outside the production gate
retain their existing package scheduling.

Native recovery tests require compatible `pg_dump` and `pg_restore` tools on
`PATH`. Use the test server's major version for same-version restore rehearsals;
a newer dump tool can emit settings an older target rejects, even when it dumps
that older server. See [PostgreSQL's dump compatibility notes](https://www.postgresql.org/docs/16/app-pgdump.html#APP-PGDUMP-NOTES).
Never suppress restore errors or edit the dump to make a recovery test pass.

## Default Local Profile

Run the default release gate from the repository root:

```sh
make release-check
```

The target runs formatting, unit tests, OpenAPI drift checks, docs/deployment/SDK checks, release acceptance, linting, gosec, govulncheck, race tests, and the live PostgreSQL targets. When `EVYDENCE_TEST_DATABASE_URL` is unset, live PostgreSQL checks are explicitly skipped and the summary records that limitation.

For the deterministic metadata-only release evidence gate, run:

```sh
make release-acceptance
```

That target runs the fast local checks, verifies the root license, governance, support, trademark, release-evidence, changelog, and Docker build-context metadata, and rejects prohibited product claims in the documented surfaces.
It also runs `make release-asset-smoke-check`, which creates a synthetic local
release-evidence set, verifies checksum files, verifies a signed release
manifest, runs the customer package verifier against the checked sample package,
and confirms checksum, signature, missing-asset, and package-identity mismatch
failure cases are rejected.

The target writes:

```text
tmp/release-check-summary.txt
```

Keep this file with release evidence when preparing an internal release review. It records the pass/skip status for the gate families, including whether live PostgreSQL checks ran.

## Production Readiness Gate

For self-hosted production-readiness evidence, run:

```sh
make production-check
```

That gate is stricter than `make release-check`: it requires
`EVYDENCE_TEST_DATABASE_URL`, rejects skipped live PostgreSQL checks, enforces
the configured coverage threshold, verifies every committed migration prefix can
upgrade to the current schema in a temporary PostgreSQL schema, runs the checked
release-evidence benchmark, starts an API and worker against a disposable
PostgreSQL schema for a black-box demo/restart persistence check, runs the same
black-box flow against release-style local binaries through
`make black-box-release-artifact-check`, and runs a release artifact signing
smoke test. See [Production readiness](production-readiness.md) for the
supported profiles and exit criteria.

`make coverage-check` is intentionally part of the production profile and fails
early when `EVYDENCE_TEST_DATABASE_URL` is unset. Use `make coverage` for a
local no-database coverage report that is not release-candidate evidence.
Both commands instrument all repository Go packages with `-coverpkg=./...`,
including adapters exercised through wiring tests. The critical-package floor
counts each shared statement block once across test binaries. This changes
measurement, not test selection or either coverage floor; see the
[coverage policy](test-strategy.md#coverage-policy).

## Disposable memory-backed test database

On a Linux Docker engine, a separate tmpfs-backed PostgreSQL instance can reduce
schema-fixture I/O without changing tests. This is a test-only profile, not a
production deployment. Keep the pinned image from `docker-compose.yml`, leave
`fsync`, `synchronous_commit` and `full_page_writes` enabled, and retain the
same package/fixture deadlines, race checks and coverage thresholds.

The example bounds database files to 2 GiB and total container memory to 5 GiB.
Allow enough available memory for PostgreSQL and the test processes. The
container name and loopback port must be unused; do not remove an existing
service to make the example run. Start it from the repository root:

```sh
validation_pg_image=$(docker compose config --format json | jq -r '.services.postgres.image')
docker run -d --name evydence-validation-postgres \
  --memory=5g --memory-swap=5g \
  --tmpfs /var/lib/postgresql/data:rw,size=2g \
  --publish 127.0.0.1:55439:55439 \
  --env POSTGRES_USER=evydence --env POSTGRES_PASSWORD=change-me \
  --env POSTGRES_DB=evydence --env PGPORT=55439 \
  "$validation_pg_image" postgres -p 55439
docker exec evydence-validation-postgres pg_isready -U evydence -d evydence -p 55439
```

Repeat the readiness command until it reports accepting connections, then verify
the durability settings:

```sh
docker exec evydence-validation-postgres psql -U evydence -d evydence -p 55439 -At \
  -c "SELECT name,setting FROM pg_settings WHERE name IN ('fsync','synchronous_commit','full_page_writes') ORDER BY name"
```

All three settings must be `on`. Use the server-major-compatible recovery
clients described above; a
container client wrapper must stream host fixture files rather than pass their
paths into a container that cannot see them. Then select this test URL while
retaining the configured MinIO test service:

```sh
set -a; . ./.test.env.example; set +a
export ENV=''
export EVYDENCE_TEST_DATABASE_URL='postgres://evydence:change-me@127.0.0.1:55439/evydence?sslmode=disable'
make production-check
```

The data mount counts against the container memory ceiling. Leave additional
headroom for backend allocations: oversized-projection rejection fixtures can
temporarily exceed a GiB even though invalid data is never transferred to the
application. Accumulated WAL/data and backend memory together exhausted an
earlier 3 GiB ceiling during coverage. Treat the example as a starting bound,
not a portable resource guarantee; monitor container/host memory and retain the
original adversarial fixtures and deadlines.

The complete gate is still required; an out-of-memory event, full tmpfs or timeout
is a failure, not a reason to omit tests. Record the ephemeral storage choice
with the results. This profile checks logical database behavior, migrations,
application restart persistence and backup/restore; it does not demonstrate
host-reboot, container-stop or power-loss persistence. Container stop discards
its database files. See [Docker tmpfs limits](https://docs.docker.com/engine/storage/tmpfs/)
and [memory/swap limits](https://docs.docker.com/engine/containers/resource_constraints/).
After retaining the gate's host-side evidence, stop/remove only the disposable
container you created; this destroys all its test database data. Never use this
profile or its example credentials for production data.

## Release Candidate Checklist

Before tagging `v0.1.0-rc.1`, `v0.9.0-rc.1`, or another controlled
self-hosted release candidate, follow
[Release candidate checklist](release-candidate.md). The minimum evidence set
is:

- passing `make production-check` with live PostgreSQL;
- `tmp/release-check-summary.txt` from the same run;
- coverage output and threshold result;
- OpenAPI checksum and migration checksums;
- release SBOM metadata and release provenance metadata;
- pre-build release-input manifest used by the API build identity;
- signed release artifact manifest, manifest signature, and artifact checksums;
- release notes that state supported profile, assumptions, limitations,
  upgrade notes, and unresolved hardening work.

Do not use release-candidate evidence as legal compliance proof, certification,
complete vulnerability coverage, complete SBOM proof, secure-release proof, or
auditor/regulator acceptance.

The local packaging gate is:

```sh
set -a; . ./.test.env; set +a
export EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64="$(cat evydence-release-private.key)"
make release-candidate-check TAG=<vX.Y.Z-rc.N>
```

`scripts/release_candidate_package.sh` creates `dist/<tag>/` with the
release archives, `SHA256SUMS`, `openapi.sha256`, `migrations.sha256`,
`release-build-manifest.json`,
release SBOM metadata, release provenance metadata, `coverage.out`,
`release-check-summary.txt`, checked release notes, signed release manifest,
and manifest signature. It refuses dirty worktrees, invalid release-candidate
tags, missing live PostgreSQL configuration, missing signing material, and
existing local tags unless a CI tag build explicitly sets
`EVYDENCE_RELEASE_ALLOW_EXISTING_TAG=1`.

For a lightweight local smoke check that does not require a clean worktree,
live PostgreSQL, release signing credentials, or GitHub Releases, run:

```sh
make release-asset-smoke-check
```

The smoke check writes temporary files under `tmp/release-asset-smoke/`,
removes the temporary private signing key after signing, and leaves
`tmp/release-asset-smoke/summary.txt` with the checked result.

## Configured Live PostgreSQL Profile

For the scripted local profile, run:

```sh
make release-check-local-postgres
```

The target starts the Compose PostgreSQL service, waits for readiness, loads
`.test.env` when present or `.test.env.example` otherwise, runs
`make release-check`, and preserves `tmp/release-check-summary.txt`. For
production-gate failures, use
[Production gate troubleshooting](production-gate-troubleshooting.md) before
changing release status or weakening a gate.

You can also run the sequence manually:

```sh
make compose-up
set -a; . ./.test.env; set +a
make release-check
```

The configured profile requires `EVYDENCE_TEST_DATABASE_URL`. The example `.test.env.example` points at the Docker Compose PostgreSQL service:

```sh
EVYDENCE_TEST_DATABASE_URL=postgres://evydence:change-me@localhost:5432/evydence?sslmode=disable
```

With that variable set, `make release-check` applies migrations through `make live-postgres-check` and runs the Postgres-backed integration target. The summary should contain:

```text
live_postgres=passed
postgres_integration=passed
```

If either line is skipped, the release evidence should state that durable-store validation was not covered in that run.

## CI Usage

The checked-in GitHub Actions workflow provides a disposable PostgreSQL service,
sets `EVYDENCE_TEST_DATABASE_URL`, and runs `make production-check`. That gate
runs the live PostgreSQL release check, coverage threshold enforcement, lint,
gosec, govulncheck, race tests, OpenAPI/docs/deployment/SDK checks, migration
compatibility tests, production benchmark evidence, black-box release-style binary evidence,
and a release manifest signing smoke test.

The workflow preserves `tmp/release-check-summary.txt`, `coverage.out`, and the
production benchmark summary, black-box release-style binary summary,
release-style binary checksums, and production-check release manifest/signature
smoke artifacts as build artifacts. The database must not contain production
evidence, customer package tokens, signing-key material, or other real secrets.

GitHub Actions and service container dependencies are pinned by commit SHA or
image digest in the checked CI workflows. The repository also runs a CodeQL
workflow with the `security-and-quality` query suite so SAST results are
published through GitHub code scanning when that service is available.

## Signed Release Artifact Workflow

The checked-in `.github/workflows/release-artifacts.yml` workflow calls the
same release-candidate package script used locally. The package job has
read-only `GITHUB_TOKEN` permissions and the release signing secret only; the
separate draft-release publication job downloads the packaged evidence artifact
and uses `EVYDENCE_RELEASE_PUBLISH_TOKEN` only when publishing is explicitly
enabled or a release tag is pushed. It packages self-contained release archives
for the CLI, API, worker, and migration commands on Linux, macOS, and Windows
targets. The script runs `make production-check` against disposable PostgreSQL
before building artifacts.

The workflow requires this repository secret:

```text
EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64
```

The value must be the base64 Ed25519 private key generated by:

```sh
./dist/evydence release keygen \
  --private-out evydence-release-private.key \
  --public-out evydence-release-public.key
```

The private key is written only to a temporary file with restrictive
permissions inside the workflow, used to produce
`evydence-release-manifest.sig.json`, copied to the Scorecard-compatible
`evydence-release-manifest.sig` alias, and then removed. The uploaded artifact
set includes binaries, checksums, `openapi.yaml`, `openapi.sha256`, migration
checksums, `coverage.out`, `release-check-summary.txt`, checked release notes,
release SBOM/provenance metadata, the Scorecard-compatible in-toto provenance
statement, the release manifest, and the manifest signature. Tag pushes create
or update a draft GitHub release only when the external
`EVYDENCE_RELEASE_PUBLISH_TOKEN` secret is configured. The publish token should
be a maintainer-controlled fine-grained token or GitHub App token with the
minimum release-publication scope needed for the repository. Maintainers publish
a draft as a prerelease only after the workflow artifact and release assets are
verified. Manual runs can upload only the workflow artifact unless
`upload_draft_release` is enabled.

The container image workflow similarly keeps `GITHUB_TOKEN` from receiving
package-write permissions. GHCR publication requires
`EVYDENCE_GHCR_PUBLISH_TOKEN`; keyless image signing still requires GitHub OIDC
through `id-token: write`, but that permission is scoped to the image-signing
job rather than the build/push job. These secrets are repository settings, not
release evidence artifacts, and must not be logged or committed.

The canonical artifact map is
[Release evidence index](release-evidence-index.md). Keep that page aligned
with the release-candidate package script whenever the artifact set changes.

These artifacts support reproducible engineering review. They are not legal
compliance proof, certification, a secure-release guarantee, complete SBOM
proof, or authoritative vulnerability coverage.

Before promoting the release-candidate line to a stable `v0.1.0` tag, also use
[Stable v0.1.0 exit criteria](stable-v0.1.0-exit-criteria.md). That reference
records the extra release evidence, documentation alignment, and hard blockers
for leaving the candidate line.
