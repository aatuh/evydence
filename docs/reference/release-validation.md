# Release Validation

This reference describes the project-owned release validation profile. It is evidence for engineering review only; it does not prove legal compliance, certification, complete vulnerability detection, or secure releases.

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
PostgreSQL schema for a black-box demo/restart persistence check, and runs a
release artifact signing smoke test. See [Production readiness](production-readiness.md)
for the supported profiles and exit criteria.

`make coverage-check` is intentionally part of the production profile and fails
early when `EVYDENCE_TEST_DATABASE_URL` is unset. Use `make coverage` for a
local no-database coverage report that is not release-candidate evidence.

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
release SBOM metadata, release provenance metadata, `coverage.out`,
`release-check-summary.txt`, checked release notes, signed release manifest,
and manifest signature. It refuses dirty worktrees, invalid release-candidate
tags, missing live PostgreSQL configuration, missing signing material, and
existing local tags unless a CI tag build explicitly sets
`EVYDENCE_RELEASE_ALLOW_EXISTING_TAG=1`.

## Configured Live PostgreSQL Profile

For the scripted local profile, run:

```sh
make release-check-local-postgres
```

The target starts the Compose PostgreSQL service, waits for readiness, loads `.test.env` when present or `.test.env.example` otherwise, runs `make release-check`, and preserves `tmp/release-check-summary.txt`.

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
compatibility tests, and a release manifest signing smoke test.

The workflow preserves `tmp/release-check-summary.txt`, `coverage.out`, and the
production-check release manifest/signature smoke artifacts as build artifacts.
The database must not contain production evidence, customer package tokens,
signing-key material, or other real secrets.

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
