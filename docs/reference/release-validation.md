# Release Validation

This reference describes the project-owned release validation profile. It is evidence for engineering review only; it does not prove legal compliance, certification, complete vulnerability detection, or secure releases.

## Default Local Profile

Run the default release gate from the repository root:

```sh
make release-check
```

The target runs formatting, unit tests, OpenAPI drift checks, docs/deployment/SDK checks, linting, gosec, govulncheck, race tests, and the live PostgreSQL targets. When `EVYDENCE_TEST_DATABASE_URL` is unset, live PostgreSQL checks are explicitly skipped and the summary records that limitation.

The target writes:

```text
tmp/release-check-summary.txt
```

Keep this file with release evidence when preparing an internal release review. It records the pass/skip status for the gate families, including whether live PostgreSQL checks ran.

## Configured Live PostgreSQL Profile

Start the local dependencies and load the test profile:

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

CI should provide a disposable PostgreSQL service, set `EVYDENCE_TEST_DATABASE_URL`, run `make release-check`, and preserve `tmp/release-check-summary.txt` as a build artifact. The database should not contain production evidence, customer package tokens, signing-key material, or other real secrets.
