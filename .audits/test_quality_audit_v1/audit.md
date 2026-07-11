## Executive summary

Evydence has a broad and useful Go test suite across the application service, HTTP adapter, CLI, worker, object stores, and Postgres integration path. The strongest tests exercise tenant isolation, idempotency, release readiness, evidence immutability, VEX decisions, controls, collector/build attestations, customer package boundaries, and OpenAPI route registration.

The largest current risk is coverage integrity. `go test ./... -coverprofile=/tmp/evydence-cover.out` reports `61.0%` total statement coverage, below the required `80%`. Several security-sensitive and contract-sensitive paths remain unexecuted in the default coverage command: future-extension HTTP handlers, read/list endpoints, key rotation/revocation handlers, app getters/list methods, command helpers, the Go SDK, and skipped Postgres integration code when `EVYDENCE_TEST_DATABASE_URL` is not set.

Assertion quality is generally good where tests exist: many tests check response status, replay behavior, safe errors, tenant denial, and report contents. The weak spots are route coverage gaps and coverage that depends on optional environment configuration rather than the default project-owned command.

Confidence: medium. The repository has meaningful tests for critical workflows, but the 80% coverage requirement and missing route/helper coverage mean the current suite is not yet strong enough for the requested bar.

## Test inventory

| Area | Test types | Status | Notes |
|------|------------|--------|-------|
| `internal/app` | Unit/behavior tests | Partial | Strong workflow coverage, but multiple read/list/getter, lifecycle, and error-helper paths are still uncovered. |
| `internal/adapters/httpapi` | HTTP/contract tests | Partial | OpenAPI route contract tests and several end-to-end API flows exist; newer future-extension handlers and many read/action routes are uncovered. |
| `internal/adapters/postgres` | Live integration tests | Partial | Meaningful Postgres test exists, but it skips without `EVYDENCE_TEST_DATABASE_URL`, causing default coverage to show 0%. |
| Object stores | Unit tests | Partial | Filesystem coverage is reasonable; S3 adapter coverage mostly validates constructor behavior and does not cover live Put/Get. |
| `cmd/evydence` | CLI unit tests | Partial | Several CLI commands are covered; usage, manifest verification, keygen, and safe API error helper gaps remain. |
| API/worker entrypoints | Unit tests | Weak | Production config and worker job processing have some coverage; run loops and env helpers are thinly tested. |
| SDK | Unit tests | Missing | Go SDK `Post` has no test despite being a public integration surface. |
| CI/reporting | Makefile gates | Partial | Makefile includes tests, OpenAPI, docs, deploy, lint, gosec, vuln, race, and coverage. No `.github` CI workflow exists in the checkout. |

## Scorecard

| Dimension                             | Score | Notes |
|---------------------------------------|------:|-------|
| Critical behavior coverage            |  7/10 | Core release/evidence/security workflows are covered, but newer future-extension routes and read/list surfaces are gaps. |
| Coverage integrity                    |  5/10 | Default total coverage is 61.0%, below the required 80%; optional Postgres tests skip in default coverage. |
| Assertion quality                     |  7/10 | Existing tests usually assert results, statuses, errors, and tenant isolation; some gaps are simply untested. |
| Negative path & edge case testing     |  6/10 | Good malformed JSON/idempotency/tenant examples, but many route/helper negative paths remain uncovered. |
| Test architecture & maintainability   |  7/10 | Helpers make HTTP/app tests readable; route tests are large and should keep adding focused helpers. |
| Isolation, determinism & flakiness    |  7/10 | Fixed clocks and local fakes are common; live Postgres remains environment-dependent and must be run deliberately. |
| Mocking, fakes & contract safety      |  7/10 | In-process HTTP and memory/object fakes are useful; SDK and S3 contract safety are thin. |
| Feedback speed & developer workflow   |  8/10 | `make test`, `make openapi-check`, `make finalize`, and focused `go test` are fast. |
| CI enforcement & reporting            |  4/10 | Project-owned gates exist, but no checked-in `.github` CI workflow enforces them. |
| Regression protection & change safety |  7/10 | Good protection for many implemented increments; missing route and SDK coverage leaves routine-change risk. |

Mean score formula, excluding Overall: `(7 + 5 + 7 + 6 + 7 + 7 + 7 + 8 + 4 + 7) / 10 = 6.5`.

Overall score: 6.5/10.
