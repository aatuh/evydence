## Executive summary
Evydence is a functional Go API codebase with clear intent around hexagonal boundaries: domain types live under `internal/domain`, application behavior is mostly concentrated in `internal/app`, and HTTP, PostgreSQL, filesystem, S3, and command entrypoints sit in adapter or `cmd` packages. The project-owned gates I ran are green, including tests, OpenAPI route checks, docs checks, lint, gosec, govulncheck, coverage, and `make finalize`.

The strongest aspects are the consistent tenant-scoped application methods, structured JSON decoding with unknown-field rejection, central Problem Details mapping, scoped API keys, hashed one-time secrets, object-store digest checks, audit-chain append behavior, and documentation that avoids overclaiming legal compliance or secure-release guarantees.

The biggest risk is that the durable runtime is still snapshot-centered. `internal/app.Store` persists a whole `PersistedState` object, and the PostgreSQL adapter stores that JSON blob in `ledger_state`; many relational migration tables exist but are not the runtime source of truth. This limits transactionality, row-level concurrency, queryability, operational debugging, and migration confidence as data volume grows.

The second major risk is breadth. A single `Ledger` struct holds dozens of maps and a single mutex, and `internal/adapters/httpapi/router.go` registers and implements a very large API surface in one file. This has allowed fast feature growth, but it now raises the cost of safe change, targeted testing, and production-grade behavior per feature.

Security is directionally good, but enterprise RBAC currently grants tenant-wide scopes from role names while ignoring the stored `ResourceType` and `ResourceID` fields on role bindings. That is acceptable only if all role bindings are intentionally tenant-wide; the model implies narrower access, so the enforcement gap should be closed before customer-facing or enterprise use.

## Scorecard
| Dimension                              | Score | Notes |
|----------------------------------------|------:|-------|
| Architecture & boundaries              |  7/10 | Good package separation and inward adapter dependencies, but `Ledger` is a large god object and PostgreSQL runtime persists one snapshot rather than per-resource repositories. Evidence: `internal/app/ledger.go:71`, `internal/app/ports.go:10`, `internal/adapters/postgres/store.go:48`. |
| SOLID / cohesion / coupling            |  6/10 | Many cohesive domain methods exist, but `Ledger` owns nearly every resource map and `router.go` owns route registration plus handler implementations for the full API. Evidence: `internal/app/ledger.go:80`, `internal/adapters/httpapi/router.go:58`. |
| Correctness & robustness               |  7/10 | Tests pass and core validation/idempotency patterns are present, but the worker marks known job kinds successful without doing parse/sign/verify side effects. Evidence: `cmd/evydence-worker/main.go:73`. |
| Security                               |  7/10 | Strong basics: scoped API keys, HMAC-hashed secrets, strict JSON decoding, safe errors, and production config guards. RBAC resource scope is not enforced when deriving user scopes. Evidence: `internal/app/ledger.go:310`, `internal/adapters/httpapi/router.go:2423`, `cmd/evydence-api/main.go:32`, `internal/app/enterprise.go:662`. |
| Test effectiveness                     |  7/10 | Unit/API coverage is meaningful and total statement coverage is 60.2%, but command entrypoints, PostgreSQL adapter logic without live DB, and several read/verify handlers have 0% coverage in `make coverage`. |
| Change safety & backward compatibility |  7/10 | OpenAPI generation and route validation exist, migrations are append-only, and docs checks avoid prohibited claims. The generated OpenAPI operations are still generic and mostly schema-light. Evidence: `internal/adapters/httpapi/router.go:2502`. |
| Operability & observability            |  7/10 | Health, readiness, metrics, worker polling, migrations, Helm, and operations docs exist. Worker behavior and snapshot persistence limit production diagnosis and recovery. Evidence: `cmd/evydence-worker/main.go:42`, `internal/adapters/postgres/store.go:64`. |
| Clarity & developer experience         |  7/10 | README/docs/Makefile are discoverable and project-owned commands are clear. Large central files and broad app state reduce local reasoning for new contributors. Evidence: `Makefile:1`, `internal/app/ports.go:24`. |
| Extensibility                          |  7/10 | Ports and adapters make new transports/storage possible, and the domain vocabulary is rich. The current store interface and monolithic ledger make feature extension cheap initially but expensive to harden. Evidence: `internal/app/ports.go:10`, `internal/app/ledger.go:71`. |
| Overall                                |  7/10 | Good MVP-quality foundation with clean gates, but not yet an 8+ production-quality codebase because persistence, RBAC scope enforcement, worker semantics, contract precision, and critical-path coverage need hardening. |

Confidence: medium

## Findings by severity
### Critical
- None found in this pass. The project-owned checks passed, and I did not identify an immediate unauthenticated raw evidence disclosure, obvious secret logging path, SQL injection path, or compile/test failure.

### High
- PostgreSQL is not the true per-resource source of truth yet. The application store contract is `LoadState`/`SaveState` over one `PersistedState` value (`internal/app/ports.go:10`), and the PostgreSQL adapter loads/saves that state as JSON in `ledger_state` (`internal/adapters/postgres/store.go:48`, `internal/adapters/postgres/store.go:64`). Many relational tables exist in migrations, for example `evidence_items` (`migrations/20260527000100_initial_ledger.up.sql:62`) and later increment tables, but runtime writes primarily synchronize a snapshot and a resource projection. This creates risks around large-state writes, concurrent process behavior, row-level constraints, partial failure recovery, and operational queryability.
- The worker currently treats core async jobs as no-ops. `processJob` returns `nil` for `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract`, `parse_vex`, `sign_bundle`, `verify_subject`, and `verify_attestation` (`cmd/evydence-worker/main.go:73`). If callers or operators expect the outbox to perform durable parsing, signing, or verification side effects, jobs can be marked succeeded without doing the work.
- RBAC role bindings store resource scope but scope derivation ignores it. `RoleBinding` creation accepts `ResourceType` and `ResourceID`, but `scopesForUserLocked` derives a flat tenant-wide scope set only from `binding.Role` (`internal/app/enterprise.go:662`). A user intended to have a scoped `customer_verifier` or release role can receive tenant-wide scopes such as `package:read`, `bundle:read`, `verify:read`, and `report:read` (`internal/app/enterprise.go:699`). This is a tenant-internal authorization overreach risk.

### Medium
- The application layer is becoming a god object. `Ledger` owns a single mutex and dozens of maps for unrelated resource families (`internal/app/ledger.go:71`). This makes isolated reasoning and transaction design harder, especially as enterprise identity, evidence lifecycle, reporting, deployment, incident, and package workflows grow.
- HTTP routing and handlers are too centralized. `registerRoutes` builds the full API route table in one function (`internal/adapters/httpapi/router.go:58`), while the same file implements handlers and shared helpers. This raises merge risk and makes package-level ownership unclear as new increments add endpoints.
- OpenAPI contract checking is route-centric, not schema-precise. The `op` helper gives all operations the same generic status set and adds idempotency extensions to every `POST` (`internal/adapters/httpapi/router.go:2502`). This prevents the contract from fully documenting request bodies, response schemas, endpoint-specific errors, pagination fields, or unauthenticated token endpoints.
- Test coverage is uneven on production entrypoints and adapters. `make coverage` reported total coverage of 60.2%, with 0.0% for `cmd/evydence-api`, `cmd/evydence-worker`, `cmd/evydence-migrate`, `cmd/openapi`, `internal/adapters/postgres`, and several important HTTP/app read or verify functions. This is a test confidence gap, even though current unit/API tests are useful.
- `make finalize` is weaker than the full security gate set. It runs formatting, tests, OpenAPI, docs, deploy, and SDK checks (`Makefile:82`), but not `make lint`, `make gosec`, `make vuln`, `make test-race`, `make live-postgres-check`, or `make postgres-integration-test`. I ran lint/gosec/vuln separately for this audit.
- Customer portal token access has no visible rate-limit or failed-attempt audit. The unauthenticated endpoint is intentional, and the token is high-entropy and hashed (`internal/app/enterprise.go:452`), but there is no obvious throttle or failed token access record in the inspected code.

### Low
- `ScopeCustomerPortal` is declared but not visibly used in the current authorization flow (`internal/app/ledger.go:60`). This may be a placeholder, but unused scopes create ambiguity in API docs and future reviews.
- Some docs accurately state roadmap limitations, but README’s supported-feature list is very broad and can make it harder for users to distinguish durable, synchronous, structurally validated, cryptographically verified, and roadmap-hardening behavior. Evidence: `README.md:14`.
- `ProblemDetails` responses include stable codes and safe details, but no request ID is visible in the shared `writeProblem` helper (`internal/adapters/httpapi/router.go:2454`). The original design calls for stable request IDs.

## Hexagonal architecture verdict
The codebase is partially hexagonal. Clean parts: domain structs are framework-free in `internal/domain`, most business operations are in `internal/app`, HTTP depends on app/domain rather than the reverse, and concrete storage adapters live under `internal/adapters`.

The main leaks are not framework leaks; they are boundary compression. The application layer combines state storage, authorization, validation, report generation, signing, outbox enqueueing, and resource orchestration in one `Ledger` object. The persistence port is a whole-ledger snapshot port, so the application cannot express repository-level transactions or query contracts cleanly.

The current shape is good for an MVP and rapid increments, but it is not yet production-grade hexagonal architecture for a high-trust ledger. The next architecture step should be splitting store contracts by aggregate/use case and moving PostgreSQL to real repositories while keeping application services independent of pgx.

## Test verdict
Covered well: API route registration/OpenAPI rendering, many application workflows, idempotency replay/conflict, strict JSON decoding behavior through handlers, evidence/package/control/risk workflows, object-store basics, and several security-sensitive token/hash paths.

Weak: command entrypoints, live PostgreSQL behavior when `EVYDENCE_TEST_DATABASE_URL` is absent, worker job side effects, schema migration behavior against real data, resource-scoped RBAC, customer portal abuse/failure paths, detailed OpenAPI schema drift, and several read/verify endpoints with 0% coverage.

The tests are confidence-building for MVP behavior, not superficial. They are not yet enough for an 8+ production-quality high-trust ledger because some critical operational and authorization paths are either untested or implemented as structural placeholders.

## Best next fixes
1. Replace snapshot-backed production persistence with relational repositories for identity, API keys, idempotency, evidence, audit chain, bundles, reports, and outbox transactions.
2. Enforce resource-scoped RBAC/ABAC from `RoleBinding.ResourceType` and `RoleBinding.ResourceID`, with cross-tenant and scoped-access regression tests.
3. Make outbox worker jobs perform real idempotent parse/sign/verify/report work or stop marking no-op jobs as succeeded.
4. Split the monolithic HTTP router into resource route groups while preserving route-contract generation.
5. Upgrade OpenAPI generation to include endpoint-specific request/response schemas, auth/idempotency requirements, pagination, and error models.
6. Raise critical-path test coverage for command entrypoints, PostgreSQL adapter behavior, worker semantics, read/verify endpoints, and enterprise access flows.
7. Strengthen `make finalize` or add a release gate that includes lint, gosec, govulncheck, race tests, and live integration checks when configured.

## Optional follow-up
- Targeted remediation plan for reaching an 8+ mean score.
- Package-by-package review of `internal/app`.
- Security-focused pass on RBAC, customer portal access, SSO sessions, and package exports.
- Test-gap plan focused on worker, PostgreSQL, and API contract precision.

## Commands/checks run
- `pwd && rg --files -g '!vendor' -g '!bin' | sort | sed -n '1,220p'`: passed; confirmed current repo structure includes Go module, `cmd/`, `internal/`, migrations, docs, deployment assets, SDK examples, and OpenAPI.
- `git status --short && git log --oneline -5`: passed; worktree was clean before audit file creation, latest commit was `082cf38 feat(api): add enterprise identity and portal increments`.
- `make help`: passed; listed project-owned targets.
- `make test`: passed for all packages.
- `make openapi-check`: passed.
- `make docs-check`: passed.
- `make lint`: passed, `0 issues.`
- `make gosec`: passed, `Issues: 0`.
- `make vuln`: passed, no called vulnerable code; reported vulnerabilities in imported/required packages that current code does not appear to call.
- `make coverage`: passed, total statement coverage `60.2%`.
- `make finalize`: passed.

