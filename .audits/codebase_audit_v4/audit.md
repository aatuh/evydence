## Executive summary
Evydence improved again after remediation commit `9d85ec0`. The exact instance-admin boundary is now implemented and tested, tenant admins cannot mint `instance:admin` API keys without already holding that explicit scope, API key/SSO/customer-portal bearer hash checks use constant-time HMAC comparison, repeated matching customer portal token failures revoke the access record, and docs now describe SSO as admin-managed records rather than live OIDC/SAML login.

The codebase is a credible high-trust API product foundation. Its strongest areas are ports-and-adapters direction, deterministic application services, strict JSON decoding, tenant-scoped checks, append-only audit-chain behavior, hashed secrets, request-ID Problem Details, generated route contracts, broad Makefile gates, and documentation that avoids legal compliance, certification, complete-SBOM, scanner-authority, or secure-release claims.

The mean score remains below 8. The limiting issues are structural rather than isolated defects: PostgreSQL persistence is still centered on a whole-ledger snapshot, `Ledger` remains a very broad aggregate with one mutex and many resource maps, the worker validates expected durable parser state instead of re-reading object storage and parsing payloads, the HTTP/OpenAPI contract is still schema-light for a large public API, and live PostgreSQL release evidence is skipped unless `EVYDENCE_TEST_DATABASE_URL` is configured.

The specific remediation items requested for re-evaluation are improved. `require` now treats `instance:admin` as an explicit scope in `internal/app/ledger.go:1660`, `CreateAPIKey` calls `requireGrantableScopes` in `internal/app/ledger.go:366`, `secretHashEqual` uses `hmac.Equal` in `internal/app/ledger.go:1476`, portal failed attempts revoke at the configured limit in `internal/app/enterprise.go:455`, SSO limitations are documented in `docs/api.md:26` and `docs/operations.md:104`, and `docs/reference/release-validation.md:23` documents the live Postgres release profile.

All project-owned checks run during this audit passed. `make release-check` passed and wrote `tmp/release-check-summary.txt`; the summary explicitly records live Postgres checks as skipped because `EVYDENCE_TEST_DATABASE_URL` is unset. `make coverage` passed and reported total statement coverage of `60.1%`.

## Scorecard
| Dimension                              | Score | Notes |
|----------------------------------------|------:|-------|
| Architecture & boundaries              |  7.6/10 | `internal/domain` is framework-free, `internal/app` owns use cases, and adapters depend inward. The main gap is still whole-state persistence through `internal/app/ports.go:10` and `internal/adapters/postgres/store.go:48`, plus the broad `Ledger` aggregate in `internal/app/ledger.go:64`. |
| SOLID / cohesion / coupling            |  7.2/10 | Handler decomposition improved with `identity_handlers.go`, `portal_handlers.go`, `ops_handlers.go`, and `system_handlers.go`, but `internal/adapters/httpapi/router.go` still owns route registration plus many handlers/helpers, and `internal/app/enterprise.go` remains a large multi-concern application file. |
| Correctness & robustness               |  8.0/10 | `make release-check` passed, strict JSON decoding exists in `internal/adapters/httpapi/router.go:2136`, idempotency is centralized in `internal/app/ledger.go:1428`, exact instance-admin semantics are tested in `internal/app/enterprise_test.go:81`, and worker jobs fail closed. Parser jobs still do not perform true async parse side effects. |
| Security                               |  8.1/10 | The requested hardening landed: exact `instance:admin`, API key minting restrictions, constant-time HMAC hash comparisons, portal revocation-on-abuse, and safer docs. Remaining risks are deferred live OIDC/SAML verification, no built-in portal rate limiter, snapshot storage for secrets, and optional live Postgres gates. |
| Test effectiveness                     |  7.6/10 | Tests cover core flows, route contracts, request IDs, idempotency, tenant isolation, resource-scoped human sessions, instance-admin denial, portal revocation, and worker fail-closed behavior. Coverage is `60.1%`, with weak live Postgres, command entrypoint, read/verify handler, and helper branch coverage. |
| Change safety & backward compatibility |  8.1/10 | `make finalize`, `make release-check`, OpenAPI drift checks, docs checks, migrations, and recent Conventional Commits provide strong change discipline. The OpenAPI contract is generated consistently but remains too generic for an 8.5+ public API compatibility score. |
| Operability & observability            |  7.9/10 | Health, readiness, metrics, worker logs, migrations, backup manifests, release-check summary, and release validation docs exist. Operability is constrained by snapshot-centered persistence, skipped live Postgres evidence, limited structured telemetry, and worker parser validation-only behavior. |
| Clarity & developer experience         |  7.9/10 | Docs are organized into tutorial/how-to/reference/explanation, Make targets are discoverable, and product limitations are clear. Large central files and generic OpenAPI schemas still raise onboarding and review cost. |
| Extensibility                          |  7.5/10 | Adding new evidence types is straightforward, and adapters are present. Extensibility is limited by whole-state persistence, concentrated authorization/resource-reference helpers, and a central route-registration table that grows with every feature. |
| Overall                                |  7.77/10 | The security and change-safety profile now crosses 8 in important areas, but the mean remains below 8 until relational persistence, async parser side effects, OpenAPI precision, and durable integration evidence improve. |

Confidence: medium-high

## Findings by severity
### Critical
- None found in this pass. The current checkout builds and passes the strongest declared local release gate. I did not identify an immediate unauthenticated raw evidence disclosure, SQL injection path, command execution path, bearer-token logging path, or failing project-owned gate.

### High
- PostgreSQL is still not the per-resource source of truth. The `Store` port exposes whole-state `LoadState`/`SaveState` in `internal/app/ports.go:10`, and the Postgres adapter stores a JSON ledger snapshot in `ledger_state` in `internal/adapters/postgres/store.go:48` and `internal/adapters/postgres/store.go:64`. `syncResourceIndex` deletes and rebuilds projections on each save in `internal/adapters/postgres/store.go:101`. This limits database-enforced invariants, row-level locking for business resources, incremental writes, large-state performance, restore diagnostics, and concurrent writer confidence.
- `Ledger` remains a high-risk central aggregate. The struct in `internal/app/ledger.go:64` owns tenant, identity, collector, evidence, build, deployment, incident, control, report, signing, package, storage, outbox, and integrity state behind one mutex. This is understandable for the staged MVP, but it makes aggregate ownership, transaction scope, concurrency behavior, and focused review increasingly difficult.

### Medium
- Parser worker jobs validate durable state but do not re-read object storage and parse raw payloads. `processJob` in `cmd/evydence-worker/main.go:78` checks snapshot records for `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract`, and `parse_vex`, and compares optional hashes in `requirePayloadHash` at `cmd/evydence-worker/main.go:153`. This fails safely, but it is still short of the design goal for async parsing/signing/report generation from object storage.
- HTTP/OpenAPI precision is still too generic for the breadth of the API. The route table in `internal/adapters/httpapi/router.go:61` covers many resource families, while the common operation registration in `internal/adapters/httpapi/router.go:2257` applies broad shared responses and idempotency metadata. `make openapi-check` proves generated-contract consistency, but the contract does not yet describe endpoint-specific request bodies, response schemas, query parameters, pagination, unauthenticated portal token semantics, or precise status codes.
- Live durable-store validation remains opt-in. `make release-check` calls `live-postgres-check` and `postgres-integration-test` in `Makefile:95`, but those targets skip when `EVYDENCE_TEST_DATABASE_URL` is unset in `Makefile:131` and `Makefile:134`. The docs now explain the configured profile in `docs/reference/release-validation.md:23`, but this audit run did not exercise live Postgres.
- Customer portal abuse controls are improved but still incomplete. `AccessCustomerPortalPackage` records safe failed attempts and revokes after repeated matching-prefix failures in `internal/app/enterprise.go:455`, and tests assert no token leakage in `internal/app/enterprise_test.go:254`. There is still no application-level IP/account throttling or deployment-enforced rate-limit contract for the unauthenticated endpoint; docs recommend reverse-proxy or API-gateway throttling in `docs/operations.md:102`.
- Current SSO support is still a records/session model, not live provider login. `CreateSSOProvider`, `LinkSSOIdentity`, and `CreateSSOSession` live in `internal/app/enterprise.go:230`, `internal/app/enterprise.go:252`, and `internal/app/enterprise.go:283`. Docs correctly state that live OIDC discovery, JWKS validation, SAML assertion verification, browser redirects, and provider callbacks are not implemented in `docs/api.md:26`.

### Low
- Important authorization helper branches remain lightly covered despite broad characterization tests. Coverage output shows zero or low coverage for helper paths such as `projectCoversRefsLocked`, `releaseCoversRefsLocked`, `artifactCoversProductLocked`, and `artifactCoversReleaseLocked` in `internal/app/enterprise.go`, even though these helpers sit behind resource-scoped human authorization.
- Some HTTP read/verify handlers have 0% function coverage in the coverage report, including several straightforward GET/verify wrappers. This is not a current failure because application tests cover much of the behavior, but it weakens API-adapter regression confidence.
- `ScopeCustomerPortal` is declared in `internal/app/ledger.go:60` while current customer portal package access is token-based and intentionally unauthenticated. It is harmless, but it should either be documented as reserved or removed to avoid review confusion.

## Hexagonal architecture verdict
Clean parts: domain structs remain free of HTTP, SQL, object-store, queue, provider, and UI dependencies. Application behavior lives in `internal/app`; HTTP, PostgreSQL, object storage, S3, migration, CLI, API, worker, and OpenAPI generation live in adapters or commands. This is directionally consistent with the intended ports-and-adapters architecture.

Boundary leaks are concentrated in the application layer rather than outward imports. `Ledger` is simultaneously aggregate store, use-case service, authorization engine, idempotency ledger, audit-chain writer, signing orchestrator, report generator, object-store coordinator, outbox producer, and persistence coordinator. That keeps dependencies inward, but it is not yet clean aggregate separation.

The persistence boundary remains the least hexagonal part. A store port exists, but it is a whole-ledger snapshot contract, not aggregate-specific repository ports. PostgreSQL provides durable JSON state, persisted outbox jobs, and resource projections; it is not yet the relational source of truth for core business resources.

Verdict: partially hexagonal and improving. It is a good staged architecture for a fast-moving MVP, but production-grade high-trust operation still depends on splitting persistence and aggregate boundaries.

## Test verdict
Covered well: route registration, OpenAPI drift, strict JSON unknown-field rejection, request ID Problem Details, idempotency replay/conflict, tenant isolation, resource-scoped human session authorization, exact instance-admin denial, API key minting restrictions, constant-time hash helper behavior, portal failure/revocation/audit/metrics, worker fail-closed behavior, release readiness, VEX/decision/exception flows, build/attestation readiness, control coverage, customer packages, and production bootstrap secret rejection.

Weak areas: live PostgreSQL execution without an explicitly configured database, true relational constraints and row-level transaction behavior, worker parsing from object storage, endpoint-specific HTTP schema precision, command entrypoints, read/verify handler wrappers, and deeper branch coverage for resource-reference authorization helpers.

The tests are confidence-building for the current MVP and recent remediations. They are still short of an 8+ codebase-wide bar because the highest-risk durability and async boundaries are represented by tests/documentation more than by complete production behavior.

## Best next fixes
1. Start the relational store split for API keys, SSO sessions, idempotency records, evidence, audit-chain entries, release bundles, and outbox jobs.
2. Implement parser worker jobs that read raw tenant-prefixed objects, verify digests, parse payloads, and preserve idempotent side effects.
3. Improve OpenAPI precision with endpoint-specific request/response schemas, query parameters, error codes, pagination, auth, and idempotency rules.
4. Continue HTTP adapter decomposition by moving route registration and handlers into resource-family files.
5. Add a CI/live Postgres release profile that sets `EVYDENCE_TEST_DATABASE_URL` and preserves `tmp/release-check-summary.txt`.
6. Add portal abuse throttling/rate-limit integration tests or a documented reverse-proxy enforcement check.
7. Increase branch and adapter coverage for resource-scoped authorization helpers and read/verify HTTP handlers.

## Optional follow-up
- Run remediation iteration 4 from the accompanying backlog.
- Perform a focused persistence design review before implementing relational repositories.
- Perform a focused OpenAPI contract pass on the highest-value endpoints first.
- Build a live-Postgres CI profile that turns the current skipped release-check lines into passed evidence.

## Commands/checks run
- `sed -n '1,240p' /home/aatu/.codex/skills/code-review-audit/SKILL.md`: passed; loaded audit workflow.
- `sed -n '1,260p' /home/aatu/.codex/skills/software-backlog-architect-delivery-agent/SKILL.md`: passed; loaded backlog format.
- `pwd && git status --short && git log --oneline -8`: passed; confirmed repo root `/home/aatu/projects/evydence`, clean status before audit artifacts, and current commit `9d85ec0`.
- `find . -maxdepth 2 -type f | sort | sed 's#^./##' | head -200`: passed; confirmed Go module, commands, internal packages, docs, migrations, OpenAPI, deployment, SDK, and audit evidence exist.
- `find cmd internal docs migrations -maxdepth 3 -type f | sort`: passed; inspected current package/docs/migration layout.
- `rg -n "ScopeInstanceAdmin|hasExactScope|CreateAPIKey|subtle\\.ConstantTimeCompare|constant-time|failed|revoke|CustomerPortal|SSO|EVYDENCE_TEST_DATABASE_URL|release-check|recognized|outbox|fail" internal cmd docs Makefile README.md`: passed; collected requested remediation evidence.
- `rg -n "type Store|PersistedState|snapshot|resource_index|TODO|panic\\(|log\\.Printf|fmt\\.Printf|http\\.Handle|NewServer|registerRoutes|Problem|request_id|X-Request-ID" internal cmd Makefile docs`: passed; collected architecture, persistence, operation, and error-handling evidence.
- `make help`: passed; confirmed project-owned gates.
- Targeted `nl`/`sed` inspections: passed; inspected `internal/app/ledger.go`, `internal/app/enterprise.go`, `internal/adapters/httpapi/router.go`, `internal/adapters/postgres/store.go`, `cmd/evydence-worker/main.go`, tests, docs, and Makefile.
- `make release-check`: passed. It ran `make finalize`, lint, gosec, govulncheck, race tests, `live-postgres-check`, and `postgres-integration-test`; live Postgres checks skipped because `EVYDENCE_TEST_DATABASE_URL` is unset.
- `make coverage`: passed. Total statement coverage was `60.1%`.
- `git diff --check`: passed.
- `git status --short`: passed before audit artifact creation; clean except for the audit files created by this task afterward.
