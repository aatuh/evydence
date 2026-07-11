## Executive summary
Evydence improved materially after the iteration 2 remediation commits through `f799e6e`. Resource-scoped authorization now has broader workflow coverage and an inventory test, worker jobs no longer pass as no-op success, selected HTTP handlers moved out of the central router, failed customer portal attempts are counted and audited without storing token values, production refuses bootstrap secret printing, and `make release-check` writes a validation summary.

The codebase is now a solid early-product foundation for a high-trust evidence ledger. The strongest qualities are deterministic application behavior, strict JSON decoding, tenant-scoped application checks, hashed API key/SSO/portal secrets, safe Problem Details with request IDs, append-only audit events, route contract generation, broad Makefile gates, and product language that avoids legal compliance or secure-release claims.

The mean score is still below 8. The largest remaining blockers are not small style issues: runtime PostgreSQL persistence is still snapshot-centered, `Ledger` remains a single large aggregate with a global mutex and many resource maps, `router.go` still owns most HTTP registration and many handlers, OpenAPI operations are schema-light, parser worker jobs validate durable state but do not re-read object storage and parse payloads, and release evidence still skips live PostgreSQL checks when `EVYDENCE_TEST_DATABASE_URL` is unset.

Security is close to the requested bar but has one important access-control concern. `InstanceAdminSnapshot` requires `ScopeInstanceAdmin`, but the shared `require` helper accepts `ScopeAdmin` for any requested scope. That means a tenant-scoped admin API key can satisfy the instance-admin route unless callers avoid issuing `admin` keys. This is lower-risk than raw evidence exposure because the endpoint returns counts only, but it violates the intended multi-tenant admin boundary.

All project-owned checks run during this audit passed. `make release-check` passed with live Postgres gates explicitly skipped because `EVYDENCE_TEST_DATABASE_URL` is unset. `make coverage` passed and reported total statement coverage of `59.9%`, with useful coverage in `internal/app` and `internal/adapters/httpapi` but weak coverage in command entrypoints, live Postgres behavior, and several read/verify/helper paths.

## Scorecard
| Dimension                              | Score | Notes |
|----------------------------------------|------:|-------|
| Architecture & boundaries              |  7.4/10 | Domain/app/adapters remain cleanly separated, and adapters depend inward. The major boundary gap remains snapshot persistence through `internal/app/ports.go:10` and `internal/adapters/postgres/store.go:50`, plus a broad `Ledger` aggregate in `internal/app/ledger.go:64`. |
| SOLID / cohesion / coupling            |  7.0/10 | Handler decomposition started with `identity_handlers.go`, `portal_handlers.go`, `ops_handlers.go`, and `system_handlers.go`, but `internal/adapters/httpapi/router.go` is still 2287 lines and `internal/app/enterprise.go` is 1099 lines. |
| Correctness & robustness               |  7.9/10 | `make release-check` passed, strict JSON parsing exists in `internal/adapters/httpapi/router.go:2136`, idempotency is centralized in `internal/app/ledger.go:1423`, and worker jobs validate durable state in `cmd/evydence-worker/main.go:78`. Parser jobs still do not execute true asynchronous parse side effects. |
| Security                               |  7.8/10 | Resource-scoped human grants are now enforced across many workflows via `authorizeResourceLocked` and inventory tests, secrets are hashed, and production rejects bootstrap secret printing. Remaining risks include `ScopeAdmin` satisfying `ScopeInstanceAdmin`, no app-level portal throttling, string equality for secret hash comparisons, and deferred provider/OIDC verification. |
| Test effectiveness                     |  7.5/10 | Tests cover core flows, resource-scoped auth, worker state validation, request IDs, portal failures, and route contracts. `make coverage` reports `59.9%`; live Postgres tests in `internal/adapters/postgres/store_test.go:13` are skipped without `EVYDENCE_TEST_DATABASE_URL`, and several read/verify handlers remain at 0% function coverage. |
| Change safety & backward compatibility |  8.0/10 | `make finalize`, `make release-check`, OpenAPI generation checks, docs checks, append-only migrations, and Conventional Commit history provide strong change discipline. OpenAPI remains too generic for an 8+ public contract score. |
| Operability & observability            |  7.7/10 | Health/readiness/metrics, worker logs, migrations, release-check summary, backup manifests, safe request IDs, and deployment docs exist. Operational depth is limited by snapshot storage, skipped live Postgres evidence, and lack of richer structured metrics/tracing. |
| Clarity & developer experience         |  7.8/10 | README/docs are discoverable, docs now have tutorial/how-to/reference/explanation structure, and Make targets are clear. Large central files and broad state structs still make ownership and onboarding harder than necessary. |
| Extensibility                          |  7.4/10 | Adding new evidence/resource types is straightforward, and ports/adapters are present. Extensibility is constrained by whole-state persistence, generic route operation metadata, and authorization/resource-reference logic concentrated in a few large helpers. |
| Overall                                |  7.65/10 | Iteration 2 remediation lifted security, worker correctness, routing clarity, and release validation, but the codebase remains below an 8 mean until instance-admin scope semantics, relational persistence, parser worker side effects, OpenAPI precision, and live durable-store validation are addressed. |

Confidence: medium-high

## Findings by severity
### Critical
- None found in this pass. The current checkout builds and passes the strongest declared project release gate. I did not identify an immediate unauthenticated raw evidence disclosure, SQL injection path, command execution path, bearer-token logging path, or failing project-owned gate.

### High
- Instance-admin authorization can be satisfied by tenant admin scope. `InstanceAdminSnapshot` calls `require(actor, ScopeInstanceAdmin)` in `internal/app/enterprise.go:345`, but `require` allows `actor.HasScope(ScopeAdmin)` for any requested scope in `internal/app/ledger.go:1648`. Since `ScopeAdmin` is tenant administration and bootstrap/API keys can carry `"admin"` or `"*"`, the instance-wide count endpoint can be reached by broader tenant admin credentials. The endpoint only returns aggregate counts and limitations in `internal/app/enterprise.go:350`, but this still weakens the multi-tenant admin boundary.
- PostgreSQL is still not the per-resource source of truth. The `Store` port is whole-state `LoadState`/`SaveState` in `internal/app/ports.go:10`, and the Postgres adapter stores the full ledger state in `ledger_state` in `internal/adapters/postgres/store.go:50` and `internal/adapters/postgres/store.go:75`. `syncResourceIndex` deletes and rebuilds the resource projection on every save in `internal/adapters/postgres/store.go:102`. This limits row-level constraints, row locking for business resources, concurrent writer safety, audit/debug queries, restore confidence, and large-state performance.
- `Ledger` remains a high-risk central aggregate. The struct in `internal/app/ledger.go:64` contains tenant, identity, collector, evidence, build, deployment, incident, control, report, signing, object-retention, package, and integrity maps behind one mutex. This helped rapid delivery but keeps transaction boundaries, aggregate ownership, and concurrency behavior hard to reason about.

### Medium
- Parser worker jobs validate durable state but do not perform asynchronous parsing from object storage. `processJob` loads a snapshot and checks configured job kinds in `cmd/evydence-worker/main.go:78`; `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract`, and `parse_vex` confirm records exist and compare optional hashes but do not fetch raw objects or parse payloads. The docs accurately state this conservative behavior in `docs/reference/worker-outbox.md:15`, but the runtime is still short of the design’s async parsing/signing/reporting path.
- HTTP router decomposition is incomplete. Four handler groups now exist, but `internal/adapters/httpapi/router.go` still contains route registration for every resource family plus most handlers, request helpers, middleware, operation metadata, and response helpers. `wc -l` reports `router.go` at 2287 lines. This is better than iteration 2 but still a merge-risk and ownership hotspot.
- OpenAPI operation metadata is too generic. The shared `op` helper in `internal/adapters/httpapi/router.go:2255` gives broad common response sets and idempotency extensions to all POST routes. It does not express endpoint-specific request bodies, response schemas, query filters, unauthenticated portal-token semantics, pagination contracts, or precise status codes. `make openapi-check` proves generation consistency, not schema precision.
- Customer portal abuse controls are partial. `AccessCustomerPortalPackage` hashes portal tokens, increments `FailedAccessCount`, records `LastFailedAt`, and appends a safe failure audit event for matching prefixes in `internal/app/enterprise.go:455`. `Metrics` exposes `customer_portal_failed_access_count` in `internal/app/integrity_runtime.go:429`. There is still no application-level throttle, attempt cap, token revocation-on-abuse, or enforced deployment-rate-limit contract for the unauthenticated endpoint.
- Secret hash comparisons use normal string equality. `Authenticate` compares API key and SSO session hashes with `key.Hash != hash` and `session.Hash != hash` in `internal/app/ledger.go:323` and `internal/app/ledger.go:346`; customer portal access compares `access.Hash != hash` in `internal/app/enterprise.go:468`. The hashes are HMAC outputs, but constant-time comparison would be a stronger default for bearer-secret verification.
- Live durable-store validation is still optional. `make release-check` runs `live-postgres-check` and `postgres-integration-test`, but both skip when `EVYDENCE_TEST_DATABASE_URL` is unset as shown by the command output and Makefile lines `Makefile:130` and `Makefile:133`. This keeps local development ergonomic but leaves release evidence incomplete unless CI or operators configure Postgres.

### Low
- SSO is currently an admin-created session record model, not a real OIDC/SAML login flow. The domain has SSO provider, identity link, and session resources in `internal/app/enterprise.go:230`, `internal/app/enterprise.go:252`, and `internal/app/enterprise.go:283`, but no token validation callback, SAML assertion parsing, OIDC discovery/JWKS verification, or group-mapping login flow. Docs should keep this positioned as identity/session record support until provider verification exists.
- Important authz helper branches remain lightly covered. `make coverage` reports 0% for helpers such as `projectCoversRefsLocked`, `releaseCoversRefsLocked`, and artifact coverage helpers in `internal/app/enterprise.go`, even though they now sit on the resource-scoped authorization path.
- `ScopeCustomerPortal` is declared in `internal/app/ledger.go:60` but customer portal package access is token-based and unauthenticated by design. The unused scope may confuse API and policy reviews unless removed or documented as reserved.

## Hexagonal architecture verdict
Clean parts: domain structs are framework-free in `internal/domain`, application behavior lives in `internal/app`, HTTP/Postgres/object-store adapters depend inward, commands are process bootstrap code under `cmd/*`, and docs explicitly describe ports, adapters, storage, worker, and trust boundaries.

Boundary leaks are mostly inside the application layer rather than domain importing adapters. `Ledger` is acting as aggregate store, use-case service, authorization engine, idempotency ledger, audit-chain writer, report generator, signing orchestrator, object-store coordinator, outbox producer, and persistence coordinator. That makes change ownership and correctness reasoning harder as each new resource joins the same lock and state snapshot.

The persistence boundary is still the least hexagonal part. A `Store` port exists, but it is a snapshot API instead of aggregate-specific repositories. The PostgreSQL adapter is durable JSON state plus relational projections, not yet a true relational source of truth for all business resources.

Verdict: partially hexagonal and directionally sound, but not yet production-grade for a high-trust evidence ledger until persistence and aggregate boundaries are split.

## Test verdict
Covered well: route registration and OpenAPI generation, idempotency replay/conflict, strict JSON unknown-field rejection, request ID Problem Details, tenant isolation on core evidence paths, release readiness, VEX/decision/exception flows, build/attestation readiness, control coverage, customer packages, portal token leakage checks, failed portal access audit/metrics, resource-scoped human session characterization, worker durable-state validation, and production bootstrap secret rejection.

Weak areas: live PostgreSQL behavior without a configured database, true relational constraints and transactions, parser worker side effects from object storage, instance-admin exact-scope denial, app-level portal abuse throttling, constant-time secret comparison, endpoint-specific OpenAPI schema drift, and several read/verify/config paths with 0% function coverage.

The tests are confidence-building for the MVP and recent remediations. They are still short of an 8+ high-trust production target because core durability and privileged access semantics need sharper tests and implementation.

## Best next fixes
1. Fix privileged scope semantics so tenant `admin` and `"*"` do not automatically satisfy instance-wide administration unless intentionally configured.
2. Start the relational store split with API keys, SSO sessions, idempotency, evidence, audit-chain entries, release bundles, and outbox jobs.
3. Implement parser worker handlers that re-read object storage, verify digests, parse payloads, and preserve idempotent side effects.
4. Continue HTTP decomposition by moving route registration and handlers into resource-family files while preserving route-contract generation.
5. Add endpoint-specific OpenAPI request/response schemas, precise errors, query parameters, auth rules, and idempotency requirements.
6. Add customer portal throttle/attempt-limit controls and constant-time bearer-secret hash comparisons.
7. Add a documented CI/live Postgres profile so release evidence includes at least one durable-store integration run.

## Optional follow-up
- Run remediation iteration 3 from the accompanying backlog.
- Perform a focused privileged-scope/security pass on `require`, wildcard scopes, instance admin, tenant admin, and customer portal token behavior.
- Perform a package-by-package persistence design review before implementing relational repositories.
- Build a test-gap plan for OpenAPI schema precision, worker object-store parsing, and live Postgres release evidence.

## Commands/checks run
- `git status --short`: passed; worktree was clean before audit evidence file creation.
- `git rev-parse --short HEAD`: passed; confirmed current commit `f799e6e`.
- `find . -maxdepth 2 -type f | sort | sed 's#^./##' | head -200`: passed; confirmed repo has Go module, commands, internal packages, migrations, docs, deployment files, OpenAPI, SDK, and prior audit evidence.
- `find .audits -maxdepth 2 -type f | sort`: passed; confirmed existing v1/v2 audit evidence and no v3 evidence before this audit.
- `make help`: passed; listed project-owned gates including `finalize` and `release-check`.
- `find internal cmd docs -maxdepth 3 -type f | sort`: passed; reviewed current package/docs layout and handler decomposition.
- `rg -n "Authorize|resource_type|resource_id|RoleBinding|SSOSession|portal|failed|outbox|Worker|release-check|EVYDENCE_PRINT_BOOTSTRAP_SECRET|request_id|X-Request-ID|FOR UPDATE SKIP LOCKED" internal cmd Makefile docs migrations -S`: passed; collected remediation evidence.
- `wc -l internal/adapters/httpapi/*.go internal/app/*.go cmd/evydence-worker/main.go Makefile`: passed; central inspected files total 15256 lines, with `router.go` at 2287 lines and `enterprise.go` at 1099 lines.
- `make release-check`: passed. It ran `make finalize`, lint, gosec, govulncheck, race tests, `live-postgres-check`, and `postgres-integration-test`. Live PostgreSQL checks skipped because `EVYDENCE_TEST_DATABASE_URL` is unset. Summary was written to `tmp/release-check-summary.txt`.
- `make coverage`: passed. Total statement coverage was `59.9%`.
- Additional targeted source inspections with `sed` and `rg`: passed; inspected authz helpers, worker processing, HTTP handlers, Postgres store, object stores, Makefile release check, production config validation, tests, and prior audit evidence.
