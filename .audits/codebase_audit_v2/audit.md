## Executive summary
Evydence has improved since audit iteration 1. The remediation commit `ca5b5a4 fix(auth): enforce scoped human role grants` closed several concrete findings: human SSO actors now carry resource grants, core product/release/evidence/package/report paths check those grants, Problem Details include request IDs, failed customer portal token access is audited without token disclosure, configured-but-unimplemented worker jobs fail closed, and `make release-check` now exercises the strongest declared validation set.

The codebase remains a strong MVP-to-early-product foundation. It has a clear Go module, project-owned Makefile gates, API/worker/CLI entrypoints, domain/application/adapters packages, migrations, OpenAPI generation, documentation, SDK examples, and tests. The strongest qualities are deterministic application behavior, tenant-scoped records, strict JSON decoding in HTTP handlers, hashed one-time secrets, safe error mapping, append-only audit entries, and docs that avoid legal compliance or secure-release claims.

The main blockers to an 8+ codebase score are structural rather than cosmetic. PostgreSQL runtime persistence is still snapshot-centered through `LoadState`/`SaveState`, the application layer is dominated by a large `Ledger` aggregate with a single mutex and many resource maps, and `internal/adapters/httpapi/router.go` remains a very large route/handler file. Those choices supported fast increments but now limit transaction isolation, operational diagnosis, and safe feature ownership.

Security is materially better than in iteration 1, but resource-scoped RBAC is not yet universal. The remediation covers important core flows, but many newer workflows still only call `require(actor, scope)` and tenant filters rather than `authorizeResourceLocked` with resource references. For example controls, incidents, security scans, builds, and several source/deployment paths have tenant-level scope enforcement but not the same product/release/package grant narrowing.

All project-owned checks I ran passed on the current commit. Coverage increased slightly from the prior audit evidence to 60.3%, but adapter/entrypoint/live PostgreSQL coverage remains weak when `EVYDENCE_TEST_DATABASE_URL` is not configured.

## Scorecard
| Dimension                              | Score | Notes |
|----------------------------------------|------:|-------|
| Architecture & boundaries              |  7/10 | Domain/app/adapters are separated, but the production store is still whole-ledger snapshot persistence via `internal/app/ports.go:10` and `internal/adapters/postgres/store.go:50`, and `Ledger` centralizes most resources in `internal/app/ledger.go:71`. |
| SOLID / cohesion / coupling            |  6.5/10 | Behavior is reasonably cohesive by domain method, but `internal/app/ledger.go` is 1765 lines, `internal/app/enterprise.go` is 937 lines, and `internal/adapters/httpapi/router.go` is 2577 lines, which keeps coupling and merge risk high. |
| Correctness & robustness               |  7.5/10 | Core gates pass, idempotency and validation are tested, and worker no-op semantics improved by failing closed in `cmd/evydence-worker/main.go:73`. Remaining risk: async jobs do not yet perform parse/sign/verify side effects, and snapshot persistence weakens concurrency behavior. |
| Security                               |  7.5/10 | API keys, SSO/customer portal tokens, strict decoding, safe errors, and request IDs are strong. Resource grants now exist in `internal/domain/domain.go:77` and are checked in core paths through `internal/app/enterprise.go:761`, but several workflow families still only use scope checks. |
| Test effectiveness                     |  7/10 | Tests cover many API/app flows and the remediation added RBAC, request ID, failed portal access, and worker fail-closed coverage. `make coverage` still reports 60.3% total coverage, with 0% for several command entrypoints and live Postgres adapter coverage skipped without `EVYDENCE_TEST_DATABASE_URL`. |
| Change safety & backward compatibility |  7.5/10 | `make release-check`, OpenAPI generation checks, docs checks, append-only migrations, and Conventional Commit history improve safety. OpenAPI operations are still schema-light and generated from a generic `op` helper in `internal/adapters/httpapi/router.go:2531`. |
| Operability & observability            |  7/10 | Health/readiness/metrics, migrations, worker polling, Helm/air-gap docs, backup manifests, request IDs, and release gates exist. Missing pieces include real worker handlers, richer safe metrics/tracing, and durable relational operational queries. |
| Clarity & developer experience         |  7.5/10 | README/docs/Makefile are discoverable, docs are organized by task type, and the current source layout is understandable. Large central files and broad state structs still increase cognitive load for new contributors. |
| Extensibility                          |  7/10 | The project can add new resources quickly, and adapters depend inward. Extensibility is constrained by the snapshot store contract, monolithic route registration, and incomplete reusable authorization/resource-reference patterns. |
| Overall                                |  7.25/10 | The iteration 1 remediation improved security, correctness, and gates, but the codebase remains below an 8+ mean until persistence, authorization coverage, router/app decomposition, OpenAPI precision, and worker execution are hardened. |

Confidence: medium-high

## Findings by severity
### Critical
- None found in this pass. The current commit builds and passes the strongest declared release gate. I did not identify an immediate unauthenticated raw evidence disclosure, bearer-token logging path, SQL injection path, or failing test gate.

### High
- PostgreSQL is still not the per-resource source of truth. `internal/app.Store` exposes `LoadState` and `SaveState` over a single `PersistedState` value (`internal/app/ports.go:10`), and the PostgreSQL adapter persists that value in `ledger_state` (`internal/adapters/postgres/store.go:50`, `internal/adapters/postgres/store.go:75`). `syncResourceIndex` deletes and rebuilds the projection table on every save (`internal/adapters/postgres/store.go:102`). This is the largest production architecture risk because it limits row-level locking, database constraints, concurrent writers, audit/debug queries, restore confidence, and large-state performance.
- Resource-scoped RBAC improved but is not yet universal. Human session actors now derive `ResourceGrants` from role bindings (`internal/app/ledger.go:352`, `internal/app/enterprise.go:715`), and `authorizeResourceLocked` enforces grants for core product/release/evidence/package/bundle paths (`internal/app/enterprise.go:761`). However, many implemented workflows still only call `require(actor, scope)`, then tenant-filter resource IDs. Examples include controls (`internal/app/controls.go:68`), incidents (`internal/app/risk_workflows.go:89`), build creation/read/attestations (`internal/app/builds.go:291`), and several source/deployment methods listed by `rg "require\\(actor" internal/app/*.go`. This leaves scoped human roles broader than their `resource_type`/`resource_id` fields imply outside the remediated core paths.
- The outbox worker now fails closed, but the async runtime is still not functionally implemented. `processJob` rejects configured job kinds with `"outbox job handler is not configured"` (`cmd/evydence-worker/main.go:73`). This is safer than succeeding no-op jobs, but the application still enqueues parse/sign/verify jobs such as `verify_attestation` (`internal/app/builds.go:446`) that will retry and eventually fail instead of completing side effects.

### Medium
- `Ledger` remains a god aggregate. `internal/app/ledger.go` defines one struct with a mutex and dozens of maps for tenants, users, collectors, evidence, builds, deployments, incidents, policies, packages, integrity records, and reports (`internal/app/ledger.go:71`). That makes lock scope, transaction boundaries, and aggregate ownership difficult to reason about as the product grows.
- The HTTP adapter is too centralized. `internal/adapters/httpapi/router.go` is 2577 lines and combines route registration, handlers, auth helpers, body parsing, response writing, request ID middleware, and OpenAPI operation metadata. This raises change collision risk and makes endpoint ownership unclear.
- OpenAPI contract generation remains schema-light. The shared `op` helper assigns the same broad response set to every operation and attaches idempotency extensions to every `POST` (`internal/adapters/httpapi/router.go:2531`). It does not encode endpoint-specific request/response schemas, public token endpoint nuance, pagination/filter shapes, or precise error/status behavior.
- Live PostgreSQL tests are opt-in and were skipped by the release gate because `EVYDENCE_TEST_DATABASE_URL` is not set. `internal/adapters/postgres/store_test.go:13` skips without that environment variable, and `make live-postgres-check`/`make postgres-integration-test` also skip when unset. That is acceptable locally, but release evidence should include at least one configured durable-store run.
- Customer portal token access has safe hashing and failed-access audit, but no visible throttle, attempt limit, or abuse metric. `AccessCustomerPortalPackage` audits failed attempts against matching prefixes without leaking token values (`internal/app/enterprise.go:455`, `internal/app/enterprise.go:470`), but the unauthenticated endpoint still needs rate limiting or explicit deployment-layer controls.
- Production bootstrap can print the one-time bootstrap secret when `EVYDENCE_PRINT_BOOTSTRAP_SECRET=true` (`cmd/evydence-api/main.go:75`). The log path is controlled and local-oriented, but production config should also reject that flag or require a documented break-glass mode.

### Low
- `ScopeCustomerPortal` is declared (`internal/app/ledger.go:60`) but the public customer portal access path uses a raw token instead of an authenticated actor. This may be intentional, but the unused scope can confuse policy reviews and OpenAPI consumers.
- Some resource-specific helper coverage remains low. `make coverage` reports 0% for `projectCoversRefsLocked` and `releaseCoversRefsLocked` (`internal/app/enterprise.go:855`, `internal/app/enterprise.go:863`), even though these helpers are important for the new RBAC model.
- Generated audit/report timestamps use wall-clock `l.now()` in many report paths. That is acceptable for generation metadata, but deterministic report tests should assert stable inputs where reproducibility matters.

## Hexagonal architecture verdict
The codebase is partially hexagonal and generally points in the right direction. Clean parts: domain types are framework-free in `internal/domain`, application behavior lives mostly in `internal/app`, HTTP and storage adapters depend inward, object storage adapters sit under `internal/adapters/objectstore`, and command packages bootstrap processes without being imported by domain code.

The biggest boundary leak is compressed responsibility inside the application layer rather than framework leakage into domain. `Ledger` is simultaneously an aggregate store, authorization engine, idempotency holder, audit-chain writer, signing orchestrator, report generator, outbox producer, and persistence coordinator. That makes it harder to replace snapshot persistence with repository transactions without touching many use cases.

The persistence boundary is the least hexagonal part. A port named `Store` exists, but it is a whole-state snapshot API, so application services cannot express aggregate-specific repository contracts, row locking, unique constraints, or transactional workflows. The PostgreSQL adapter is therefore durable storage for a JSON state blob plus projections, not yet a true relational adapter.

Verdict: partially hexagonal, good for MVP acceleration, not yet production-grade for a high-trust evidence ledger.

## Test verdict
Covered well: API route registration/OpenAPI rendering, idempotency replay/conflict, strict JSON unknown-field rejection, tenant isolation on core evidence reads, release bundle verification, VEX/exception/readiness behavior, control coverage, customer package generation, enterprise identity basics, resource-scoped human session characterization, request ID Problem Details, failed portal-access audit, and worker fail-closed behavior.

Weak areas: relational Postgres behavior without a live database, command entrypoint configuration paths, worker side effects, resource-scoped authorization across all workflow families, schema-precise OpenAPI drift, customer portal abuse controls, and several read/verify handlers with 0% coverage in the function coverage output.

The tests are confidence-building for MVP workflows and recent remediations. They are not yet sufficient for an 8+ high-trust production score because key durability, authorization, and async execution risks remain either structurally unresolved or only partially covered.

## Best next fixes
1. Replace snapshot-backed runtime persistence with relational PostgreSQL repositories for identity/API keys/idempotency/evidence/audit chain/bundles/outbox first.
2. Extend resource-scoped authorization to every workflow that references product, project, release, package, bundle, build, deployment, incident, evidence, control, or report scope.
3. Implement real idempotent worker handlers for configured outbox jobs or stop enqueuing jobs whose handlers are not ready.
4. Split HTTP routes and handlers into resource-focused files while preserving one OpenAPI/route-contract registry.
5. Add endpoint-specific OpenAPI request/response schemas, auth/idempotency requirements, pagination/filter contracts, and precise error status sets.
6. Add always-runnable adapter tests for Postgres SQL generation/projection behavior and a documented CI/live database profile for release evidence.
7. Add customer portal rate limiting or explicit reverse-proxy throttle guidance plus safe metrics for failed access attempts.

## Optional follow-up
- Run remediation iteration 2 from the accompanying backlog.
- Perform a package-by-package review of `internal/app` to prepare the relational store split.
- Run a security-focused pass on resource-scoped authorization coverage and customer portal abuse controls.
- Build a test-gap plan for worker execution, PostgreSQL integration, and OpenAPI schema precision.

## Commands/checks run
- `git status --short`: passed; worktree was clean before audit evidence file creation.
- `git log --oneline -5`: passed; confirmed latest commit was `ca5b5a4 fix(auth): enforce scoped human role grants`.
- `find . -maxdepth 3 -type f | sort | sed 's#^./##' | head -250`: passed; confirmed repo structure includes Go module, `cmd/`, `internal/`, migrations, docs, deployment files, SDK examples, OpenAPI, and prior audit evidence.
- `make help`: passed; listed project-owned targets including `release-check`.
- `wc -l internal/app/*.go internal/adapters/httpapi/router.go internal/adapters/postgres/store.go cmd/evydence-worker/main.go Makefile`: passed; identified central file sizes, including `router.go` at 2577 lines and total inspected Go/Makefile lines at 14005 for the selected central set.
- `rg -n "request_id|X-Request-ID|customer_portal_package.access_failed|ResourceGrants|release-check|handler is not configured|TestHumanSSOSessionRoleBindingsAreResourceScoped|TestProblemDetailsIncludeRequestID|TestProcessJobFailsClosed" internal cmd Makefile -g'*.go' -g'Makefile'`: passed; confirmed remediation evidence for request IDs, failed portal audit, resource grants, worker fail-closed tests, and release gate.
- `rg -n "authorizeResourceLocked|resourceAllowedLocked|require\\(actor" internal/app/*.go`: passed; confirmed resource authorization is present in core paths and missing from several newer workflow families.
- `make release-check`: passed. It ran finalize, lint, gosec, govulncheck, race tests, and configured live integration gates. `live-postgres-check` and `postgres-integration-test` skipped because `EVYDENCE_TEST_DATABASE_URL` is unset.
- `make coverage`: passed. Total statement coverage was `60.3%`; notable low-coverage areas include command entrypoints, `internal/adapters/postgres` without live DB, and multiple read/verify handlers.
