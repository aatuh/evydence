# Backlog

Project: Evydence

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Relational Runtime Source Of Truth [ ]

Description: Replace snapshot-backed production persistence with transactionally safe PostgreSQL repositories while preserving the in-process store for tests and local demos.

### Ticket E1-T1 - Add Store Contract Characterization Tests [ ]

Description: Define shared store behavior tests for tenant isolation, idempotency replay/conflict, append-only audit entries, uniqueness, and rollback safety across memory and PostgreSQL stores.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Prefer a reusable test harness that can run without PostgreSQL and optionally with `EVYDENCE_TEST_DATABASE_URL`.

### Ticket E1-T2 - Split Identity And Auth Persistence [ ]

Description: Move tenants, API keys, organizations, users, role bindings, SSO providers, SSO sessions, and idempotency records from snapshot persistence to relational repositories.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Keep one-time secrets hashed and never persisted in returned public state.

### Ticket E1-T3 - Split Evidence And Audit Persistence [ ]

Description: Move products, projects, releases, artifacts, evidence, evidence lifecycle, audit chain, signing keys, signatures, bundles, verification results, and object metadata to relational repositories.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Preserve append-only semantics and chain continuity during migration.

### Ticket E1-T4 - Remove Snapshot Persistence From Production Path [ ]

Description: Keep snapshot persistence only as a compatibility/local test adapter and fail production startup if a relational repository path is not configured.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Include migration/upgrade documentation for existing snapshot-backed development data.

## Epic E2 - Resource-Scoped RBAC And ABAC [x]

Description: Make enterprise authorization enforce the resource scope already modeled by role bindings and prevent tenant-wide privilege expansion.

### Ticket E2-T1 - Characterize Current RBAC Scope Behavior [x]

Description: Add tests that prove current role bindings with `resource_type` and `resource_id` do or do not limit reads, writes, reports, exports, and verification endpoints.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Cover product, project, release, package, bundle, report, and control evidence scopes.

### Ticket E2-T2 - Enforce Scoped Role Bindings [x]

Description: Add authorization checks that combine actor scopes with role-binding resource constraints before resource reads, writes, links, exports, reports, and verification results.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Fail closed on unknown resource types.

### Ticket E2-T3 - Document Enterprise Authorization Semantics [x]

Description: Update API and operations docs with exact role, scope, and resource-binding behavior and limitations.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E3 - Real Outbox Worker Semantics [ ]

Description: Make background jobs perform deterministic, idempotent work and expose enough state to operate them safely.

### Ticket E3-T1 - Define Job Handler Contracts [ ]

Description: Introduce application-level job handler interfaces for parse, sign, verify, and report jobs with idempotency and tenant-scope requirements.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E3-T2 - Implement Parse And Verify Job Side Effects [ ]

Description: Replace no-op success handling for SBOM, vulnerability scan, OpenAPI, VEX, bundle signing, subject verification, and attestation verification jobs with real application calls.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Jobs must be safe to retry without duplicating append-only records.

### Ticket E3-T3 - Add Worker Observability And Failure Tests [ ]

Description: Add tests for claim exclusivity, retry/backoff, terminal failure, duplicate prevention, safe logs, and persisted job status.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E4 - Precise API Contracts [ ]

Description: Upgrade OpenAPI and route contracts from route existence checks to request, response, auth, idempotency, pagination, and error-shape contracts.

### Ticket E4-T1 - Add Shared Schema Registration [ ]

Description: Define reusable OpenAPI schemas for core resources, Problem Details, pagination, idempotency errors, and report envelopes.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E4-T2 - Replace Generic Operation Metadata [ ]

Description: Replace the generic `op` helper behavior with endpoint-specific request bodies, response codes, security requirements, and idempotency rules.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E4-T3 - Add Contract Drift Tests For Schemas [ ]

Description: Add tests that compare handler behavior, required headers, error codes, and JSON response shapes against OpenAPI for representative endpoints in each resource group.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E5 - Critical-Path Test Coverage [ ]

Description: Raise confidence in production entrypoints, adapters, worker behavior, authorization boundaries, and package/export paths.

### Ticket E5-T1 - Cover Command Entrypoints And Config Failure Modes [ ]

Description: Add tests for API, worker, migrate, and OpenAPI command startup validation, production config rejection, object-store selection, and safe bootstrap output behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E5-T2 - Cover Read And Verify Endpoints [ ]

Description: Add API tests for currently weak read/verify handlers, including not-found, forbidden, cross-tenant, malformed query, and success cases.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E5-T3 - Add Live PostgreSQL Integration Coverage [ ]

Description: Add durable API flows that run with `EVYDENCE_TEST_DATABASE_URL`, including migration application, restart persistence, relational constraints, and object-store failure behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

## Epic E6 - Quality Gates And Operability Hardening [ ]

Description: Make release validation and production diagnosis strong enough for a high-trust evidence ledger.

### Ticket E6-T1 - Strengthen Finalize Or Add Release Gate [x]

Description: Update the project-owned final gate or add a release gate that includes tests, OpenAPI, docs, deploy, SDK, lint, gosec, govulncheck, race tests, and configured live integration checks.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E6-T2 - Add Request IDs And Safe Audit Events For Failed External Access [x]

Description: Add request IDs to Problem Details and record safe, non-secret audit signals for failed customer portal access and other unauthenticated token endpoints.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

### Ticket E6-T3 - Split HTTP Route Groups By Resource Family [ ]

Description: Refactor `internal/adapters/httpapi/router.go` into route group files for identity, evidence, builds, controls, packages, reports, operations, and integrity without changing public paths.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
