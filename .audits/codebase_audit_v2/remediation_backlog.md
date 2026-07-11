# Backlog

Project: Evydence Codebase Quality Remediation Iteration 2

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Durable Relational Store Foundation [ ]

Description: Replace the highest-risk snapshot persistence behavior with relational PostgreSQL repositories for critical ledger resources while preserving the current application contract.

### Ticket E1-T1 - Add Store Contract Characterization Tests [ ]

Description: Add repository-agnostic tests for tenant isolation, idempotency replay/conflict, append-only audit-chain behavior, API key/session hash secrecy, and resource index consistency.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(store): characterize durable ledger invariants`
- Keep tests runnable against memory first, then reuse them for PostgreSQL where configured.

### Ticket E1-T2 - Split Critical Store Ports [ ]

Description: Introduce explicit store interfaces for tenants, API keys, SSO sessions, idempotency records, evidence, audit-chain entries, release bundles, and outbox jobs.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(store): split critical ledger ports`
- Keep the current snapshot store as a compatibility adapter during the transition.

### Ticket E1-T3 - Implement PostgreSQL Repositories For Critical Resources [ ]

Description: Move runtime reads/writes for critical resources from `ledger_state` snapshot persistence to relational tables with tenant-scoped queries, transactions, uniqueness constraints, and row locking where needed.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(postgres): persist critical ledger records relationally`
- Include migration/backfill behavior and rollback-safe tests.

### Ticket E1-T4 - Add Configured Postgres Release Evidence [ ]

Description: Add a documented live Postgres test profile and ensure release validation records whether `EVYDENCE_TEST_DATABASE_URL` backed tests actually ran or were skipped.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `ci(postgres): document live durable-store validation`
- Do not require local developers to run Docker for every fast test.

## Epic E2 - Resource-Scoped Authorization Coverage [ ]

Description: Complete the resource-scoped RBAC/ABAC model across all workflows that currently enforce tenant-wide scopes only.

### Ticket E2-T1 - Inventory Resource-Scoped Authorization Gaps [x]

Description: Add a test or static inventory that lists app methods referencing product, project, release, package, bundle, build, deployment, incident, evidence, control, or report IDs and classifies whether they call resource authorization.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(authz): inventory resource-scope coverage`
- Use this inventory to prevent regressions as new methods are added.

### Ticket E2-T2 - Extend Resource References For Builds, Controls, Deployments, And Incidents [x]

Description: Expand the `resourceRefs` model and coverage helpers so builds, attestations, controls, deployments, incidents, security scans, source records, and reports can be authorized against product/release/project/package scope.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(authz): cover workflow resources in scoped grants`
- Preserve API key and collector behavior while narrowing human session actors.

### Ticket E2-T3 - Enforce Resource Authorization In Remaining Workflows [ ]

Description: Replace tenant-wide-only checks with resource-aware authorization in controls, risk workflows, builds, source/deployment workflows, report generation, and verification endpoints where applicable.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `fix(authz): enforce scoped grants across workflows`
- Add cross-resource and cross-tenant negative tests for each changed workflow family.

## Epic E3 - Worker Execution Semantics [ ]

Description: Make the outbox worker perform real deterministic work for configured job kinds instead of only failing closed.

### Ticket E3-T1 - Define Idempotent Job Handler Contracts [x]

Description: Specify inputs, outputs, idempotency keys, retry behavior, failure states, and safe logging rules for each configured worker job kind.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `docs(worker): define outbox handler contracts`
- Include `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract`, `parse_vex`, `sign_bundle`, `verify_subject`, and `verify_attestation`.

### Ticket E3-T2 - Implement Verification And Signing Worker Handlers [x]

Description: Implement idempotent handlers for `verify_subject`, `verify_attestation`, and `sign_bundle` using existing application services and persisted state.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(worker): process verification and signing jobs`
- Do not log raw payloads, tokens, private keys, or customer package contents.

### Ticket E3-T3 - Implement Parser Worker Handlers [ ]

Description: Implement idempotent parser handlers for SBOM, vulnerability scan, OpenAPI contract, and VEX jobs with object-store reads, digest verification, safe errors, and terminal failure behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(worker): process parser jobs safely`
- Add retry/no-duplicate side-effect tests.

## Epic E4 - API Contract And Router Maintainability [ ]

Description: Reduce HTTP adapter risk by splitting route ownership and improving generated OpenAPI precision.

### Ticket E4-T1 - Split HTTP Routes By Resource Family [ ]

Description: Move route registration and handlers into focused files such as system, identity, evidence, builds, controls, packages, integrity, and reports while preserving the same public paths and route registry.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(http): split route groups by resource`
- Keep `make openapi-check` green after each move.

### Ticket E4-T2 - Add Endpoint-Specific OpenAPI Schemas [ ]

Description: Replace generic operation metadata with endpoint-specific request bodies, response schemas, security requirements, idempotency requirements, pagination/filter parameters, and precise error status sets.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(openapi): describe endpoint schemas precisely`
- Include unauthenticated customer portal token access as a special case.

### Ticket E4-T3 - Add API Compatibility Tests For Schema Drift [ ]

Description: Add tests that compare representative handler behavior against OpenAPI schemas for required fields, unknown fields, idempotency headers, Problem Details, and pagination/filter parameters.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(openapi): guard API schema drift`
- Keep tests focused on high-risk public endpoints first.

## Epic E5 - Customer Portal And Operational Hardening [x]

Description: Harden unauthenticated package access and release operations evidence without weakening local developer workflows.

### Ticket E5-T1 - Add Customer Portal Abuse Controls [x]

Description: Add safe rate-limit hooks or documented reverse-proxy throttle integration for `/v1/customer-portal/package`, plus failed-attempt counters that do not store raw tokens or customer package contents.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(portal): add safe access abuse controls`
- Preserve the current no-raw-token logging invariant.

### Ticket E5-T2 - Harden Production Bootstrap Secret Behavior [x]

Description: Reject or explicitly guard `EVYDENCE_PRINT_BOOTSTRAP_SECRET=true` in production, document the local-only path, and add tests for production config validation.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `fix(config): prevent production bootstrap secret printing`
- Keep local demo behavior available for non-production use.

### Ticket E5-T3 - Add Release Validation Summary Artifact [x]

Description: Make `make release-check` produce a small local summary file or console summary that records which checks passed and which configured-live checks were skipped.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `chore(release): summarize validation gates`
- The summary must not claim live Postgres coverage when the env var is unset.
