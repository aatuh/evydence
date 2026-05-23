# Backlog

Project: Evydence Codebase Quality Remediation Iteration 4

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Relational Persistence Foundation [ ]

Description: Reduce the largest remaining architecture and correctness risk by replacing whole-ledger snapshot persistence for critical resources with relational PostgreSQL repositories.

### Ticket E1-T1 - Add Critical Store Contract Tests [ ]

Description: Add repository-agnostic tests for API keys, SSO sessions, idempotency records, evidence, audit-chain entries, release bundles, and outbox jobs before changing storage behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(store): characterize critical persistence contracts`
- Cover tenant isolation, append-only behavior, idempotency replay/conflict, hash secrecy, row-lock expectations, and safe error mapping.

### Ticket E1-T2 - Introduce Critical Repository Ports [ ]

Description: Split the current snapshot `Store` contract into focused critical-resource ports while keeping the snapshot store as a compatibility fallback during migration.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(store): split critical repository ports`
- Keep port methods tenant-scoped and aggregate-specific.

### Ticket E1-T3 - Persist API Keys, SSO Sessions, And Idempotency Relationally [ ]

Description: Implement PostgreSQL repositories for bearer-secret records and idempotency records with HMAC hash secrecy, uniqueness constraints, tenant filters, replay semantics, and conflict handling.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(postgres): persist auth and idempotency records`
- Include migrations and tests for cross-tenant denial and reused idempotency keys.

### Ticket E1-T4 - Persist Evidence, Audit Chain, Bundles, And Outbox Relationally [ ]

Description: Move the highest-value ledger resources to relational writes with append-only constraints, tenant-scoped lookups, row locking where needed, and safe rollback behavior.

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
- Keep old snapshot loading during the migration window.

## Epic E2 - Worker Parser Side Effects [ ]

Description: Turn parser outbox jobs from durable-state validation into deterministic, idempotent object-store parsing work.

### Ticket E2-T1 - Wire Worker Object Store And Parser Dependencies [ ]

Description: Give the worker access to configured object storage and parser services without logging raw payloads, provider dumps, bearer tokens, portal tokens, or private keys.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(worker): inject object store for parser jobs`
- Preserve current fail-closed behavior for unsupported jobs.

### Ticket E2-T2 - Implement SBOM, Scan, OpenAPI, And VEX Parser Jobs [ ]

Description: Re-read tenant-prefixed raw payload objects, verify declared digests, parse payloads, and write duplicate-safe durable parser results for configured parser job kinds.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(worker): parse uploaded evidence payloads`
- Include retry tests proving no duplicate findings, decisions, evidence, signatures, or audit entries.

### Ticket E2-T3 - Add Worker Redaction And Terminal Failure Tests [ ]

Description: Add tests for malformed JSON, missing objects, digest mismatch, parser failures, retry backoff, terminal failure, and safe error text.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(worker): cover parser failure safety`
- Assert persisted job errors do not contain raw payload bytes or secrets.

## Epic E3 - HTTP Contract Precision [ ]

Description: Make the public API contract more useful for clients and safer for future change.

### Ticket E3-T1 - Add Endpoint-Specific OpenAPI Schemas For Critical Routes [ ]

Description: Add concrete request and response schemas for auth, evidence, bundles, VEX, decisions, exceptions, builds, attestations, customer portal access, and instance admin routes.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(openapi): describe critical route schemas`
- Keep generated `openapi.yaml` and docs aligned.

### Ticket E3-T2 - Encode Auth, Idempotency, Query, And Error Contracts Precisely [ ]

Description: Replace broad shared OpenAPI metadata with per-route auth scopes, idempotency requirements, query parameters, pagination fields, public portal-token behavior, and stable Problem Details codes.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `fix(openapi): tighten route operation contracts`
- Add drift tests for representative route families.

### Ticket E3-T3 - Split Route Registration By Resource Family [x]

Description: Move route registration into focused files by resource family while preserving public paths, operation IDs, middleware, and route-contract generation.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(http): split route registration`
- Keep the current router tests green after each moved family.
- Implemented in this pass by moving route registration into resource-family helpers in `internal/adapters/httpapi/route_registration.go`, preserving public paths and operation IDs, and adding route-family contract tests.

## Epic E4 - Live Durable Release Evidence [x]

Description: Turn the current optional live Postgres profile into repeatable evidence for release and audit review.

### Ticket E4-T1 - Add Local Live Postgres Scripted Profile [x]

Description: Add a project-owned script or Make target sequence that starts Compose, loads `.test.env`, runs `make release-check`, and preserves `tmp/release-check-summary.txt`.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `chore(release): add live postgres validation profile`
- Do not require Docker for ordinary `make finalize`.
- Implemented in this pass with `make release-check-local-postgres`, which starts Compose PostgreSQL, loads `.test.env` or `.test.env.example`, runs `make release-check`, and preserves `tmp/release-check-summary.txt`.

### Ticket E4-T2 - Add CI Documentation For Live Postgres Gates [x]

Description: Document the disposable Postgres service, required environment variables, expected pass lines, artifact retention, and secret-handling constraints for CI release validation.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `docs(release): document live postgres CI evidence`
- Keep wording limited to engineering validation evidence.
- Implemented in this pass in `docs/reference/release-validation.md` and `README.md`.

## Epic E5 - Portal And Authz Coverage Depth [x]

Description: Improve confidence around the remaining security-sensitive edge cases without broad feature expansion.

### Ticket E5-T1 - Add Portal Abuse Control Boundary Tests [x]

Description: Add tests for expired portal tokens, revoked portal tokens, wrong-prefix attempts, repeated known-prefix attempts, safe metrics, and no raw token leakage in errors/audit entries.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(portal): deepen access abuse coverage`
- If application throttling is added, document how it composes with reverse-proxy limits.
- Implemented in this pass with expired-token, wrong-prefix, known-prefix revocation, safe metrics, and audit no-leak coverage.

### Ticket E5-T2 - Add Resource-Scoped Authz Branch Tests [x]

Description: Cover currently weak branches for product/project/release/artifact/evidence-reference helper decisions that gate human SSO session access.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(authz): cover resource grant helper branches`
- Include negative cross-tenant and wrong-resource cases.
- Implemented in this pass with direct product/project/release/artifact resource grant helper coverage.

### Ticket E5-T3 - Document Reserved Or Remove Unused Customer Portal Scope [x]

Description: Resolve the `ScopeCustomerPortal` ambiguity by either documenting it as reserved future scope or removing it if no route or role uses it.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `docs(auth): clarify customer portal scope`
- Keep token-based portal access semantics explicit.
- Implemented in this pass by removing the unused `ScopeCustomerPortal` constant and documenting that customer portal access is token-based rather than API-scope based.
