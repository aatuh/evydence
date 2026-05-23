# Backlog

Project: Evydence Codebase Quality Remediation Iteration 3

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Privileged Scope Boundary Hardening [x]

Description: Fix the highest-risk authorization semantics found in audit iteration 3 before expanding the enterprise/admin surface further.

### Ticket E1-T1 - Characterize Instance Admin Scope Semantics [x]

Description: Add tests proving tenant `admin` and ordinary wildcard tenant API keys cannot access instance-wide diagnostics unless the credential explicitly has instance administration authority.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(authz): characterize instance admin scope boundary`
- Cover API-key, SSO-session, and bootstrap-key behavior.

### Ticket E1-T2 - Enforce Exact Privileged Scopes [x]

Description: Adjust authorization helpers so tenant administration does not implicitly satisfy instance-wide, signing-provider, or other explicitly privileged scopes unless the scope model says so.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `fix(authz): require explicit instance admin scope`
- Preserve tenant-admin behavior for tenant-scoped resources.

### Ticket E1-T3 - Document Admin Scope Boundaries [x]

Description: Update API and operations docs to distinguish tenant admin, instance admin, collector admin, keys admin, and customer verifier capabilities without overstating compliance or security outcomes.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `docs(authz): clarify admin scope boundaries`
- Keep docs aligned with implemented behavior.

## Epic E2 - Durable Relational Store Split [ ]

Description: Replace the largest remaining production architecture risk by moving critical resources from whole-ledger snapshot persistence into relational PostgreSQL repositories.

### Ticket E2-T1 - Add Critical Store Contract Tests [ ]

Description: Add repository-agnostic tests for tenant isolation, idempotency replay/conflict, append-only audit-chain behavior, API key and SSO hash secrecy, release bundle immutability, and outbox job state transitions.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(store): characterize critical ledger persistence`
- Run against memory first and Postgres when configured.

### Ticket E2-T2 - Split Critical Repository Ports [ ]

Description: Introduce explicit ports for tenants, API keys, SSO sessions, idempotency records, evidence, audit-chain entries, release bundles, and outbox jobs while keeping the snapshot adapter as a compatibility fallback.

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
- Keep application interfaces tenant-scoped.

### Ticket E2-T3 - Persist Critical Resources Relationally [ ]

Description: Implement PostgreSQL repositories for the critical ports with tenant-scoped queries, uniqueness constraints, row locking where needed, and safe error mapping.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(postgres): persist critical ledger resources relationally`
- Include forward migrations and rollback-safe tests.

### Ticket E2-T4 - Remove Full Resource Index Rebuild From Critical Writes [ ]

Description: Replace delete-and-rebuild resource projection behavior for critical resources with targeted upserts/deletes that preserve concurrency and operational query safety.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `fix(postgres): update resource projections incrementally`
- Preserve existing projection query behavior.

## Epic E3 - Worker Parser Side Effects [ ]

Description: Make configured outbox parser jobs perform deterministic object-store reads and parsing instead of only validating already-written state.

### Ticket E3-T1 - Inject Object Store And Parser Services Into Worker [ ]

Description: Wire the worker so parser jobs can read tenant-prefixed raw payload objects, verify digests, and call parser/application services without logging raw payloads or secrets.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(worker): wire object store for parser jobs`
- Use existing object-store adapters and safe error patterns.

### Ticket E3-T2 - Implement SBOM, Scan, OpenAPI, And VEX Parser Jobs [ ]

Description: Add idempotent handlers for `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract`, and `parse_vex` with duplicate-safe side effects and terminal failure behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(worker): process parser jobs from object storage`
- Include retry tests that prove no duplicate evidence, findings, decisions, or audit entries.

### Ticket E3-T3 - Add Worker Failure Observability Tests [ ]

Description: Verify worker logs and persisted job errors never include raw payload bytes, bearer tokens, portal tokens, private keys, object-store secrets, or provider environment dumps.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(worker): guard parser failure redaction`
- Include malformed JSON and digest mismatch cases.

## Epic E4 - HTTP Contract Precision And Router Ownership [ ]

Description: Continue reducing HTTP adapter risk by improving route ownership and making the generated OpenAPI contract materially descriptive.

### Ticket E4-T1 - Split Route Registration By Resource Family [ ]

Description: Move route registration into focused resource-family registration files while preserving the same public paths, operation IDs, middleware, and route-contract registry.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `refactor(http): split route registration by resource`
- Keep `make openapi-check` green after each move.

### Ticket E4-T2 - Add Endpoint-Specific OpenAPI Schemas [ ]

Description: Replace generic operation metadata with request bodies, response schemas, query parameters, auth/idempotency requirements, pagination/filter contracts, and precise error sets for representative high-risk endpoints first.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(openapi): add precise schemas for critical endpoints`
- Prioritize auth, evidence upload, release bundle, customer portal, SSO session, and admin endpoints.

### Ticket E4-T3 - Add API Contract Behavior Tests [ ]

Description: Add tests that compare representative handler behavior against OpenAPI expectations for required fields, unknown fields, idempotency headers, Problem Details, and query filters.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(openapi): validate contract behavior for critical routes`
- Keep tests small and route-focused.

## Epic E5 - Secret And Customer Portal Abuse Hardening [x]

Description: Harden bearer-secret comparison and unauthenticated portal-token access without changing public response shapes unnecessarily.

### Ticket E5-T1 - Use Constant-Time Secret Hash Comparison [x]

Description: Replace normal string equality for API key, SSO session, and customer portal HMAC hash checks with constant-time comparison helpers.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `fix(auth): compare bearer secret hashes in constant time`
- Keep prefix filtering as an index optimization only.

### Ticket E5-T2 - Add Portal Attempt Limits And Safe Metrics [x]

Description: Add application-level failed-attempt limits or token revocation-on-abuse for customer portal access, plus tenant-safe metrics and tests that prove token values are never stored or returned.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `feat(portal): limit customer package token abuse`
- Do not expose raw evidence or token material in metrics, reports, logs, or audit entries.

### Ticket E5-T3 - Clarify SSO Session Support Versus Provider Login [x]

Description: Either implement strict provider token/assertion verification for the current SSO paths or explicitly document and name the current behavior as admin-managed identity/session records.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `docs(identity): clarify SSO session trust model`
- Avoid implying live OIDC/SAML verification until it exists.

## Epic E6 - Release Evidence And Coverage Depth [ ]

Description: Improve confidence evidence so future audits can score durability, compatibility, and critical-path coverage above 8.

### Ticket E6-T1 - Add Configured Live Postgres Release Profile [x]

Description: Add documented local/CI steps for running `make release-check` with `EVYDENCE_TEST_DATABASE_URL` and preserving the resulting pass/skip summary as release evidence.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `ci(postgres): document live release validation profile`
- Keep ordinary local fast checks Docker-optional.

### Ticket E6-T2 - Raise Coverage On Critical Read And Helper Paths [ ]

Description: Add tests for low-covered read/verify handlers and authorization helper branches that affect release, bundle, evidence, Postgres, and resource-scoped access behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete

Notes:

- Suggested commit: `test(app): cover critical read and authz helper paths`
- Focus on meaningful negative cases, not coverage-only tests.
