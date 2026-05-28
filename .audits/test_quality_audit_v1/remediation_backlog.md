# Backlog

Project: Evydence test quality remediation

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Raise Behavioral Coverage To 80% [ ]

Description: Add meaningful tests for uncovered behavior until project coverage reaches at least 80% and the mean test-quality score can reach 8/10.

### Ticket E1-T1 - Cover App Read/List And Lifecycle Gaps [x]

Description: Add application-layer tests for release transitions, list/get paths, supersession/link behavior, missing evidence, key rotation/revocation, error helper mapping, and future-extension edge cases.

Implementation rules:

- implement the ticket in the smallest sensible step
- run focused `go test ./internal/app` and `make coverage`
- ensure assertions prove behavior, tenant boundaries, and safe errors rather than only executing code
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after checks pass

### Ticket E1-T2 - Cover HTTP Route Gaps [x]

Description: Add route-level tests for future-extension handlers, read/list endpoints, key/admin endpoints, policy/missing-evidence endpoints, and source snapshot handlers.

Implementation rules:

- implement the ticket in the smallest sensible step
- run focused `go test ./internal/adapters/httpapi` and `make openapi-check`
- assert status codes, response bodies, idempotency behavior, and authz where relevant
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after checks pass

### Ticket E1-T3 - Cover Command, SDK, And Adapter Helpers [ ]

Description: Add tests for CLI helper commands, worker/API env helpers, Go SDK request behavior, S3 constructor/metadata behavior, and Postgres migration/resource projection helper paths that can be tested without external services.

Implementation rules:

- implement the ticket in the smallest sensible step
- run focused package tests and `make coverage`
- avoid live network dependencies; use fakes or local `httptest` where useful
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after checks pass

## Epic E2 - Strengthen Enforcement And Reporting [ ]

Description: Make coverage and test quality easier to enforce consistently.

### Ticket E2-T1 - Add Coverage Threshold Gate [ ]

Description: Add a project-owned coverage gate that fails below 80% and document how to run it with optional live Postgres configuration.

Implementation rules:

- implement the ticket after coverage is actually at or above 80%
- run `make coverage-check` or the chosen project-owned gate
- update README or docs if a new command is added
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after checks pass

### Ticket E2-T2 - Add CI Workflow For Test Gates [ ]

Description: Add a checked-in CI workflow that runs test, OpenAPI, docs, deploy, and coverage threshold gates without requiring secrets.

Implementation rules:

- keep the workflow deterministic and self-contained
- do not require live Postgres for the fast CI path unless services are configured in the workflow
- run `make finalize` after adding the workflow
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after checks pass
