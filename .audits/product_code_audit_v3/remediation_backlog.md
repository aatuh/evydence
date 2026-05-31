# Backlog

Project: Evydence product-code audit v3 remediation

Status legend:

- [ ] not done
- [x] done

Execution rules:

- Complete tickets in dependency order.
- Prefer the smallest change that restores the product claim without expanding scope.
- Run `make finalize` after each completed ticket, or the strongest equivalent if a ticket intentionally uses a narrower gate.
- For production-readiness tickets, also run `set -a; . ./.test.env.example; set +a; make production-check` when live PostgreSQL is available.
- Create a Conventional Commit immediately after each completed ticket.
- Update ticket checkmarks only after implementation, docs, tests, and gates pass.
- Preserve tenant isolation, append-only evidence behavior, safe errors, and conservative non-claim language.

## Epic E1 - Restore Current Checkout Usability [ ]

Description: Fix the current product-blocking build failure so Evydence can be tested, packaged, and evaluated again.

### Ticket E1-T1 - Complete Or Revert `releaseEvidenceService` Refactor [ ]

Description: Resolve PCA3-001 by adding the missing `releaseEvidenceService` type and Ledger wrappers, or reverting the partial receiver rewrite if the service split cannot be completed safely in one step.

Implementation rules:

- inspect `internal/app/ledger.go`, `internal/app/vex.go`, and existing identity service patterns first
- preserve public `Ledger` method signatures used by HTTP handlers and tests
- add characterization tests if any wrapper behavior is not already covered
- run `go test ./internal/app ./internal/adapters/httpapi ./cmd/evydence-api ./cmd/evydence-worker`
- run `make fast-check`
- create a Conventional Commit after the gate passes

### Ticket E1-T2 - Re-run Production Gate From The Restored Tree [ ]

Description: Prove the restored checkout satisfies the controlled self-hosted production gate.

Implementation rules:

- load `.test.env.example` or the local `.test.env`
- run `set -a; . ./.test.env.example; set +a; make production-check`
- preserve the resulting coverage and release-check artifacts
- do not mark complete if live PostgreSQL is unavailable unless the dependency is explicitly documented
- create a Conventional Commit only if this ticket required code/doc changes

## Epic E2 - Finish Product-Maturity Service Boundaries [ ]

Description: Reduce regression risk and improve product maturity by finishing the service decomposition already tracked in `.production_readiness.md`.

### Ticket E2-T1 - Finish Release And Evidence Application Service Split [ ]

Description: Resolve PCA3-004 and PR-030c by moving product, project, release, artifact, evidence, SBOM, scan, OpenAPI, VEX, decision, exception, and readiness behavior behind a focused internal application service while preserving the public API.

Implementation rules:

- keep tenant checks, idempotency, object-store handling, audit-chain append, and append-only lifecycle invariants unchanged
- add focused service tests or update existing tests to prove wrapper delegation does not bypass authorization
- run `go test ./internal/app ./internal/adapters/httpapi`
- run `make finalize`
- create a Conventional Commit after the gate passes

### Ticket E2-T2 - Split Package, Report, And Portal Behavior [ ]

Description: Resolve PR-030d by moving customer packages, report generation, portal package access behavior, and related package/report workflows behind a focused service boundary.

Implementation rules:

- preserve portal token hash-only handling and package scope/redaction behavior
- do not expose raw evidence payloads, bearer tokens, package tokens, or customer data in errors or logs
- add tests for portal/package/report delegation and tenant isolation
- run `go test ./internal/app ./internal/adapters/httpapi`
- run `make finalize`
- create a Conventional Commit after the gate passes

### Ticket E2-T3 - Replace Remaining Broad Aggregate Persistence Calls [ ]

Description: Resolve PR-030e by replacing broad aggregate `SaveState` synchronization for remaining write families with canonical repository transactions or focused mutation paths.

Implementation rules:

- identify every remaining write family that still relies on whole-state synchronization
- migrate in dependency order and keep compatibility snapshot behavior only where explicitly documented
- test retry/idempotency, rollback, tenant isolation, and restart recovery for each migrated family
- run `make postgres-integration-test`
- run `set -a; . ./.test.env.example; set +a; make production-check`
- create a Conventional Commit after the gate passes

## Epic E3 - Restore Release Candidate Evidence [ ]

Description: Make release evidence reproducible from a clean, green checkout and prepare public release publication.

### Ticket E3-T1 - Clean And Commit The Release-Candidate Workspace [ ]

Description: Resolve PCA3-002 by ensuring the working tree is clean after coherent implementation commits.

Implementation rules:

- use `git status --short --branch` to verify only intended files remain
- do not discard unrelated user changes without explicit instruction
- ensure `.audits` and other ignored evidence remain local unless intentionally tracked
- run `make finalize`
- create Conventional Commits for all coherent implementation groups

### Ticket E3-T2 - Generate The Next Local Signed Release Candidate Package [ ]

Description: Regenerate release evidence from a clean tree using the next RC tag.

Implementation rules:

- choose a new tag that does not already exist locally or publicly
- require `EVYDENCE_TEST_DATABASE_URL` and release signing material
- run `make release-candidate-check TAG=<next-rc>`
- verify `SHA256SUMS`, OpenAPI checksum, migration checksum, coverage output, release notes, manifest, and manifest signature
- create a Conventional Commit only for source changes; do not commit generated ignored artifacts unless release policy requires it

### Ticket E3-T3 - Publish A Public Draft Or RC Release [ ]

Description: Resolve PCA3-003 by publishing signed release artifacts to GitHub when credentials and signing secret are configured.

Implementation rules:

- use the existing release-artifacts workflow or `gh release` process
- keep release status draft or RC unless production exit review explicitly approves stronger wording
- include release notes with assumptions, limitations, and non-claims
- verify with `gh release view <tag>`
- this ticket may be marked external if repository permissions or signing secret custody are unavailable

## Epic E4 - Strengthen Adoption Proof [ ]

Description: Improve confidence that a new evaluator can see the product value without maintainer explanation.

### Ticket E4-T1 - Add A Black-Box End-To-End Demo Check [ ]

Description: Resolve PCA3-005 by turning the end-to-end release-evidence example into an executable smoke test that creates a release, uploads evidence, generates readiness output, and verifies a package or bundle.

Implementation rules:

- keep the test local and deterministic
- use fixtures with no secrets or customer data
- avoid live provider calls
- run the demo check from `make fast-check` only if it is fast; otherwise add a dedicated target
- run `make finalize`
- create a Conventional Commit after the gate passes

### Ticket E4-T2 - Test Python And TypeScript SDK Examples Or Scope Them Down [ ]

Description: Resolve PCA3-007 for SDK credibility by adding executable tests for Python and TypeScript examples, or marking them as illustrative if the repository is not ready to test those runtimes.

Implementation rules:

- keep examples aligned with strict API decoders
- avoid unsupported fields in example payloads
- add `make sdk-check` coverage for any new executable tests
- run `make sdk-check`
- run `make finalize`
- create a Conventional Commit after the gate passes

### Ticket E4-T3 - Validate The Package Viewer With A Fixture [ ]

Description: Resolve PCA3-006 by proving the minimal package viewer can load a sample customer package/readiness fixture without manual inspection.

Implementation rules:

- use deterministic local fixtures only
- do not require external browser services unless a local headless test is added
- test that sensitive raw payload fields are not displayed accidentally
- run the viewer test and `make docs-check`
- create a Conventional Commit after the gate passes

## Epic E5 - Public Trust Follow-Through [ ]

Description: Close the remaining public trust gaps that are within repository or maintainer control.

### Ticket E5-T1 - Verify Public Security And Branch-Protection Settings [ ]

Description: Track external trust controls that cannot be proven by repository files alone.

Implementation rules:

- verify GitHub private vulnerability reporting, branch protection, required checks, and dependency-alert settings through GitHub settings
- document which controls are enabled and which remain external in a tracked status file
- do not claim these are repository-complete if they depend on account settings
- this ticket may be marked external when permissions are unavailable

### Ticket E5-T2 - Update README Proof Pointers After Public RC Publication [ ]

Description: Once a public RC exists, update the README to point to the release artifacts, checksum, manifest signature, CI run, OpenAPI checksum, and limitations.

Implementation rules:

- avoid legal compliance, certification, complete-SBOM, scanner-authority, or secure-release claims
- keep the fastest proof path short
- run `make docs-check`
- run `make release-acceptance`
- create a Conventional Commit after the gate passes
