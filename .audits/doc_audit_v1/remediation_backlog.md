# Backlog

Project: Evydence Documentation Remediation

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Restore Documentation Navigation [x]

Description: Make the documentation entrypoints complete and dependency-safe so readers can find the right guide before deeper rewrites happen.

### Ticket E1-T1 - Expand The Documentation Portal Map [x]

Description: Update the docs portal navigation to include the existing collector, GitHub Actions, GitLab CI, SDK, Kubernetes, air-gapped, release-signing, production-hardening, OpenAPI, worker, and release-validation documents without duplicating their content.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep product language within Evydence constraints and avoid compliance, certification, legal sufficiency, complete-SBOM, scanner-authority, or secure-release claims

Notes:

- Evidence paths: `docs/README.md`, `docs/collectors/source-snapshots.md`, `docs/github-actions/release-evidence-workflow.yml`, `docs/gitlab/evydence-release-evidence.gitlab-ci.yml`, `docs/sdk/README.md`, `docs/kubernetes.md`, `docs/air-gapped.md`.

### Ticket E1-T2 - Consolidate Canonical Command References [x]

Description: Choose canonical docs for release validation and local operations, then replace repeated command explanations in secondary docs with concise links.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep one source of truth for each command family and link to it from README/how-to pages

Notes:

- Evidence paths: `README.md`, `docs/how-to/install-and-operate.md`, `docs/operations.md`, `docs/reference/release-validation.md`, `Makefile`.

## Epic E2 - Make First-Run Task Support Real [x]

Description: Give first-time developers and API integrators a runnable path from local startup to useful evidence output.

### Ticket E2-T1 - Rewrite The Getting Started Tutorial As A Complete Evidence Flow [x]

Description: Replace the current startup-only tutorial with a runnable flow that starts the API, captures the bootstrap secret, creates minimal product/project/release resources, uploads representative evidence, and reads a readiness or report response.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- include exact commands, representative JSON, expected status codes, and expected limitations
- do not claim the flow proves compliance, certification, legal sufficiency, complete SBOM coverage, scanner authority, or a secure release

Notes:

- Evidence paths: `docs/tutorials/getting-started.md`, `docs/api.md`, `openapi.yaml`, `cmd/evydence-api/main.go`.

### Ticket E2-T2 - Add A Minimal API Integration Workflow [x]

Description: Add a workflow-oriented API guide or section that explains authentication, idempotency, request envelopes, error shape, core resource setup, evidence upload, and readiness/report retrieval.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- cite `openapi.yaml` as the generated contract but keep examples checked against implemented route behavior

Notes:

- Evidence paths: `docs/api.md`, `openapi.yaml`, `internal/adapters/httpapi/route_registration.go`, `internal/adapters/httpapi/openapi_operations.go`.

### Ticket E2-T3 - Link CI Workflow Examples From The Main Docs [x]

Description: Add navigation and short prerequisite notes for the GitHub Actions, composite action, GitLab CI, source snapshot, and collector supply-chain examples.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- make provider-trust limitations explicit and avoid suggesting uploaded CI metadata is provider-verified unless code proves it

Notes:

- Evidence paths: `docs/github-actions/release-evidence-workflow.yml`, `docs/github-actions/upload-build/action.yml`, `docs/gitlab/evydence-release-evidence.gitlab-ci.yml`, `docs/collectors/source-snapshots.md`, `docs/collectors/supply-chain.md`.

## Epic E3 - Improve Human API And SDK References [x]

Description: Make the API and SDK documentation usable without forcing readers to inspect Go internals or a minified generated contract for common tasks.

### Ticket E3-T1 - Restructure The API Reference Around Core Workflows [x]

Description: Rework the API reference so high-value workflows have request examples, response examples, idempotency notes, scope notes, and error examples before the broad endpoint catalog.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep `openapi.yaml` as the contract source and mark any design-only behavior as intent, not implemented behavior

Notes:

- Evidence paths: `docs/api.md`, `openapi.yaml`, `docs/reference/openapi.md`.

### Ticket E3-T2 - Make The OpenAPI Contract Reviewable [x]

Description: Improve generated OpenAPI documentation usability by adding guidance or tooling output that makes the contract easier to inspect, including schema/response limitations that remain.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- do not hand-edit generated `openapi.yaml` unless the generation workflow is intentionally changed and checked

Notes:

- Evidence paths: `openapi.yaml`, `cmd/openapi/main.go`, `Makefile`, `docs/reference/openapi.md`.

### Ticket E3-T3 - Expand SDK Usage Documentation [x]

Description: Add one minimal usage example each for Go, TypeScript, and Python, including idempotency-key handling, error behavior, current wrapper limitations, and OpenAPI generation expectations.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep SDK claims limited to the committed lightweight wrappers unless generated clients are added

Notes:

- Evidence paths: `docs/sdk/README.md`, `sdk/go/evydence/client.go`, `sdk/typescript/client.ts`, `sdk/python/evydence_client.py`.

## Epic E4 - Separate Operator References From Runbooks [x]

Description: Reduce operations-doc drift by creating focused operator references for configuration, worker behavior, deployment verification, and production caveats.

### Ticket E4-T1 - Add A Canonical Configuration Reference [x]

Description: Document all current environment example files and runtime variables in one reference, including which file is for Compose dependencies, API runtime, and live PostgreSQL tests.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- state clearly that example secrets are placeholders and must not be used for production

Notes:

- Evidence paths: `.env.example`, `.api.env.example`, `.test.env.example`, `docs/operations.md`, `docs/reference/release-validation.md`.

### Ticket E4-T2 - Split Operations Into Focused References Or A Clear Operator Index [x]

Description: Reorganize `docs/operations.md` so configuration, local dependencies, worker behavior, CI/CLI ingestion, integrity operations, portal tokens, SSO sessions, and release validation are easy to find and maintain.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- preserve safe logging, token-handling, trust-boundary, and limitations guidance during the split

Notes:

- Evidence paths: `docs/operations.md`, `docs/reference/worker-outbox.md`, `docs/explanation/trust-model.md`.

### Ticket E4-T3 - Add Deployment Verification Checklists [x]

Description: Add concrete verification steps and expected outcomes for Compose, Helm, air-gapped package verification, backup pairing, and production config rejection behavior.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep deployment language about hardening and evidence organization, not certification or secure-release conclusions

Notes:

- Evidence paths: `docs/kubernetes.md`, `docs/air-gapped.md`, `docs/production-hardening.md`, `deploy/helm/evydence/values.yaml`, `deploy/airgap/manifest.yaml`, `docker-compose.yml`.

## Epic E5 - Reduce Drift In High-Level Product Docs [x]

Description: Make the top-level and architecture docs easier to maintain as implementation changes.

### Ticket E5-T1 - Rewrite README Capabilities Into Stable Groups [x]

Description: Replace the long current-implementation bullet with grouped capability sections and links to detailed docs, while preserving accurate implementation status.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- verify every implementation claim against current files, tests, OpenAPI, or docs rather than `.initial_design.md` alone

Notes:

- Evidence paths: `README.md`, `docs/api.md`, `openapi.yaml`, `.initial_design.md`, `.implementation_increments.md`.

### Ticket E5-T2 - Refactor Architecture Boundaries Into Shorter Subsections [x]

Description: Break the dense security-boundaries section into smaller subsections for tenant/auth, storage, append-only behavior, verification/trust, operations, and limitations.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- preserve the distinction between implemented behavior, trust assumptions, and roadmap limitations

Notes:

- Evidence paths: `docs/architecture.md`, `docs/explanation/trust-model.md`, `internal/app`, `internal/adapters`.

### Ticket E5-T3 - Add A Documentation Drift Guard For Navigation And Examples [x]

Description: Extend docs validation so canonical docs and important workflow examples remain linked and product-claim guardrails continue to run.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep the guard small and project-owned; do not introduce heavy documentation tooling without clear value

Notes:

- Evidence paths: `Makefile`, `docs/README.md`, `docs/github-actions/release-evidence-workflow.yml`, `docs/gitlab/evydence-release-evidence.gitlab-ci.yml`, `docs/sdk/README.md`.
