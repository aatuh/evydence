# Backlog

Project: Evydence Documentation Remediation V2

Status legend:

- [ ] not done
- [x] done

## Epic E1 - Fix Executable Example Accuracy [x]

Description: Correct the remaining documentation examples that can fail when followed literally, before expanding documentation depth.

### Ticket E1-T1 - Make Release CLI Paths Explicit [x]

Description: Update release-signing and air-gapped command examples so they either invoke the built local binary with an explicit path or state that `evydence` must already be installed on `PATH`.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- preserve product-language constraints and avoid compliance, certification, legal sufficiency, complete-SBOM, scanner-authority, or secure-release claims

Notes:

- Evidence paths: `docs/air-gapped.md`, `docs/release-signing.md`, `cmd/evydence/main.go`.

### Ticket E1-T2 - Repair The GitLab CI Upload Example [x]

Description: Change the GitLab CI example so `evydence-upload-manifest.json` is created, supplied as an artifact, or replaced by a command that uses files produced by the shown pipeline.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- keep provider-trust limitations explicit and do not imply CI metadata is provider-verified unless code proves it

Notes:

- Evidence paths: `docs/gitlab/evydence-release-evidence.gitlab-ci.yml`, `docs/how-to/integrate-ci.md`, `cmd/evydence/main.go`.

## Epic E2 - Synchronize API Documentation With The Contract [ ]

Description: Make the human API reference accurately track the generated OpenAPI contract, reducing route drift for API integrators.

### Ticket E2-T1 - Complete Or Scope The API Endpoint Catalog [x]

Description: Update `docs/api.md` so every implemented OpenAPI path is listed, or clearly mark the catalog as selected routes and point readers to `openapi.yaml` for the complete path list.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- treat `openapi.yaml` and route registration as source of truth, not `.initial_design.md`

Notes:

- Missing paths found in iteration 2 include `/v1/artifact-signatures`, `/v1/commercial-collectors`, `/v1/container-images`, `/v1/dsse-trust-roots`, `/v1/evidence-bundles`, `/v1/incidents`, `/v1/release-candidates`, `/v1/remediation-tasks`, `/v1/reports/incident-package`, `/v1/reports/missing-evidence`, `/v1/sboms/{id}`, and `/v1/vulnerability-scans/{id}` plus related subpaths.
- Evidence paths: `docs/api.md`, `openapi.yaml`, `internal/adapters/httpapi/route_registration.go`, `internal/adapters/httpapi/openapi_operations.go`.

### Ticket E2-T2 - Add An API Catalog Drift Check [ ]

Description: Add a project-owned docs check that detects when paths in `openapi.yaml` are absent from the human API catalog, unless the catalog is explicitly scoped and the check enforces that wording instead.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- prefer a simple deterministic check under an existing Make target before adding new tooling

Notes:

- Evidence paths: `Makefile`, `docs/api.md`, `openapi.yaml`, `docs/reference/openapi.md`.

## Epic E3 - Improve Copy-Paste Task Support [ ]

Description: Tighten remaining examples so developers can use the docs without inferring imports, setup, or validation behavior.

### Ticket E3-T1 - Add SDK Setup Context [ ]

Description: Add minimal import/package setup context to the Go, TypeScript, and Python SDK examples, including any necessary imports used by the snippets.

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

### Ticket E3-T2 - Add Lightweight Documentation Example Checks [ ]

Description: Extend documentation validation with cheap checks for CLI command names, workflow example prerequisites, or documented generated files so example drift is caught before release.

Implementation rules:

- implement the ticket in the smallest sensible step
- run `make finalize` after completing the ticket, or an equivalent quality toolkit if `make finalize` is unavailable
- ensure the quality check covers testing, formatting, linting, and other relevant validation for the repository
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after the ticket is actually complete
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- do not require live external services for the default docs check

Notes:

- Evidence paths: `Makefile`, `docs/tutorials/getting-started.md`, `docs/air-gapped.md`, `docs/release-signing.md`, `docs/github-actions/release-evidence-workflow.yml`, `docs/gitlab/evydence-release-evidence.gitlab-ci.yml`.
