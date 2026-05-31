## Inspected state

Repository inspected: `/home/aatu/projects/evydence`, public repository `https://github.com/aatuh/evydence`, scope `entire system`.

Local `HEAD`: `842fb053f303b2a78eb3118be6a4536715571215`, commit `feat: add direct cloud kms signers`, commit date `2026-05-31 11:37:01 +0300`.

Public GitHub state verified with `gh`:

- repository: `aatuh/evydence`
- URL: `https://github.com/aatuh/evydence`
- default branch: `master`
- visibility: public
- archived: false
- license: GNU Affero General Public License v3.0
- stars/forks/watchers: `0/0/0`
- pushed at: `2026-05-31T08:41:59Z`
- latest visible CI runs: latest `CI` run for `842fb053...` succeeded
- published releases: none returned by `gh release list`
- public tags: none returned by the GitHub tags API

Local checkout state: dirty and not currently buildable. `git status --short --branch` shows modified tracked files and untracked production-hardening files, examples, docs, workflows, and `internal/app/identity_service.go`. Practical local gates fail because `internal/app/ledger.go` and `internal/app/vex.go` already use `releaseEvidenceService`, but no type or Ledger wrappers exist in the checkout.

Primary languages and manifests: Go module `github.com/aatuh/evydence`, Go 1.25-oriented tooling, shell/Python scripts, Docker/Compose/Helm, TypeScript/Python/Go SDK examples, OpenAPI contract.

Missing visibility: branch protection, required checks, private vulnerability reporting configuration, dependency-alert settings, release signing secrets, live provider credentials, live object-lock settings, production backup rehearsals, and operator deployment evidence cannot be verified from repository files alone.

Validation limits: I ran only local, non-destructive checks. I did not push tags, create releases, call live cloud/KMS/GitHub/GitLab provider APIs, or modify source code.

Confidence: medium-high for the local checkout and public repository metadata; medium for public release/trust posture because GitHub settings are not fully visible.

## Executive summary

Evydence is a coherent and ambitious self-hosted release-evidence ledger. The product promise is sharp enough: organize, verify, package, and report technical release evidence without claiming legal compliance, certification, complete SBOMs, authoritative scanner coverage, or secure releases.

The committed public `HEAD` has a green CI signal and the repository has strong product scaffolding: OpenAPI, docs, CI, Helm, Docker, migrations, SDKs, examples, security metadata, release evidence scripts, and a large API/domain model. That makes the project materially stronger than a prototype.

The current local system, however, is not product-usable because it does not compile. `make fast-check` and `make production-check` both fail immediately with `undefined: releaseEvidenceService`. That blocks the core API, worker, OpenAPI generation, Postgres adapter, and production gate. Until this is fixed, the current checkout cannot honestly be called production-usable.

The second major product issue is release credibility. Local RC tags exist, and docs say a local `v0.1.0-rc.3` evidence package was generated, but there are no public GitHub releases or public tags visible through `gh`. That is acceptable for internal hardening, but not enough for broad public product trust.

Verdict: Promising but not production-ready in the current checkout. The committed public project is close to a controlled self-hosted production candidate, but this working tree is currently a broken release-candidate workspace.

## Product promise and scope

Primary audience: security, AppSec, platform, DevSecOps, and compliance-readiness teams at B2B software companies that need customer-reviewable release evidence while retaining self-hosted control.

Product category: self-hosted API-first release evidence ledger, with CLI, worker, SDK helpers, object storage, PostgreSQL, OpenAPI, Helm, and release evidence packaging.

Core claims inferred from README, docs, OpenAPI, Makefile, scripts, and code:

- documented and implemented in broad shape: collect release evidence such as artifacts, SBOMs, vulnerability scans, VEX, decisions, controls, builds, deployments, incidents, approvals, exceptions, and packages.
- documented and partly tested: preserve tenant-scoped, append-only, tamper-evident records with audit-chain and release-bundle verification.
- documented and partly tested: support durable self-hosted operation with PostgreSQL, object storage, outbox worker, migrations, and production checks.
- documented and partly tested: provide precise `/v1` API contracts, OpenAPI drift checks, SDK wrappers, and examples.
- documented and partly tested: produce signed release-candidate evidence packages with checksums, coverage, OpenAPI checksum, migration checksum, release notes, and release manifest signatures.
- documented non-goal: do not make legal compliance, certification, complete-SBOM, scanner-authority, or secure-release guarantees.

Current critical contradiction: the local checkout cannot run the project-owned gates because a partially applied service split references a missing `releaseEvidenceService`.

## Capability map

| Capability | Status | Evidence | Product implication |
|------------|--------|----------|---------------------|
| API server and worker entrypoints | partial | `cmd/evydence-api`, `cmd/evydence-worker`, `cmd/evydence-migrate`, but current build fails | The intended runtime exists, but current checkout cannot ship. |
| Product/release/evidence ledger | partial | `internal/app/ledger.go` contains release/evidence logic but now references undefined `releaseEvidenceService` | Core workflow is blocked until the refactor is completed or reverted. |
| Identity and tenant boundaries | implemented but mid-refactor | `internal/app/identity_service.go`, service receiver methods in `enterprise.go` | Good direction, but current worktree has not completed adjacent service split. |
| PostgreSQL migrations and adapters | implemented but unverified in current checkout | many migrations, `internal/adapters/postgres`, production gate fails before adapter tests | Strong structure, but current build prevents product proof. |
| Object storage and worker outbox | implemented but unverified in current checkout | filesystem/S3 adapters, worker docs, outbox tests referenced by code | Product surface is credible, current gate failure blocks confidence. |
| OpenAPI contract | implemented but currently unverified | `openapi.yaml`, `cmd/openapi`, matrix docs; `openapi-check` cannot run because build fails | Contract precision is a strength when build is green. |
| Release readiness and reports | implemented but currently unverified | app/domain/docs expose readiness, control coverage, CRA/package reports | Useful product feature set, blocked by build. |
| SDKs and examples | implemented and locally passing for Go path | `go test ./examples/sdk/go ./sdk/go/evydence` passed | Good adoption proof for one SDK path. |
| Production-like Compose | implemented and locally valid config | `docker compose -f compose.production-like.yml config --quiet` passed | Useful operator evaluation path. |
| Helm deployment | implemented | chart has required image tag, single-writer defaults, probes, resources, optional NetworkPolicy | Strong controlled self-hosted posture. |
| Release candidate packaging | partial | local tags exist; public releases/tags absent; `release-candidate-check` blocked by dirty worktree | Not ready to cut a trustworthy release from current checkout. |
| Public open-source trust surface | partial | AGPL, SECURITY, CONTRIBUTING, governance, CI, issue templates, Scorecard workflow exist; no public release/tag/adoption | Good repo hygiene, weak release/adoption proof. |

## Practical claim tests

| Claim | Test | Expected | Observed | Result | Implication |
|-------|------|----------|----------|--------|-------------|
| SDK examples are executable and aligned with API client behavior | `go test ./examples/sdk/go ./sdk/go/evydence` | Go SDK example and client tests pass | Passed | pass | Good adoption proof for Go SDK path. |
| Production-like Compose stack is at least syntactically valid | `POSTGRES_PASSWORD=test MINIO_ROOT_PASSWORD=test EVYDENCE_API_KEY_PEPPER=test-test-test-test docker compose -f compose.production-like.yml config --quiet` | Compose renders without errors | Passed with no output | pass | Deployment config shape is credible. |
| Fast local project gate proves the current checkout is healthy | `make fast-check` | Unit tests, OpenAPI, docs, deploy, and SDK checks pass | Failed at build: `undefined: releaseEvidenceService` in `internal/app/ledger.go` | fail | Current checkout is not shippable. |
| Production gate proves controlled self-hosted readiness | `set -a; . ./.test.env.example; set +a; make production-check` | Production checks pass with live PostgreSQL env | Failed at `make test` with the same build error | fail | Production readiness cannot be claimed for this checkout. |
| Release candidate packaging can produce evidence | `make release-candidate-check TAG=v0.1.0-rc.4` | Clean worktree, production gate, signed package | Failed immediately: `release candidate packaging requires a clean worktree` | fail | Current workspace cannot cut release evidence. |
| Public repository has current CI evidence | `gh run list --repo aatuh/evydence --limit 5 ...` | Latest public `HEAD` has a visible passing CI run | Latest CI for `842fb053...` succeeded | pass | Committed public state is healthier than the dirty local checkout. |
| Public users can install a tagged release | `gh release list --repo aatuh/evydence --limit 10`; GitHub tags API | Public release/tag visible | No releases or tags returned | fail | Public adoption/release trust is not yet established. |

## Scorecard

| Dimension | Score | Notes |
|-----------|------:|-------|
| Claimed problem alignment | 8.5/10 | The problem, audience, and non-claims are coherent and timely. |
| Core workflow completeness | 5.0/10 | The intended workflow is broad, but the current checkout cannot build. |
| Feature richness | 8.5/10 | Very broad evidence/reporting/deployment/API surface. |
| Feature depth and usability | 6.5/10 | Many features appear wired, but broken build and public release absence reduce usable depth. |
| Product focus and coherence | 7.0/10 | Strong center of gravity, but breadth risks shallow productization. |
| Domain correctness and invariant fit | 7.5/10 | Good append-only/tenant/non-claim posture; current refactor gap undercuts confidence. |
| Practical claim-test performance | 4.0/10 | SDK and Compose pass; core gates and release packaging fail. |
| Production readiness | 4.5/10 | Public committed CI is green, but current local production gate fails and public releases are absent. |
| Integration and contract credibility | 7.0/10 | OpenAPI/SDK/CI examples are strong, but current OpenAPI check cannot run. |
| Operability, supportability and debuggability | 6.5/10 | Good docs and scripts; current build break makes operational evidence stale. |
| Positioning and adoption readiness | 7.5/10 | README has a sharper product stance than earlier versions and avoids dangerous claims. |
| Open-source trust and release integrity | 7.0/10 | Strong metadata and CI; no public release/tag/adoption yet. |
| Evidence quality and release confidence | 5.0/10 | Local evidence tooling is strong, but current dirty/broken tree cannot produce release evidence. |
| Overall | 5.5/10 | The current checkout is a credible product workspace but not a usable system until the build is restored. |

Mean dimension score excluding Overall: `(8.5 + 5.0 + 8.5 + 6.5 + 7.0 + 7.5 + 4.0 + 4.5 + 7.0 + 6.5 + 7.5 + 7.0 + 5.0) / 13 = 6.5/10`.

Confidence: medium-high.

Verdict: Promising but not production-ready.

## Findings by impact

### Product-blocking

- PCA3-001: Current checkout does not compile.
  Evidence: `make fast-check` and `make production-check` fail with `undefined: releaseEvidenceService` in `internal/app/ledger.go`.
  Affected claim/workflow: all API, worker, OpenAPI, Postgres, release evidence, and production readiness claims for the current workspace.
  User or operator impact: no one can build or validate this checkout.
  Fix direction: complete the release/evidence service split by adding `releaseEvidenceService` type and Ledger wrappers, or revert the partial receiver rewrite before continuing.
  Validation plan: `go test ./internal/app ./internal/adapters/httpapi ./cmd/evydence-api ./cmd/evydence-worker`, then `make fast-check`, then `make production-check` with live PostgreSQL.

- PCA3-002: Current release-candidate packaging is blocked by dirty working tree.
  Evidence: `make release-candidate-check TAG=v0.1.0-rc.4` fails with `release candidate packaging requires a clean worktree`.
  Affected claim/workflow: reproducible release-candidate evidence.
  User or operator impact: no trustworthy release can be cut from this workspace.
  Fix direction: restore a green build, commit coherent changes, regenerate release evidence from a clean tree.
  Validation plan: `git status --short`, `make release-candidate-check TAG=<next-rc>`, verify manifest signature and checksums.

### High leverage

- PCA3-003: Public release trust is still weak.
  Evidence: `gh release list` and public tags API returned no releases/tags, while local tags `v0.1.0-rc.1` through `v0.1.0-rc.3` exist.
  Affected claim/workflow: public installability, open-source trust, release integrity.
  User or operator impact: external users cannot verify or install a named release without cloning a moving branch.
  Fix direction: after a clean green checkout, publish a draft or public RC release with signed artifacts, checksums, OpenAPI checksum, migration checksum, coverage, release notes, and release evidence.
  Validation plan: `gh release view <tag>`, artifact checksum verification, release manifest verification.

- PCA3-004: Product breadth has outpaced clean service boundaries.
  Evidence: `internal/app/ledger.go` and `internal/app/state.go` remain very broad, and `.production_readiness.md` still tracks PR-030c through PR-030e as open.
  Affected claim/workflow: production maturity under ongoing feature changes and future concurrency hardening.
  User or operator impact: high regression risk and difficult review of tenant/evidence invariants.
  Fix direction: finish release/evidence service split, package/report/portal service split, then replace remaining broad aggregate persistence with focused repository transactions.
  Validation plan: focused service tests, mutation spy tests, Postgres integration tests, production gate.

### Medium

- PCA3-005: Public adoption proof is still absent.
  Evidence: public stars/forks/watchers are `0/0/0`, no releases, no public tags.
  Affected claim/workflow: marketability and buyer trust.
  User or operator impact: skeptical users have no external validation.
  Fix direction: publish RC artifacts, add a concise demo path, record screenshots/terminal outputs, and link release evidence prominently.
  Validation plan: README proof path review, public artifact checks, demo execution.

- PCA3-006: Release/package viewer is useful but still minimal.
  Evidence: `site/package-viewer/index.html` exists, but no tested browser workflow was run in this audit.
  Affected claim/workflow: customer-reviewable evidence packages.
  User or operator impact: package review remains API/file-centric unless the viewer is validated and documented as supported.
  Fix direction: add a deterministic fixture and a browser-free smoke test or Playwright screenshot test for the viewer.
  Validation plan: viewer fixture test and docs link check.

### Low

- PCA3-007: Documentation is strong but risks over-density.
  Evidence: README and docs are comprehensive and conservative, but still long and status-heavy.
  Affected claim/workflow: adoption and first 30-second understanding.
  User or operator impact: interested users may struggle to identify the fastest proof path.
  Fix direction: keep the top README focused on one runnable path and move detailed inventory deeper.
  Validation plan: docs-check plus manual README scan.

## Repository trust checklist

| Area | Status | Evidence | Severity | Recommended fix |
|------|--------|----------|----------|-----------------|
| README | Strong | Clear audience, non-claims, fastest proof path, current limitations | Low | Keep top section shorter after build is restored. |
| Quickstart | Adequate | `docs/tutorials/getting-started.md`, local API docs | Medium | Add a smoke script that proves the exact quickstart on current checkout. |
| Examples/demo | Adequate | end-to-end example, SDK examples, GitHub/GitLab workflows | Medium | Add a single black-box demo check that runs from clean clone to readiness/package output. |
| Tests/CI | Partial | Public CI latest `HEAD` succeeded; current local tests fail to build | Blocker | Restore build and re-run local gates before any release. |
| Releases/provenance | Weak | local RC tags exist; no public releases/tags visible | High | Publish signed RC artifacts after green clean tree. |
| Docs/API/config/ops | Strong | docs portal, API matrix, operations, Kubernetes, config, runbooks | Low | Keep source-of-truth docs aligned after refactors. |
| Security/trust files | Strong | AGPL, SECURITY, CONTRIBUTING, governance, support, issue templates, Scorecard workflow | Medium | Verify public private-vulnerability-reporting settings externally. |
| Deployment/upgrade/recovery | Adequate | Helm, Compose, Dockerfile, runbooks, deploy-check; Compose config passes | Medium | Add a full restore rehearsal artifact and public release image digest. |
| OpenAPI contract | Partial | committed OpenAPI and precision tooling; cannot run now due build failure | High | Restore build, run `make openapi-check` and `make openapi-precision-check`. |
| SDKs | Adequate | Go SDK example tests pass | Medium | Add execution tests for TypeScript and Python examples or scope them as illustrative. |

## Best next fixes

Next 1-2 days:

- Restore the build by completing or reverting the partial `releaseEvidenceService` refactor.
- Run and fix `make fast-check`, then `make production-check` with live PostgreSQL.
- Commit the identity/release service split only when the tree is green.
- Regenerate or revalidate the local RC evidence package from a clean worktree.

Next 1-2 weeks:

- Finish PR-030c and PR-030d service boundaries, then PR-030e focused repository transactions for remaining write families.
- Add a black-box end-to-end demo check that starts the API, uploads release evidence, generates readiness output, and verifies a package.
- Add execution tests for Python/TypeScript SDK examples or clearly label them as illustrative.
- Publish the first public RC with signed artifacts and release evidence.

Next 1-2 months:

- Complete production exit review with backup/restore rehearsal evidence, package viewer verification, public release provenance, and operator deployment notes.
- Decide whether the product stays permanently single-writer for self-hosted deployments or designs a reviewed multi-writer path.
- Add customer/operator feedback or a design-partner case study before claiming broad market readiness.

## Residual risk and unproven claims

The current dirty checkout is the largest risk. Any claim about product readiness, production checks, OpenAPI drift, or release evidence is stale until the compile failure is fixed and the gates are rerun.

Public release trust remains unproven because public releases and tags were not visible. Local release evidence is useful for development, but not a public installability signal.

External controls remain outside repository proof: branch protection, private vulnerability reporting settings, release signing secret custody, cloud KMS/HSM behavior, provider management APIs, public transparency providers, object-lock enforcement, backups, restore rehearsals, and live production deployment review.

The product is worth continuing. The immediate path to a score above 8 is not more features; it is restoring a green checkout, finishing the partial service split, producing clean release evidence, and publishing a public release candidate.
