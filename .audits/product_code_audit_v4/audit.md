## Inspected state

Repository inspected: `/home/aatu/projects/evydence`, public repository
`https://github.com/aatuh/evydence`.

Scope: entire system, with emphasis on whether the VEX-first customer-review
workflow is implemented deeply enough to justify the controlled self-hosted
production-candidate product claim.

Local state:

- Branch: `master`
- Commit: `d080a2e8cf67792a0ec7cf850bd9ab3ddb1113a9`
- Commit date: `2026-06-01T18:35:38+03:00`
- Commit subject: `test(productization): preserve portal coverage gate`
- Local branch: ahead of `origin/master` by 28 commits
- Primary language: Go
- License: `AGPL-3.0-only`

Public state:

- Public repository: `aatuh/evydence`
- Public `origin/master`: `34954f9ee88043b40797a0772a056bdb7f41108e`
- Latest public release: `v0.1.0-rc.5`, prerelease, published
  `2026-06-01T11:48:56Z`
- Public CI and CodeQL are green on `origin/master`.
- Local productization commits, including the package review page and reviewer
  workflow proof, are not yet public until pushed.

Validation evidence used:

- `make production-check`: passed on the current source state, including live
  PostgreSQL, 80.1% coverage, race tests, security scans, restore rehearsal,
  black-box demo, and release signing smoke.
- `make public-release-verify TAG=v0.1.0-rc.5`: passed.
- `make reviewer-package-workflow-check`: passed.
- `make demo-check`: passed.
- `make package-viewer-check`: passed.
- Focused app/API tests for the VEX-first flow and customer portal package view
  passed.

Validation limits:

- No real customer/design-partner release was inspected.
- Public GitHub security settings and private repository settings were not
  fully visible.
- External provider controls and operator deployment controls are not
  source-repository facts.

Confidence: medium-high for repo-local product fitness, medium for public
adoption readiness until local commits are pushed and external proof exists.

## Executive summary

Evydence is now a coherent product, not just an implementation inventory. The
product promise is specific: help product-security and release teams answer
customer CVE/SBOM/provenance questions with traceable, customer-safe release
evidence.

The primary VEX-first workflow is implemented deeply enough for controlled
self-hosted evaluation and internal production after operator review. The repo
can create release evidence, ingest VEX/manual decisions, generate readiness
and package output, verify packages, and show limitations without asking a
reviewer to read the full architecture.

The product is still not broadly production-ready. The public branch trails the
local productization work, there is no non-maintainer pilot proof, multi-writer
API HA is out of scope, and deployment-specific high-trust controls remain
external.

Verdict: Production-usable with caveats. Worth continuing and hardening. Do
not reposition beyond controlled self-hosted production candidate yet.

## Product promise and scope

Primary implemented product claim:

Evydence records, verifies, links, and packages technical release evidence so a
team can answer: "This CVE appears in your SBOM for this release. Are you
affected, why or why not, who approved that answer, and what evidence can we
verify?"

Audience:

- product security and AppSec teams;
- platform and release engineering teams;
- compliance-readiness teams that need technical evidence organization;
- customer/security reviewers receiving scoped evidence packages.

Core workflows:

- create product, release, and artifact records;
- upload SBOM and vulnerability scan evidence;
- import OpenVEX or CycloneDX VEX or record manual vulnerability decisions;
- link decisions, exceptions, approvals, and supporting evidence;
- evaluate release readiness and evidence gaps;
- generate signed release bundles and customer-safe packages;
- verify release/package manifests and audit-chain state;
- review package contents locally or through a token-scoped portal page.

Non-goals:

- legal compliance proof;
- certification;
- complete SBOM proof;
- authoritative scanner truth;
- release-security guarantees;
- broad hosted SaaS or regulated-production readiness.

Evidence sources: README, OpenAPI matrix, app/domain code, HTTP routes, CLI
commands, release scripts, sample package fixtures, docs, migrations,
production gate output, and public rc5 release assets.

## Capability map

| Capability | Status | Evidence | Product implication |
|------------|--------|----------|---------------------|
| VEX-first release-evidence flow | implemented | `TestVEXFirstReleaseEvidenceFlowEndToEnd`, release readiness, decisions, packages | Core buyer question is product-backed. |
| Customer-safe decision export | implemented | package summaries, decision docs, redaction tests | Reviewers get a scoped answer without raw payload exposure. |
| Local package viewer | implemented | `site/package-viewer`, `make package-viewer-check`, docs | Offline review path exists for sample/customer packages. |
| Server-hosted package review page | implemented | `/v1/customer-portal/package/view`, HTTP tests, OpenAPI matrix | Minimal browser review surface exists without broad UI. |
| Reviewer workflow proof | implemented | `make reviewer-package-workflow-check`, `docs/how-to/review-customer-package.md` | A reviewer can verify archive/report without maintainer knowledge. |
| Release evidence and public RC | implemented | public `v0.1.0-rc.5`, signed manifests, checksums, `make public-release-verify` | Public install/verification proof exists. |
| CI release-evidence path | implemented | GitHub/GitLab examples, CLI preflight, local CI simulation | First CI integration is practical. |
| Production runtime profile | implemented with caveats | PostgreSQL, object storage, worker, Helm, Compose, production-check | Suitable for controlled single-writer self-hosted deployments. |
| Multi-writer API HA | out-of-scope | production readiness docs | Not a fit for high-availability API writer deployments yet. |
| Design-partner proof | unproven/external | backlog E8 | Main remaining productization gap. |
| External provider custody/WORM/SSO proof | external | external controls matrix | Operators must provide deployment-specific evidence. |

## Practical claim tests

| Claim | Test | Expected | Observed | Result | Implication |
|-------|------|----------|----------|--------|-------------|
| The controlled self-hosted production gate is real | `make production-check` with `.test.env.example` | Live Postgres, security, coverage, race, restore, release-signing checks pass | Passed; coverage 80.1% | pass | Production-candidate claim has a strong local gate. |
| Public rc5 release assets are verifiable | `make public-release-verify TAG=v0.1.0-rc.5` | Checksums and signed release manifest verify | Passed | pass | Public release evidence is credible. |
| Reviewer can verify sample package without maintainer knowledge | `make reviewer-package-workflow-check` | Manifest/archive verify, ZIP extracts safely, report exists, unsafe markers absent | Passed | pass | Customer-review path is no longer only documented. |
| Package viewer remains safe and deterministic | `make package-viewer-check` | Sample package can be rendered without raw secret markers | Passed | pass | Offline UX is supported. |
| VEX-first release evidence flow exposes expected next steps | `go test ./internal/app -run TestVEXFirstReleaseEvidenceFlowEndToEnd -count=1` | Flow reaches review-ready state and exposes idempotent step metadata | Passed | pass | Core workflow is both implemented and guided. |
| Customer portal form rejects unsafe token handling | `go test ./internal/adapters/httpapi -run 'TestCustomerPortalPackageViewHTMLSafety|TestCustomerPortalPackageFormValidation' -count=1` | Query tokens, duplicates, unknown fields, invalid checkbox values, and token leakage fail safely | Passed | pass | Browser package surface has practical input/security checks. |

## Scorecard

| Dimension | Score | Notes |
|-----------|------:|-------|
| Claimed problem alignment | 9.0/10 | The CVE/SBOM/VEX customer question is concrete and matches implemented objects. |
| Core workflow completeness | 8.8/10 | VEX-first evidence, decisions, readiness, bundles, packages, and verification are end to end. |
| Feature richness | 8.7/10 | Broad evidence and report families exist without dominating the primary wedge. |
| Feature depth and usability | 8.2/10 | Reviewer workflow and portal page make the core result usable; broad UI remains intentionally absent. |
| Product focus and coherence | 8.4/10 | README and docs keep the VEX-first path dominant. |
| Domain correctness and invariant fit | 8.7/10 | Append-only, tenant, idempotency, redaction, and non-claim invariants are explicit and tested. |
| Practical claim-test performance | 8.8/10 | Primary gates and user-facing claim tests passed. |
| Production readiness | 8.2/10 | Strong controlled profile; multi-writer and external controls remain out of scope. |
| Integration and contract credibility | 8.5/10 | OpenAPI, CLI, SDKs, CI examples, and release assets are strong. |
| Operability, supportability and debuggability | 8.2/10 | Production gate, runbooks, release validation, troubleshooting, and package checks exist. |
| Positioning and adoption readiness | 8.0/10 | Clear product story; real external adoption proof still absent. |
| Open-source trust and release integrity | 8.1/10 | Public rc5 evidence exists; public Scorecard alert closure awaits push/rerun. |
| Evidence quality and release confidence | 8.4/10 | Tests, release assets, package fixtures, and audits are strong for the candidate profile. |
| Overall | 8.4/10 | Product fulfills the controlled self-hosted VEX-first promise with caveats. |

Confidence: medium-high.

Verdict: Production-usable with caveats.

## Findings by impact

### Product-blocking

- None for repo-local controlled self-hosted candidate scope after E1-E7.

### High leverage

- PCA4-001: Public GitHub state trails the repo-local productization work.
  Evidence: local branch is 28 commits ahead of `origin/master`; public
  code-scanning still shows TokenPermissions alerts that are addressed locally.
  Affected claim/workflow: public trust and adopter evaluation.
  Impact: external users cannot yet see the improved portal/reviewer workflow
  or workflow permission fixes.
  Fix direction: push local commits, rerun public CI/CodeQL/Scorecard, and
  verify alert status.
  Validation plan: `gh run list`, code-scanning alert query, `make
  public-release-verify TAG=<next-rc>`.

- PCA4-002: No real non-maintainer pilot proof exists.
  Evidence: backlog E8 remains external; no case study or design-partner report
  is present.
  Affected claim/workflow: market adoption and buyer confidence.
  Impact: skeptical buyers still see maintainer-generated examples only.
  Fix direction: run one design-partner pilot, sanitize the outcome, and keep
  customer data out of public artifacts.
  Validation plan: approved pilot report and package verification notes.

### Medium

- PCA4-003: Public GitHub description is less sharp than the README.
  Evidence: public description remains `Self-hosted API-first evidence ledger
  for software release compliance readiness`.
  Affected claim/workflow: first impression and market positioning.
  Impact: the public repo does not immediately communicate the VEX-first buyer
  wedge.
  Fix direction: update provider metadata to
  `Self-hosted VEX-first release evidence ledger for customer CVE, SBOM, provenance, and release-review questions.`
  Validation plan: `gh repo view aatuh/evydence --json description`.

- PCA4-004: Broad production claims remain unsupported.
  Evidence: production docs intentionally require one API writer and external
  operator/provider controls.
  Affected claim/workflow: production positioning.
  Impact: overclaiming would reduce trust.
  Fix direction: keep controlled self-hosted production candidate wording.
  Validation plan: `make docs-check`, `make release-acceptance`, audit review.

### Low

- PCA4-005: Operation count references can drift in prose.
  Evidence: `docs/reference/api-contract-matrix.md` reports 186 operations
  while older prose/badge text referenced earlier counts.
  Affected claim/workflow: documentation precision.
  Impact: small trust issue, easy to correct.
  Fix direction: update prose references or generate them from the matrix.
  Validation plan: `make docs-check`, `make openapi-check`.

## Repository trust checklist

| Area | Status | Evidence | Severity | Recommended fix |
|------|--------|----------|----------|-----------------|
| README | Strong | Buyer question, proof path, release evidence, non-claims | Low | Keep operation counts current. |
| Quickstart | Strong | 10-minute evaluator, getting started, CI quickstart | Low | Keep one clear first path. |
| Examples/demo | Strong | sample package, local CI simulation, reviewer workflow check | Low | Add external pilot proof. |
| Tests/CI | Strong locally | production-check passed, public CI green on origin | Medium | Push local commits and rerun public checks. |
| Releases/provenance | Strong | public rc5 verified; signed manifests/checksums present | Low | Cut next RC after local E7/E9 changes. |
| Docs/API/config/ops | Strong | OpenAPI matrix, production docs, runbooks, troubleshooting | Low | Keep generated references aligned. |
| Security/trust files | Adequate | SECURITY, CODEOWNERS, Scorecard/CodeQL, support/governance | Medium | Verify external GitHub security settings. |
| Deployment/upgrade/recovery | Adequate | Helm/Compose/runbooks, production gate restore rehearsal | Medium | External operator deployment proof remains required. |

## Best next fixes

Next 1-2 days:

- Push local productization commits and rerun public CI/Scorecard.
- Verify public code-scanning alert closure.
- Update public GitHub description.

Next 1-2 weeks:

- Cut the next public RC with the portal/reviewer workflow included.
- Run one design-partner pilot or at least a non-maintainer evaluation session.
- Record a sanitized pilot result if permitted.

Next 1-2 months:

- Add more operator proof around target backup/restore, monitoring, incident
  response, and provider custody controls.
- Revisit the single-writer API stance before any broad production language.

## Residual risk and unproven claims

The product is strong enough for controlled self-hosted candidate use, but not
for broad production language. The largest remaining risks are public state not
yet matching local state, lack of external pilot proof, and deployment-specific
provider controls that cannot be implemented entirely inside this repository.

No audit evidence supports legal compliance, certification, complete SBOM
coverage, scanner authority, secure-release guarantees, broad regulated
production, or hosted SaaS readiness.
