## Latest visible state inspected

Repository: `aatuh/evydence`, local checkout
`/home/aatu/projects/evydence`.

Audit scope: public repository plus local checkout readiness for the controlled
self-hosted release-candidate profile. This audit was run after the
productization E1-E7 repo-local backlog closed.

Local state inspected:

- Branch: `master`
- Local commit: `d080a2e8cf67792a0ec7cf850bd9ab3ddb1113a9`
- Local commit date: `2026-06-01T18:35:38+03:00`
- Local commit subject: `test(productization): preserve portal coverage gate`
- Local branch state: ahead of `origin/master` by 28 commits at audit time
- Primary language: Go
- Package manifests: `go.mod`, `go.sum`
- License: `AGPL-3.0-only`

Latest visible public state inspected with `gh`:

- Repository: `https://github.com/aatuh/evydence`
- Visibility: public
- Archived: false
- Public description:
  `Self-hosted API-first evidence ledger for software release compliance readiness`
- Public topics include `release-evidence`, `sbom`, `vex`,
  `supply-chain-security`, `vulnerability-management`, and
  `compliance-readiness`
- Public `origin/master` commit:
  `34954f9ee88043b40797a0772a056bdb7f41108e`
- Public `origin/master` commit date: `2026-06-01T14:53:58+03:00`
- Latest public release: `v0.1.0-rc.5`, prerelease, published
  `2026-06-01T11:48:56Z`
- Public release assets include platform archives, `SHA256SUMS`,
  `openapi.yaml`, `openapi.sha256`, `migrations.sha256`, `coverage.out`,
  `release-check-summary.txt`, release SBOM/provenance metadata, release
  notes, signed release manifest, manifest signatures, and container-image
  evidence.
- Latest visible public CI for `origin/master`:
  - `CI` run `26753278348`: success
  - `CodeQL` run `26753278319`: success
  - `Container Image` run `26752805538`: success for
    `d5098c635ee7b171dac3a449ba7ca2e30d8b0c16`
  - `OpenSSF Scorecard` run `26748354206`: success for
    `d5098c635ee7b171dac3a449ba7ca2e30d8b0c16`
- Public code-scanning alerts still visible before the local workflow fixes are
  pushed:
  - Scorecard `TokenPermissionsID` at
    `.github/workflows/container-image.yml:17`
  - Scorecard `TokenPermissionsID` at
    `.github/workflows/release-artifacts.yml:27`

Local checks inspected or run after productization work:

- `make production-check`: passed on the current source state before the final
  coverage-test commit, including live PostgreSQL, release-check, lint, gosec,
  govulncheck, race tests, migration checks, backup/restore rehearsal,
  coverage at `80.1%`, black-box demo, and release signing smoke test.
- `make fast-check`: passed.
- `make release-acceptance`: passed.
- `make public-release-verify TAG=v0.1.0-rc.5`: passed.
- `make reviewer-package-workflow-check`: passed.
- Targeted coverage tests added for the customer portal package view and
  VEX-first release-evidence flow passed.

External/visibility limits:

- Local E1-E7 productization fixes are not yet visible on public GitHub until
  the 28 local commits are pushed and public workflows rerun.
- Private vulnerability reporting, secret scanning, push protection, repository
  secret values, branch protection admin bypass state, and external provider
  settings cannot be fully proven from source files.
- No external design-partner deployment or real customer review package was
  inspected.
- KMS/HSM custody, broad WORM/object-lock enforcement, live SSO provider
  behavior, production backups, monitoring, and incident-response proof remain
  operator/provider responsibilities.

Confidence: medium-high for the local checkout and public release evidence,
medium for the current public-repository posture until local fixes are pushed
and public alerts are re-evaluated.

## What the project appears to be

Evydence is a self-hosted, API-first release evidence ledger for product
security, AppSec, platform, release engineering, and compliance-readiness teams
that need to answer customer CVE, SBOM, provenance, VEX, exception, approval,
and release-review questions.

The product shape is now clear:

- a `/v1` HTTP API with OpenAPI and SDK wrappers;
- a CLI for upload, verification, release evidence, and CI preflight;
- PostgreSQL plus object storage plus worker/outbox runtime;
- signed release bundles, evidence bundles, customer packages, and package
  verification paths;
- local package viewer and minimal token-scoped customer package view for
  reviewer workflows;
- Compose, Helm, air-gapped, public release, and operational documentation.

The README communicates the target user and core buyer question quickly:
"This CVE appears in your SBOM. Are you affected, why, who approved it, and
what can I verify?" That is a credible product wedge. The repository also keeps
non-claim language visible: Evydence supports compliance readiness and
technical evidence organization, but does not prove legal compliance,
certification, complete SBOMs, scanner authority, or release security.

## Production readiness

Assessment: production-usable with caveats for controlled self-hosted
evaluation, pilots, and controlled internal production after operator review.
It is not broadly production-ready, regulated-production-ready, or SaaS-ready.

Strong evidence:

- Public `v0.1.0-rc.5` release assets are published and locally verified with
  `make public-release-verify TAG=v0.1.0-rc.5`.
- The local production gate passes with live PostgreSQL, 80%+ coverage, race
  tests, lint, gosec, govulncheck, migration compatibility, restore rehearsal,
  black-box demo, and release-signing smoke proof.
- Public CI and CodeQL passed on the latest pushed public commit.
- The public API contract has 186 precise `/v1` operations and zero broad
  operations.
- Production startup rejects unsafe defaults, in-process production state,
  unsupported writer mode, writer replicas above one, missing production
  persistence, local plaintext signing-key mode, and bootstrap-secret printing.
- PostgreSQL relational-only production load and focused relational write paths
  cover critical state plus release/evidence core; compatibility snapshots
  remain a migration/recovery/local compatibility path, not the default
  production source of truth.
- Worker/outbox, object-store replay, parser side effects, restore checks,
  package verification, and release evidence verification have project-owned
  gates.
- Helm and production docs intentionally support one API writer replica and
  scalable worker replicas through PostgreSQL outbox locking.
- Security, support, governance, contribution, code of conduct, issue
  templates, Dependabot, Scorecard, CodeQL, CODEOWNERS, and maintainer review
  policy files exist.

Remaining caveats:

- Public GitHub still shows two Scorecard token-permission alerts until the
  local workflow fixes are pushed and Scorecard/code-scanning re-evaluate.
- The public GitHub description is still compliance-readiness-first rather
  than the sharper VEX-first buyer wording.
- Multi-writer API HA is intentionally unsupported.
- A real design-partner pilot and external case study remain unavailable.
- External provider/security settings and operator deployment controls are not
  source-repository facts.

Score: 8.3/10.

## Feature completeness

The implemented product is feature-complete enough for a real controlled
VEX-first release-evidence pilot:

- products, projects, releases, artifacts, SBOMs, vulnerability scans, OpenVEX
  and CycloneDX VEX, decisions, exceptions, waivers, approvals, bundles,
  packages, controls, reports, source/build/deployment/incident evidence, and
  security evidence families exist;
- customer package output is redaction-aware and now has both offline local
  viewer and minimal token-scoped server review paths;
- the VEX-first workflow is tested end to end and includes customer-safe
  decision summaries, supporting context, package verification, and audit-chain
  checks;
- CI integration is practical through preflight CLI checks, GitHub/GitLab
  examples, and local CI simulation.

Feature depth is now stronger than the previous audit because the primary
customer-review path no longer requires maintainer explanation: a reviewer can
inspect package limitations, verify the manifest/archive, view report HTML,
and download through a scoped portal page.

Remaining feature caveats are mostly external or deliberate scope limits:
design-partner proof, broad hosted portal UX, multi-writer HA, direct
provider-management clients, and deployment-specific custody/WORM evidence.

Score: 8.6/10.

## Security and open-source trust

Strong signals:

- AGPL license, security policy, support policy, governance, contributing
  rules, code of conduct, trademarks, release evidence docs, issue/PR
  templates, CODEOWNERS, Dependabot, CodeQL, Scorecard, gosec, govulncheck, and
  release acceptance checks exist.
- API keys, SSO sessions, portal tokens, package tokens, release signing keys,
  and sensitive report/package fields use hash-only, redaction-aware, or
  non-secret representations where exposed.
- Customer portal package view rejects query tokens, requires form bodies,
  uses `no-store`, `no-referrer`, CSP, frame denial, no cookies, and HTML
  escaping.
- Package viewer and reviewer workflow checks reject raw payload refs, object
  keys, private key markers, token hashes, internal notes, and script tags.
- Public release assets are signed and checksummed, and release manifests
  verify locally.

Weak or external signals:

- Current public code-scanning alerts still show broad token-permission
  findings until the local workflow fixes land publicly.
- Branch protection and private vulnerability reporting settings require
  maintainer/provider verification.
- Native HSM, direct cloud-provider management, external transparency,
  object-lock enforcement, and real provider custody proof are not repo-local
  guarantees.

Score: 8.1/10 locally, with public confidence capped until the alert closure is
verified.

## Marketability and positioning

The current product story is marketable enough for serious evaluation:
self-hosted VEX-first release evidence for customer CVE, SBOM, provenance, and
release-review questions. The value proposition is specific, concrete, and
tied to implemented behavior instead of broad compliance automation.

The fastest proof path, public rc5 release evidence, sample customer package,
local package viewer, server-hosted package review page, reviewer workflow
check, and CLI verifier form a credible first-ten-minutes experience.

The biggest market gap is not another feature. It is external adoption proof:
one non-maintainer team using Evydence on a real release and producing a
sanitized customer/security-review result.

Score: 8.2/10.

## Differentiation

Direct and adjacent alternatives:

- Dependency-Track, OWASP CycloneDX tooling, and scanner platforms handle SBOM
  and finding workflows well, but are not primarily release-evidence ledgers
  with signed customer packages and audit-chain verification.
- Vanta, Drata, and other GRC platforms address broader compliance workflows,
  but are not self-hosted technical release-evidence ledgers and should not be
  treated as direct replacements.
- Sigstore/cosign/in-toto/SLSA tools verify signatures and provenance, but do
  not organize the broader release/customer-review evidence graph.
- The practical alternative is in-house glue: object storage folders, scanner
  exports, CI logs, spreadsheets, tickets, and custom reports.

Meaningful differentiation:

- VEX-first release review answer, not just scanner output.
- Self-hosted API and OpenAPI contract.
- Tenant-scoped append-only evidence and audit chains.
- Signed release bundles and customer-safe packages with limitations.
- Reviewer workflow proof and offline verification.

Weak differentiation:

- Without design-partner proof, external users still have to trust the
  maintainer's examples.
- Broad evidence-family breadth can look similar to a GRC inventory unless the
  VEX-first release-evidence path remains dominant.

## Repository quality checklist

| Area | Status | Evidence | Severity | Recommended fix |
|------|--------|----------|----------|-----------------|
| README | Strong | Buyer question, proof path, release evidence, non-claims | Low | Update public repo description to match VEX-first positioning. |
| Quickstart | Strong | Getting started, 10-minute evaluator, CI quickstart | Low | Keep first path short as APIs expand. |
| Examples/demo | Strong | End-to-end sample package, demo checks, reviewer workflow check | Low | Add real pilot proof externally. |
| Tests | Strong | `make production-check` passed with 80.1% coverage and live Postgres | Low | Keep threshold above 80 as features are added. |
| CI | Adequate | Public CI/CodeQL green on `origin/master`; local CI workflow fixes pending push | Medium | Push local workflow fixes and verify Scorecard alert closure. |
| Releases/provenance | Strong | Public rc5 release assets, signatures, checksums, SBOM/provenance metadata | Low | Publish next RC after local E7/E9 commits are pushed. |
| Docs/API/config/ops | Strong | OpenAPI matrix, operations, release, production, Kubernetes, runbooks | Low | Keep operation-count references generated or checked. |
| Docker/deployment | Adequate | Dockerfile, Compose, production-like Compose, Helm, air-gap docs | Medium | Real operator deployment proof remains external. |
| Security policy | Adequate | SECURITY, support, intake, non-secret reporting rules | Medium | Verify GitHub private reporting and secret scanning settings. |
| License/contribution/governance | Strong | AGPL, commercial, governance, contributing, CODEOWNERS | Low | None repo-local. |
| Changelog/versioning | Strong | rc5 changelog/release notes and release-candidate docs | Low | Update next release notes after E7/E9 changes. |

## Scorecard

| Dimension | Score | Notes |
|-----------|------:|-------|
| Production readiness | 8.3/10 | Local production gate passes; controlled single-writer profile is honest. |
| Feature completeness | 8.6/10 | VEX-first release-evidence path is end-to-end and reviewable. |
| Security and open-source trust | 8.1/10 | Strong local posture; public Scorecard alert closure still pending push/rerun. |
| Marketability and positioning | 8.2/10 | Clear buyer question and proof path; public description still generic. |
| Differentiation | 8.1/10 | Strong release-evidence package angle versus scanner/GRC/status quo. |
| Repository evidence quality | 8.6/10 | Release assets, gates, docs, contracts, and examples are substantial. |
| Overall | 8.3/10 | Meets target for controlled self-hosted candidate, not broad production. |

Confidence: medium-high.

Verdict: Production-usable with caveats.

## Highest-leverage next steps

Next 1-2 days:

- Push the 28 local productization commits, rerun public CI/CodeQL/Scorecard,
  and verify the two public TokenPermissions alerts close.
- Update the public GitHub description to the VEX-first positioning.
- Cut the next public RC after the local E7/E9 changes are visible and release
  evidence is regenerated.

Next 1-2 weeks:

- Run a non-maintainer design-partner pilot on one real release and produce a
  sanitized lessons-learned note.
- Verify GitHub private vulnerability reporting, secret scanning, push
  protection, and branch-protection settings with maintainer access.
- Keep production-check, public-release verification, and reviewer workflow
  checks as required release gates.

Next 1-2 months:

- Decide whether to continue with single-writer self-hosted production as the
  long-term v1 profile or design a reviewed multi-writer path.
- Add stronger external deployment proof for backup/restore, monitoring,
  incident response, KMS/HSM custody, and WORM/object-lock controls.
- Keep the top-level product story narrow around VEX-first release evidence
  while deeper evidence families mature.

## README/product-page rewrite advice

Suggested one-sentence pitch:

`Self-hosted VEX-first release evidence ledger for customer CVE, SBOM, provenance, and release-review questions.`

Keep the README first screen focused on:

- the concrete customer CVE question;
- the fastest proof path;
- public release evidence and package verification;
- limitations and non-claims.

Keep broad evidence families in the capability map and architecture docs, not
the first-screen pitch.

## Residual risk and uncertainty

The current local repo is stronger than the public visible branch. Public trust
will not fully reflect this audit until the local commits are pushed and
public CI/code-scanning reruns.

External controls remain unresolved by source code: design-partner proof,
GitHub security settings, repository secrets, KMS/HSM custody, SSO provider
configuration, object-lock enforcement, public transparency services,
operator backup/restore, monitoring, incident response, and legal/audit review.

The correct public status remains controlled self-hosted production candidate.
Do not strengthen to broad production-ready, regulated-production-ready,
hosted-SaaS-ready, compliance-proof, certification, complete-SBOM,
scanner-authoritative, or release-security-guarantee language.
