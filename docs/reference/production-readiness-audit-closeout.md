# Production Readiness Audit Closeout

This closeout records a fresh repository-local production-readiness audit after
the internal backlog pass. It is not release marketing, legal compliance proof,
certification, complete SBOM proof, authoritative vulnerability coverage, or a
secure-release guarantee.

## Latest Visible State Inspected

| Item | Evidence |
| --- | --- |
| Local repository | `/home/aatu/projects/evydence` |
| Local branch and commit | `master` at `041465bc48f7a8ea3d0536db423c617d9c8e026d` (`docs(production): add internal exit checklist`) |
| Public repository | `https://github.com/aatuh/evydence`, public, default branch `master`, AGPL-3.0 |
| Public branch state | GitHub reported latest pushed public `master` behind local by 32 commits at audit time. |
| Latest release checked | `v0.1.0-rc.7`, public prerelease published June 1, 2026, with archives, checksums, OpenAPI checksum, migration checksum, coverage, release summary, SBOM/provenance metadata, signed manifest, and manifest signature. |
| Public CI checked | Recent public CI, Marketing Site Pages, and CodeQL runs were visible as passing for the latest pushed public `master` state. |
| Verification run during audit | `make public-release-verify TAG=v0.1.0-rc.7` passed. |
| Not inspectable from repo files | GitHub private vulnerability reporting enablement, branch-protection admin-bypass settings, repository secret values, security setting toggles, analytics account settings, real buyer validation, external security review, and target-operator infrastructure. |

Confidence is high for the local repository evidence inspected here and medium
for public production-readiness claims until the current local commits are
pushed and external settings are reverified.

## What The Project Appears To Be

Evydence is a self-hosted release evidence ledger for software teams that need
to organize SBOMs, vulnerability scans, VEX decisions, build/source evidence,
approvals, exceptions, audit-chain records, release bundles, and customer-safe
packages around a specific product release.

The README now communicates the buyer question quickly: customers ask what is
inside a release, whether a CVE affects it, who reviewed the decision, and what
proof can be shared. The project presents as an API server, CLI, worker,
release-verification toolchain, package viewer, and self-hosted deployment
profile. It explicitly avoids claims of legal compliance, certification,
complete SBOMs, authoritative scanner results, regulator/auditor acceptance
without review, or secure releases.

## Production Readiness

Evydence has credible controlled self-hosted production-candidate evidence:

- precise `/v1` OpenAPI contract and generated route matrix;
- API/worker/CLI tests, package viewer checks, release acceptance, and public
  release verification;
- production startup validation, single-writer API stance, scalable worker
  stance, PostgreSQL-backed persistence, migration compatibility, backup/restore
  rehearsal, object-store checks, release signing, and release asset smoke
  checks;
- Helm, Compose, Kubernetes, air-gap, configuration, capacity, observability,
  runbook, and release-validation documentation;
- signed public prerelease artifacts and verifiable release assets.

The strongest honest classification remains controlled self-hosted production
candidate. Broad production for most uses, regulated production, and hosted
SaaS production still require external environment proof, verified repository
security settings, external security review, and operator-specific controls.

Score: 8.2/10.

## Feature Completeness

The core product path is implemented deeply enough for a real controlled pilot:
release evidence ingestion, SBOM/scan/VEX/decision handling, release readiness,
bundles, package generation, package viewer, source/build/deployment/security
evidence families, control reports, package verification, and release evidence
workflows.

Remaining gaps are mostly external adoption/proof or higher-trust deployment
dependencies rather than missing repository-local product surfaces. The product
is not a broad GRC suite, scanner, trust center, hosted SaaS, or legal
compliance engine, and the docs say so.

Score: 8.6/10.

## Security And Open-Source Trust

Strong repo signals include AGPL licensing, governance, contributing, support,
security policy, issue templates, CODEOWNERS, pinned workflows, Dependabot,
CodeQL, Scorecard workflow files, conservative release permissions, release
signing, package verification, redaction leakage checks, and no public claim
that release evidence proves compliance or security.

External trust blockers remain: GitHub private vulnerability reporting must be
verified, branch protection/security settings are account-level checks, public
CI only proves pushed commits, and an independent security review is not present
in repository evidence.

Score: 8.0/10.

## Marketability And Positioning

The product story is now sharp for self-hosted software vendors that face
customer release-security reviews. The demo path, package viewer, commercial
readiness offer, category comparison, and bilingual marketing site make the
value easier to evaluate. The dual-license/support path is plausible without
public pricing or unsupported compliance promises.

The main marketability gap is external validation: no public adoption, customer
story, design-partner quote, or third-party review has been verified.

Score: 8.3/10.

## Differentiation

The repository now explains its boundary next to Dependency-Track, GUAC,
OpenVEX tooling, Vanta, Drata, scanners, trust centers, and internal scripts.
The meaningful differentiation is release-level evidence packaging and
verification: tenant-scoped API records, append-only evidence behavior, package
redaction, signed bundles, audit-chain material, verifier commands, and
customer-safe review surfaces.

The weak point is proof of adoption, not clarity of positioning.

Score: 8.2/10.

## Repository Quality Checklist

| Area | Status | Evidence | Severity | Recommended fix |
| --- | --- | --- | --- | --- |
| README | Strong | Buyer question, demo path, status, release verification, comparisons, non-claims. | Low | Keep status synchronized with release truth. |
| Quickstart | Strong | Tutorials, local demo, GitHub/GitLab examples, SDK quickstarts. | Low | Add real pilot story when available. |
| Examples/demo | Strong | Customer CVE demo, package viewer, local CI simulation, sample package verification. | Low | Keep fixtures in sync with package schema. |
| Tests | Strong | `make finalize`, package, docs, OpenAPI, SDK, release, demo, and worker/app tests. | Low | Continue adding tests for any future public behavior. |
| CI | Adequate public, strong local | Public CI green for pushed state; local branch ahead. | Medium | Push current commits and confirm CI green for current HEAD. |
| Releases/provenance | Strong | `v0.1.0-rc.7` assets verified with `make public-release-verify`. | Low | Re-run after every release candidate. |
| Docs/API/config/ops | Strong | Reference docs, OpenAPI docs, operations/runbooks, production gate, traceability. | Low | Avoid drift from ignored audit files. |
| Docker/deployment | Strong for candidate | Compose, Helm, air-gap, hardened reference deployment, single-writer stance. | Low | Validate target operator environments externally. |
| Security policy | Adequate repo-local | `SECURITY.md` has safe intake rules and non-goals. | Medium | Verify private vulnerability reporting externally. |
| License/contribution/governance | Strong | AGPL, commercial model, governance, contributing, support, CODEOWNERS. | Low | Keep commercial claims conservative. |
| Changelog/versioning | Strong | Release notes, release truth checks, stable exit criteria. | Low | Update on each release-candidate tag. |

## Scorecard

| Dimension | Score | Notes |
| --- | ---: | --- |
| Production readiness | 8.2/10 | Controlled self-hosted candidate with strong repo evidence; not broad production. |
| Feature completeness | 8.6/10 | Core release evidence workflow is complete enough for controlled pilots. |
| Security and open-source trust | 8.0/10 | Strong repo hygiene; provider/account security settings remain external. |
| Marketability and positioning | 8.3/10 | Clear target user, demo, offer, and differentiation; adoption proof absent. |
| Differentiation | 8.2/10 | Release package verification is meaningfully distinct from adjacent tools. |
| Repository evidence quality | 8.8/10 | Extensive checks, docs, release evidence, and traceability. |
| Overall | 8.3/10 | Production-usable with caveats for controlled self-hosted use after operator review. |

Confidence: medium-high for the local repository; medium for public state until
the current local commits are pushed and external settings are verified.

Verdict: Production-usable with caveats.

## Highest-Leverage Next Steps

Next 1-2 days:

- Push the current local commits and confirm public CI, Pages, CodeQL, and
  marketing workflows are green for the same SHA.
- Verify GitHub private vulnerability reporting and branch protection settings.

Next 1-2 weeks:

- Run the paid readiness offer with a real design partner or buyer, then add
  only sanitized, permissioned proof.
- Commission or perform an independent security review and publish a sanitized
  summary.

Next 1-2 months:

- Validate a hardened target environment with external PostgreSQL, object
  storage, backup/restore, monitoring, and signing custody.
- Re-run the stable `v0.1.0` exit criteria against a concrete candidate.

## Fresh Audit Result

The fresh audit found no new repo-local remediation that is not already covered
by completed tickets or existing external blockers. If a later audit finds a
new repository-local issue, add it to the traceability matrix and backlog before
claiming internal closure.
