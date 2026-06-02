# Internal Production-Readiness Exit Checklist

This checklist defines what must be true before Evydence can say the
repository-local production-readiness and productization work from the current
analysis is complete. It does not make Evydence legally compliant, certified,
complete-SBOM-proven, scanner-authoritative, auditor-ready without review, or
secure-release-guaranteed.

## Required Internal State

- [ ] Every repository-local backlog ticket from the current
  production/productization analysis is marked complete only after
  implementation, documentation, validation, and commit.
- [ ] Every completed ticket has a Conventional Commit in Git history.
- [ ] Every behavior change updates relevant tests, docs, examples, OpenAPI,
  migrations, release evidence, SDKs, or deployment assets when applicable.
- [ ] No known repo-local production-readiness finding is unmapped in
  [Production readiness traceability](production-readiness-traceability.md).
- [ ] Ignored/local audit files are not required for public documentation to be
  understandable.

## Required Gates

- [ ] `make finalize` passes.
- [ ] `make docs-check` passes.
- [ ] `make release-acceptance` passes.
- [ ] `make marketing-site-check` passes.
- [ ] `make package-viewer-check` passes.
- [ ] `make public-release-verify TAG=v0.1.0-rc.7` passes when public release
  access is available.
- [ ] `make production-check` passes when `EVYDENCE_TEST_DATABASE_URL` and
  release signing material are available.

If live PostgreSQL, GitHub release access, provider credentials, or external
signing/verification services are unavailable, record that as an external
evidence gap. Do not silently count a skipped live dependency as an internal
pass.

## Product-Language Checks

- [ ] Public docs avoid claims that Evydence provides legal compliance,
  certification, complete SBOM proof, authoritative scanner results,
  regulator/auditor acceptance without review, or secure-release guarantees.
- [ ] Release evidence is described as reproducibility, integrity,
  traceability, assumptions, gaps, exceptions, and limitations.
- [ ] Commercial pages state deliverables, support boundaries, exclusions, and
  non-claims without public pricing unless intentionally added later.

## External-Item Status

Before assigning a maximum public production-readiness score, every external item must have a current owner and status:

- [ ] public release state and release-asset availability;
- [ ] design-partner, pilot, or adoption proof;
- [ ] target production environment validation;
- [ ] live provider integration validation;
- [ ] hosted rendered API-doc and GitHub Pages/domain health;
- [ ] GitHub private vulnerability reporting or equivalent private intake;
- [ ] branch protection, required checks, Scorecard, code-scanning, secret
  scanning, push protection, and Dependabot security settings;
- [ ] external security review;
- [ ] analytics privacy/account setting verification.

## Closeout Rule

The repository-local work can be called internally complete only after the
checklist above is satisfied, a fresh production-readiness audit finds no new repo-local remediation,
and any remaining blockers are explicitly external.
Public status must remain conservative until external evidence also supports a
stronger claim.
