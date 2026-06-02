# Stable v0.1.0 Exit Criteria

This reference defines the criteria for moving Evydence from the public
release-candidate line to a stable `v0.1.0` tag. It is an engineering and
operator-readiness decision record, not legal compliance proof, certification,
complete SBOM proof, authoritative vulnerability coverage, or a secure-release
guarantee.

## Decision Rule

Do not tag stable `v0.1.0` unless all repo-owned gates in this document pass,
the current release evidence is public and reproducible, and unresolved
limitations are explicitly carried into release notes and status docs.

Stable `v0.1.0` may still be scoped to controlled self-hosted use. It must not
be used to claim broad production readiness, regulated production readiness,
hosted SaaS readiness, legal compliance, certification, complete vulnerability
detection, complete SBOM coverage, or guaranteed release security.

## Required Repo-Owned Gates

Run these gates from a clean checkout for the release candidate that will be
promoted:

```sh
make production-check
make release-acceptance
make public-release-verify TAG=<v0.1.0-rc.N>
make docs-check
make finalize
```

`make production-check` must run with `EVYDENCE_TEST_DATABASE_URL` set to a
disposable PostgreSQL database and must not record skipped live PostgreSQL
checks. The production-check evidence must include coverage threshold output,
live PostgreSQL integration results, migration compatibility, backup/restore
rehearsal, black-box restart persistence, release signing smoke evidence, race
tests, OpenAPI drift checks, docs checks, deployment checks, SDK checks, lint,
gosec, and govulncheck.

`make public-release-verify TAG=<v0.1.0-rc.N>` must verify the public release
candidate artifact set before the stable tag is created. If public artifacts
are missing, stale, unsigned, or unverifiable, stable tagging is blocked.

## Required Release Evidence

The candidate promoted to stable must have a public release evidence set with:

- release archives for the supported target matrix;
- `SHA256SUMS`;
- `openapi.yaml` and `openapi.sha256`;
- `migrations.sha256`;
- `coverage.out`;
- `release-check-summary.txt`;
- release SBOM metadata and release provenance metadata;
- signed `evydence-release-manifest.json`;
- `evydence-release-manifest.sig.json` and the compatibility
  `evydence-release-manifest.sig` alias;
- release notes with supported profile, install and upgrade notes, assumptions,
  limitations, unresolved hardening work, and explicit non-claims;
- links to the CI production-check run, release-artifacts workflow run, CodeQL
  workflow status, and Scorecard evidence where those services are available.

Project-owned container images are stable release evidence only after the
container-image workflow has run for the same tag and produced digest plus
signing evidence. Until then, release archives remain the supported install
source for the stable line.

## Required Documentation Alignment

Before tagging stable, these sources must agree on the current tag, commit,
workflow run, supported profile, and limitations:

- `release/current.json`;
- `README.md`;
- `CHANGELOG.md`;
- `RELEASE_EVIDENCE.md`;
- `docs/reference/release-evidence-index.md`;
- `docs/reference/production-readiness.md`;
- `docs/reference/production-exit-review.md`;
- `docs/reference/release-validation.md`;
- `docs/reference/release-candidate.md`;
- `docs/how-to/install-and-operate.md`;
- `docs/tutorials/evaluate-in-10-minutes.md`;
- release notes for the promoted tag.

Run `scripts/check_release_truth.py` after any release metadata edit. The
stable tag is blocked if public docs, helper defaults, or release metadata
disagree.

## Hard Blockers

Do not tag stable `v0.1.0` while any of these repo-local conditions exist:

- `make production-check`, `make release-acceptance`, `make docs-check`, or
  `make finalize` fails;
- live PostgreSQL checks are skipped in production-check evidence;
- coverage is below the configured threshold;
- release evidence is missing, unsigned, stale, or not publicly verifiable;
- OpenAPI, migration, SDK, deployment, docs, or release-truth drift checks fail;
- backup/restore rehearsal, migration compatibility, or black-box restart
  persistence checks fail;
- release notes omit unresolved limitations or use prohibited compliance,
  certification, complete-SBOM, scanner-authority, or secure-release language;
- the supported one API writer replica stance is unclear or contradicted by
  Helm, Compose, README, production readiness, or release notes;
- public release artifacts and `release/current.json` point at different tags,
  commits, or workflow runs.

External provider and account checks can also block stronger public claims.
Private vulnerability reporting, branch protection, required checks, secret
scanning, push protection, Dependabot security updates, CodeQL, Scorecard,
publication credentials, external security review, design-partner proof, and
provider-specific KMS/HSM/object-lock verification must be either verified for
the target deployment or listed as external limitations. Do not treat repository
source alone as proof of those controls.

## Limitations That May Remain

Stable `v0.1.0` may keep these limitations if they are visible in release
notes, production readiness, and the production exit review:

- one API writer replica is the supported production profile;
- multi-writer API high availability and hosted SaaS production are out of
  scope;
- regulated production needs operator, legal, provider, retention, signing,
  SSO, and object-lock review outside repository source;
- provider-specific KMS/HSM, object-lock, transparency, SSO/group-sync, and
  external security review evidence depends on the operator or provider;
- release evidence supports reproducibility and engineering review, not
  compliance conclusions, certification, complete scanner coverage, or secure
  release claims.

## Stable Release Decision Record

When stable criteria are met, update
`docs/reference/production-exit-review.md` with:

- the stable tag and commit;
- release evidence links and workflow run identifiers;
- production-check and public-release verification results;
- supported deployment profile;
- unresolved limitations;
- external controls that remain operator responsibilities;
- explicit non-claims.

Do not remove this reference after stable tagging. Use it as the regression
checklist for subsequent patch releases until a new release profile supersedes
it.
