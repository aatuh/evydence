# Changelog

All notable public release changes for Evydence are recorded here.

Release notes must distinguish implemented behavior from future intent and must
preserve Evydence’s non-claims: no legal compliance conclusions, no
certification, no complete-SBOM guarantee, no authoritative vulnerability
results, no secure-release guarantee, and no regulator or auditor acceptance.

## Unreleased

This section records source changes after the current public release candidate.
It does not mean a new release has been cut or that those changes have public
release artifacts.

### Added

- Object payload reconciliation now provides a tenant-scoped, resumable worker
  command with dry-run reporting, conservative lifecycle quarantine/recovery,
  auditable receipts, and bounded reconciliation metrics. Provider-only objects
  are advisory candidates and are never deleted merely because a listing
  reports them; apply mode requires an explicit abandoned-staging age threshold.
- API build identity now records version, commit, build time, dirty state, Go
  version, and a pre-build release-input-manifest digest. Runtime liveness,
  dependency-backed readiness, and instance-admin readiness diagnostics are
  separate surfaces; public readiness omits dependency errors and returns 503
  for required unavailable dependencies.
- Verification responses now use a versioned, conservative assurance-result
  taxonomy and record profile scope, non-secret trust-material identifiers,
  required checks, and limitations. Customer packages include release-scoped
  verification profile summaries when available.
- Customer package reviewer materials now include a proof summary, dossier,
  proof checklist, customer-safe vulnerability-decision context, and a
  token-scoped portal review path.
- VEX import preview and parser-report workflows, decision history, and
  customer-safe decision summaries improve review of vulnerability evidence.
- Rendered API reference, client quickstarts, CI handoff templates, and
  production deployment/HA/operator guidance broaden the evaluation material.
- CI preflight, one-shot release-evidence upload, release-evidence workflow,
  and release security-summary paths add reproducible release-ledger inputs.
- Provider validation, transparency-proof, and cloud-KMS signing gateways add
  explicit integration points without treating provider metadata as trust by
  itself.

### Changed

- The release-evidence, SDK route catalog, API contract matrix, and public API
  operations now record explicit stability classifications for evaluation and
  implementation planning.
- The repository now tracks a scorecard and execution backlog with evidence
  links and external-evidence blockers; these are implementation-tracking
  records, not production or compliance claims.
- Release packaging, black-box artifact checks, source-backed persistence
  inventory, and production-like deployment configuration have been expanded
  for controlled operator evaluation.

### Fixed

- Object-retention verification no longer treats a local policy record as
  provider enforcement. Positive results now retain bounded provider-observation
  metadata; unavailable, incomplete, failed, and stale observations remain
  distinguishable.
- Updated the indirect `golang.org/x/text` dependency to v0.39.0 to remediate
  the reachable invalid-input infinite-loop advisory reported by `make vuln`.
- Cosign metadata assessment can no longer report `passed` from a non-empty
  signature string. The deprecated compatibility route now reports `limited`
  unless stored digest or signature material is missing, and explicitly rejects
  full-verification requests until a verifier and trust policy are configured.
- Customer-package archive and manifest validation rejects unsafe entries and
  duplicate JSON keys before package contents are trusted.
- Customer package reports include a Content Security Policy, and archive
  manifest comparison is validated before comparison results are reported.

## v0.1.0-rc.6 - historical local tag record (2026-06-01)

The local Git checkout contains annotated tag `v0.1.0-rc.6` (tag object
`742703baccad1726d2ca939b0ec7119c28cba3d4`) pointing to commit
`d4155b4007a4daf8ed0bd908e90792c69ade188e`. The repository does not contain
enough checked public-release evidence to state whether that tag was published
or withdrawn. It is retained here as local history only; use `v0.1.0-rc.7` for
the current public release candidate.

## v0.1.0-rc.7 - 2026-06-01

Release status: controlled self-hosted production candidate. This prerelease is
not a stable release and does not claim legal compliance, certification,
complete SBOM coverage, authoritative vulnerability truth, secure releases, or
auditor/regulator acceptance.

See the release evidence index and public-release verification command for the
current evidence and limitations associated with this release candidate.
