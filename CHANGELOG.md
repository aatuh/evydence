# Changelog

All notable public release changes for Evydence are recorded here.

Release notes must distinguish implemented behavior from future intent and must
preserve Evydence’s non-claims: no legal compliance conclusions, no
certification, no complete-SBOM guarantee, no authoritative vulnerability
results, no secure-release guarantee, and no regulator or auditor acceptance.

## Unreleased

Release status: self-hosted production hardening. Current builds are suitable
for evaluation, pilots, and controlled internal production after operator
review. Broad self-hosted production readiness requires the production gate and
exit criteria in `docs/reference/production-readiness.md`.

### Added

- Root legal, governance, security, support, trademark, commercial licensing,
  release-evidence, and changelog metadata.
- Production-readiness profile, production gate, and coverage-threshold gate.

### Known Limits

- Evydence supports compliance readiness and technical evidence organization.
- Operators remain responsible for production PostgreSQL, object storage,
  network policy, TLS, backups, monitoring, external signing, and incident
  response.
- Canonical persistence, async parser replay, API schema precision, CI release
  enforcement, and coverage remain production-hardening work until the
  production gate passes.
