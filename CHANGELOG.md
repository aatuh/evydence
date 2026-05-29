# Changelog

All notable public release changes for Evydence are recorded here.

Release notes must distinguish implemented behavior from future intent and must
preserve Evydence’s non-claims: no legal compliance conclusions, no
certification, no complete-SBOM guarantee, no authoritative vulnerability
results, no secure-release guarantee, and no regulator or auditor acceptance.

## Unreleased

Release status: controlled self-hosted production candidate hardening. Current
builds are suitable for evaluation, pilots, and controlled internal production
after operator review. Broad self-hosted production readiness, regulated
production, and hosted SaaS production remain out of scope for this status.
Release-candidate tagging requires the production gate and checklist in
`docs/reference/release-candidate.md`.

### Added

- Root legal, governance, security, support, trademark, commercial licensing,
  release-evidence, and changelog metadata.
- Production-readiness profile, production gate, and coverage-threshold gate.
- Release-candidate checklist requiring production-check evidence, checksums,
  signed artifact manifests, release notes, and documented limitations.

### Known Limits

- Evydence supports compliance readiness and technical evidence organization.
- Operators remain responsible for production PostgreSQL, object storage,
  network policy, TLS, backups, monitoring, external signing, and incident
  response.
- Focused relational write paths, HA/multi-writer operation, direct KMS/HSM SDK
  adapters, live provider validation, broader object-lock proof, and final exit
  review remain production-hardening work after the release-candidate gate.
