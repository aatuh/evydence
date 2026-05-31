# Roadmap And Release Cadence

This roadmap keeps public expectations aligned with repository evidence. It
does not make legal compliance conclusions, grant certification, prove SBOM
completeness, treat scanner output as authoritative, or guarantee release
security.

## Current Release Line

The current release line is a controlled self-hosted production candidate. The
supported API deployment profile is one API writer replica with scalable worker
replicas through PostgreSQL outbox locking. Multi-writer API high availability
is not part of the current supported profile.

## Near-Term Focus

- keep the public signed release-candidate line current with checksums, release
  notes, OpenAPI checksum, migration checksum, coverage output,
  production-check summary, SBOM/provenance metadata, and a signed release
  manifest;
- keep public GitHub trust controls active, including required checks, branch
  protection, vulnerability alerts, Dependabot security updates, and private
  vulnerability reporting;
- keep the first evaluation path tied to release artifacts, the end-to-end
  release evidence example, the package viewer, and the release evidence index;
- continue reducing large service surfaces while preserving tenant isolation,
  append-only evidence behavior, and safe error handling.

## Later Production Hardening

- review whether the single API writer profile remains the supported long-term
  posture or whether a multi-writer design is justified by operator demand;
- harden provider-specific KMS/HSM, object-lock/WORM, SSO/group-sync, and
  transparency-proof profiles with deployment-specific evidence and tests;
- publish immutable container image digests if container images become a
  supported install path;
- run production exit reviews only against a concrete release candidate and
  target deployment profile.

## Cadence

Release candidates should be cut only after `make production-check` and the
release-candidate evidence package pass. Public releases should include a clear
support window, upgrade notes, limitations, and known unresolved hardening work.

Community contributions remain selective until the public release, security
intake, branch protection, and review enforcement surfaces are stable.
