# Changelog

All notable public release changes for Evydence are recorded here.

Release notes must distinguish implemented behavior from future intent and must
preserve Evydence’s non-claims: no legal compliance conclusions, no
certification, no complete-SBOM guarantee, no authoritative vulnerability
results, no secure-release guarantee, and no regulator or auditor acceptance.

## Unreleased

- No unreleased changes.

## v0.1.0-rc.7 - 2026-06-01

Release status: controlled self-hosted production candidate. This prerelease is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status.

### Fixed

- Release artifact publication now uses the dedicated release publication token
  path after signed release evidence is generated.
- The release-candidate evidence package includes signed archives, checksums,
  OpenAPI and migration checksums, coverage output, production-check summary,
  SBOM/provenance metadata, release notes, and a signed release manifest.

### Known Limits

- No tag-specific project-owned container image evidence is asserted for this
  prerelease in the repository metadata; operators must verify a separately
  published image digest or build/sign their own image for container
  deployments.
- Multi-writer API HA remains outside the supported production profile; use one
  API writer replica and scale workers through PostgreSQL outbox locking.

## v0.1.0-rc.5 - 2026-06-01

Release status: controlled self-hosted production candidate. This prerelease is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status.

### Added

- Public release verification helper for downloading `v0.1.0-rc.5` from
  GitHub Releases into a clean temporary directory, checking release checksums,
  validating in-toto provenance metadata shape, and verifying the signed
  release manifest with the released Linux amd64 CLI.
- Container image workflow evidence for
  `ghcr.io/aatuh/evydence:v0.1.0-rc.5@sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888`,
  including release-attached image manifest and cosign verification output.
- Repository-owned restore rehearsal target for app-layer and live PostgreSQL
  backup/restore mechanics.
- Static package-viewer preview asset for public docs.

### Changed

- Dependency maintenance updates for pinned GitHub Actions, the Docker build
  and runtime base images, and `kin-openapi`.

### Fixed

- PostgreSQL release-evidence persistence now normalizes empty string slices to
  empty `text[]` values for non-null array columns, including VEX import
  reports and vulnerability decision evidence IDs.

### Known Limits

- Operators remain responsible for PostgreSQL, object storage, TLS, external
  signing or KMS/HSM custody, WORM/object-lock policy where required, backups,
  restore rehearsals, monitoring, provider validation, and incident response.
- Multi-writer API HA remains outside the supported production profile; use one
  API writer replica and scale workers through PostgreSQL outbox locking.

## v0.1.0-rc.4 - 2026-05-31

Release status: controlled self-hosted production candidate. This prerelease is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status.

### Added

- Public GitHub prerelease at
  <https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.4>.
- Release archives for Linux, macOS, and Windows.
- `SHA256SUMS`, `openapi.sha256`, and `migrations.sha256`.
- Release coverage output and production-check summary.
- Release SBOM metadata and Evydence release provenance metadata.
- Scorecard-compatible in-toto provenance metadata.
- Signed release manifest plus `.sig.json` verifier input and `.sig` release
  asset alias.
- Release notes attached to the public prerelease.

### Known Limits

- Public release archives and release evidence are published, but no
  container image should be treated as deployable release evidence unless the
  maintainer image workflow has produced an immutable digest and cosign evidence
  for the tag.
- Operators remain responsible for PostgreSQL, object storage, TLS, external
  signing or KMS/HSM custody, WORM/object-lock policy where required, backups,
  restore rehearsals, monitoring, provider validation, and incident response.
- Multi-writer API HA remains outside the supported production profile; use one
  API writer replica and scale workers through PostgreSQL outbox locking.

## v0.1.0-rc.3 - 2026-05-31

Release status: controlled self-hosted production candidate. This build is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status. The local
release-candidate package for this tag was generated with
`make release-candidate-check TAG=v0.1.0-rc.3`.

### Added

- Direct GCP Cloud KMS and Azure Key Vault signing executors for signing stored
  SHA-256 payload hashes without sending raw evidence payload bytes.
- Operator-controlled provider validation gateway that records non-secret
  validation metadata without forwarding supplied access tokens.
- Operator-controlled transparency proof gateway before local proof
  verification.
- Release-candidate SBOM metadata and release provenance metadata generation.
- OpenSSF Scorecard workflow, Dependabot configuration, issue templates, code
  of conduct, and production-like Compose rehearsal.

### Changed

- README positioning now leads with the release-evidence user problem, current
  limitations, fastest proof path, and differentiation from adjacent tools.
- Security reporting guidance no longer depends on LinkedIn as the first
  recommended path and calls out external repository settings that operators
  must verify.

### Known Limits

- Public GitHub release publication, branch protection, public CI status,
  private vulnerability-reporting settings, and public adoption evidence remain
  external repository/operator proof.
- High-scale multi-writer API HA, native PKCS#11/HSM module handling, direct
  provider management API/group synchronization, broad WORM/object-lock proof,
  and final production exit review remain hardening work or deployment-specific
  review items.

## v0.1.0-rc.2 - 2026-05-31

Release status: controlled self-hosted production candidate. This build is
suitable for evaluation, pilots, and controlled internal production after
operator review. Broad self-hosted production readiness, regulated production,
and hosted SaaS production remain out of scope for this status. The local
release-candidate package for this tag was generated with
`make release-candidate-check TAG=v0.1.0-rc.2`.

### Added

- Root legal, governance, security, support, trademark, commercial licensing,
  release-evidence, and changelog metadata.
- Production-readiness profile, production gate, and coverage-threshold gate.
- Release-candidate checklist requiring production-check evidence, checksums,
  signed artifact manifests, release notes, and documented limitations.
- Release-candidate package gate for controlled release-candidate artifacts, checksums,
  OpenAPI and migration checksums, checked release notes, signed release
  manifest, and manifest signature.
- Local `v0.1.0-rc.2` annotated release-candidate tag and signed evidence
  package generated under ignored `dist/v0.1.0-rc.2/`.
- Focused PostgreSQL critical mutations for tenants, credential hashes,
  idempotency records, audit-chain entries, release bundles, signatures,
  verification results, provider verification receipts, vulnerability
  decisions, and outbox jobs.
- Focused PostgreSQL release-ledger mutations for products, projects, releases,
  artifacts, evidence items, evidence lifecycle events, SBOMs, vulnerability
  scans, OpenAPI contracts, VEX documents, audit-chain entries, and parser
  outbox jobs.
- Relational PostgreSQL state synchronization for remaining aggregate
  persistence calls without writing the compatibility `ledger_state` snapshot.
- AWS KMS signing executor for signing provider operations over stored
  SHA-256 payload hashes without sending raw evidence payload bytes.
- Optional OIDC UserInfo live provider validation for
  `POST /v1/provider-verifications` using a supplied access token that is not
  persisted.
- Object-retention policies can require sample-object legal hold verification
  with S3/MinIO providers that expose object legal-hold status.
- Production API startup takes a PostgreSQL advisory writer lease so accidental
  second API writers fail closed under the supported single-writer profile.

### Known Limits

- Evydence supports compliance readiness and technical evidence organization.
- Operators remain responsible for production PostgreSQL, object storage,
  network policy, TLS, backups, monitoring, external signing, and incident
  response.
- Service decomposition, HA/multi-writer operation, non-AWS KMS/HSM SDK
  adapters, provider-specific management API/group synchronization, broader
  object-lock proof beyond configured bucket/sample-object checks, and final
  exit review remain production-hardening work after the release-candidate
  gate.
