# Changelog

All notable public release changes for Evydence are recorded here.

Release notes must distinguish implemented behavior from future intent and must
preserve Evydence’s non-claims: no legal compliance conclusions, no
certification, no complete-SBOM guarantee, no authoritative vulnerability
results, no secure-release guarantee, and no regulator or auditor acceptance.

## Unreleased

No public release notes have been added after local release-candidate evidence
for `v0.1.0-rc.3`. Public GitHub release publication remains an operator
action.

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
