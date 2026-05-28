# Production Readiness

This reference defines the self-hosted production bar for Evydence. It is a
gate for engineering and operator review. It does not prove legal compliance,
certification, complete vulnerability detection, complete SBOM coverage, or
release security.

## Current Status

Evydence is in self-hosted production hardening. It is suitable for evaluation,
pilots, and controlled internal production after operator review. Broad
self-hosted production use requires the production gate in this file to pass
with live PostgreSQL and release evidence enabled.

Known hardening work remains:

- canonical production persistence still needs hand-tuned relational repository
  paths for all high-risk resource families. PostgreSQL now maintains
  relational identity, idempotency, customer portal token, release-ledger core,
  build provenance, source/deployment, incident, security evidence, SBOM diff,
  vulnerability workflow, contract diff, custom policy, waiver, approval, DSSE
  trust-root, collector release, Cosign verification, signing provider, Merkle
  batch, transparency checkpoint, evidence lifecycle, release candidate,
  VEX/risk decision, control, audit-chain, signing, bundle, policy,
  verification, package, report, retention, provider verification, signing
  operation, and future-extension rows alongside the compatibility snapshot.
  When `ENV=production` and `EVYDENCE_POSTGRES_LOAD_MODE` is unset, API and
  worker startup load from relational reconstruction only. Production refuses
  snapshot fallback modes and disables compatibility snapshot writes; local
  development still defaults to snapshot-preferred loading and snapshot writes.
  If the snapshot row is absent, the store can rebuild identity, SSO session,
  customer portal token, release-ledger core,
  build provenance, source/deployment, incident, security evidence, SBOM diff,
  vulnerability workflow, contract diff, custom policy, waiver, approval, DSSE
  trust-root, collector release, Cosign verification, signing provider, Merkle
  batch, transparency checkpoint, evidence lifecycle, release candidate,
  VEX/risk decision, control, package, report, retention, provider verification,
  signing operation, and future-extension state from relational rows;
- worker parser jobs re-read raw object-store payloads for key formats,
  verify digests, validate durable state, and persist missing parser-derived
  normalized fields. CycloneDX SBOM, generic vulnerability-scan, and OpenAPI
  contract uploads can run with worker-owned normalized side effects by setting
  `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`; the other parser-backed
  upload paths still create initial normalized records, so fully worker-owned
  parsing for every payload remains hardening work;
- OpenAPI precision is enforced across the registered public API. The generated
  matrix remains the source of truth for operation ids, scopes, idempotency,
  parameters, and request/response schemas;
- production signing can use the HTTPS signing gateway executor, but direct
  cloud KMS/HSM SDK adapters, live provider API validation/group sync, and
  broad object-lock enforcement proof remain provider- and deployment-dependent
  hardening areas. SSO credential exchange can issue bearer sessions and
  HttpOnly cookies after local OIDC/SAML verification against configured trust
  material, OIDC group claim values can map to session-scoped roles without
  creating permanent role bindings, and public transparency proof material can
  be fetched from a configured endpoint and verified locally, but
  provider-specific trust semantics and availability remain deployment
  responsibilities;
- the broader production exit review remains incomplete.

## Production Profiles

| Profile | Status | Required controls |
| --- | --- | --- |
| Small internal self-hosted production | Candidate after gate passes | PostgreSQL, object storage, TLS, non-default API-key pepper, externalized secrets, backups, restore test, monitoring, `make production-check`, and operator review. |
| Regulated self-hosted production | Requires extra review | All small-production controls plus KMS/HSM or equivalent signing custody, retention policy review, SSO review, object-lock review where required, incident runbook, and documented control limitations. |
| Air-gapped production | Requires transfer controls | All small-production controls plus signed offline artifacts, import/export verification, local registry or package mirror, offline docs, and explicit backup/restore procedure. |
| Hosted SaaS production | Out of scope for this profile | Requires separate hosted tenancy, SLO, abuse, billing, privacy, support, and cloud operations controls before any SaaS production claim. |

## Machine Gate

Run the production gate from the repository root:

```sh
make production-check
```

The gate requires:

- `EVYDENCE_TEST_DATABASE_URL` set to a disposable PostgreSQL database;
- `make release-check` passing without skipped live PostgreSQL checks;
- `make coverage-check` passing at the configured threshold;
- migration compatibility from every committed migration prefix to the current
  schema passing in temporary PostgreSQL schemas;
- live PostgreSQL backup/restore rehearsal preserving ledger state, object
  payload digests, backup-manifest verification, and release-bundle
  verification after restore;
- release artifact signing smoke test passing with local temporary keys;
- generated release evidence summary available under `tmp/`.

The default coverage threshold is 80 percent:

```sh
make coverage-check
EVYDENCE_COVERAGE_THRESHOLD=85 make coverage-check
```

`make production-check` is intentionally stricter than `make finalize`. Use
`make finalize` for routine local development. Use `make production-check` for
self-hosted production readiness evidence.

## Exit Criteria

Do not describe an Evydence build as broadly self-hosted production-ready until:

- `make production-check` passes in CI with live PostgreSQL;
- coverage is at or above the configured threshold;
- release artifacts have signed manifests and published checksums;
- committed migrations have passed compatibility checks from every migration
  prefix to the current schema;
- the built-in local restore rehearsal passes and backup/restore have been
  tested for the target deployment profile;
- OpenAPI, OpenAPI precision, route-contract, and SDK drift checks pass;
- production hardening review is current;
- unresolved limitations are documented in release notes.

## Remaining Production Maturity Backlog

These items are tracked separately from the feature-completeness checklist in
`.implementation_increments.md` because they are hardening work on already
implemented capabilities:

- Continue replacing aggregate `SaveState` synchronization with
  dependency-ordered relational repositories for focused resource families.
  Identity, idempotency, customer portal token, release-ledger core, build provenance,
  source/deployment, incident, security evidence, SBOM diff, vulnerability
  workflow, contract diff, custom policy, waiver, approval, DSSE trust-root,
  collector release, Cosign verification, signing provider, Merkle batch,
  transparency checkpoint, evidence lifecycle, release candidate, VEX/risk
  decision, control, audit-chain, signing, bundle, policy, verification,
  package, report, retention, provider verification, signing operation, and
  future-extension rows are synchronized into relational tables. Production
  startup defaults to relational-only loading, production writes skip the
  compatibility snapshot, and missing-snapshot recovery can rebuild identity,
  SSO session, customer portal token,
  release-ledger core, build provenance, source/deployment, incident, security
  evidence, SBOM diff, vulnerability workflow, contract diff, custom policy,
  waiver, approval, DSSE trust-root, collector release, Cosign verification,
  signing provider, Merkle batch, transparency checkpoint, evidence lifecycle,
  release candidate, VEX/risk decision, control, package, report, retention,
  provider verification, signing operation, and future-extension families from
  relational rows. Snapshots remain for local compatibility, export/import, and
  non-production migration checks.
- Split the large application ledger aggregate into focused services or
  repositories once relational writes are in place, preserving tenant isolation
  and append-only behavior throughout.
- Continue moving parser-owned side effects for VEX and attestation payloads
  into worker processors. CycloneDX SBOM, generic vulnerability scan, and
  OpenAPI contract normalized fields can be worker-owned behind
  `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`; workers also persist
  missing parser-derived fields for replay-compatible records.
- Keep OpenAPI precision at zero broad operations as routes are added or
  changed, and expand generated SDK coverage from the committed contract.
- Add direct cloud KMS/HSM SDK adapters where required. The current HTTPS
  signing gateway executor covers deployments that put KMS/HSM custody behind a
  tenant-controlled signing service and do not send raw payload bytes.
- Complete live provider API validation and optional group mapping where those
  profiles are enabled. OIDC discovery/JWKS refresh is implemented for public
  trust-material updates, manual JWKS and SAML signing-certificate rotation is
  implemented through the SSO provider trust-material endpoint, SSO credential
  exchange can issue bearer sessions plus HttpOnly cookies after local token or
  assertion verification, OIDC group claim values can map to session-scoped
  roles, and API-first session logout can revoke the current SSO bearer session.
- Extend object-lock/WORM verification beyond the current S3/MinIO bucket-level
  checks plus optional sample-object retention checks where deployments require
  broader object-level legal hold proofs or provider policy evidence.
- Run final product, codebase, security, documentation, and test audits before
  changing release status beyond controlled self-hosted production candidate.

Operators remain responsible for secret management, TLS, network policy,
database and object-store durability, backups, restore rehearsals, monitoring,
provider configuration, incident response, and external review.
