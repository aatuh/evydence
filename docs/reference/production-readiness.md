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
  relational identity, idempotency, release-ledger core, audit-chain, signing,
  bundle, policy, and verification rows alongside the canonical snapshot, but
  the snapshot remains the preferred runtime load source. If the snapshot row
  is absent, the store can rebuild identity and release-ledger core state from
  relational rows;
- worker parser jobs re-read raw object-store payloads for key formats,
  verify digests, validate durable state, and persist missing parser-derived
  normalized fields. Upload paths still create initial accepted records, so
  fully worker-owned parsing for every payload remains hardening work;
- OpenAPI precision is enforced across the registered public API. The generated
  matrix remains the source of truth for operation ids, scopes, idempotency,
  parameters, and request/response schemas;
- production signing can use the HTTPS signing gateway executor, but direct
  cloud KMS/HSM SDK adapters, full browser OIDC/SAML login flows, provider
  discovery/group sync, object-lock enforcement proof, and live
  transparency-proof fetching remain provider- and deployment-dependent
  hardening areas;
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

- Replace canonical snapshot writes with dependency-ordered relational
  repositories for remaining report, package, portal, retention, and secondary
  resources. Identity, idempotency, release-ledger core, audit-chain, signing,
  bundle, policy, and verification rows are synchronized into relational
  tables, and missing-snapshot recovery can rebuild those families from
  relational rows. Keep snapshots only for export/import and upgrade
  compatibility after the remaining families have repository-backed writes.
- Split the large application ledger aggregate into focused services or
  repositories once relational writes are in place, preserving tenant isolation
  and append-only behavior throughout.
- Continue moving parser-owned side effects for SBOM, vulnerability scan,
  OpenAPI, VEX, and attestation payloads into worker processors. Workers now
  persist missing parser-derived fields after object replay, but upload
  endpoints still create initial accepted records.
- Keep OpenAPI precision at zero broad operations as routes are added or
  changed, and expand generated SDK coverage from the committed contract.
- Add direct cloud KMS/HSM SDK adapters where required. The current HTTPS
  signing gateway executor covers deployments that put KMS/HSM custody behind a
  tenant-controlled signing service and do not send raw payload bytes.
- Complete live OIDC/SAML browser login callbacks, provider discovery, JWKS
  fetching, logout, and optional group mapping where those profiles are
  enabled. Manual JWKS and SAML signing-certificate rotation is implemented
  through the SSO provider trust-material endpoint.
- Extend object-lock/WORM verification beyond current S3/MinIO bucket-level
  checks where deployments require object-level legal hold proofs or provider
  policy evidence, and add live provider fetching for public transparency proofs
  where deployments require it.
- Run final product, codebase, security, documentation, and test audits before
  changing release status beyond controlled self-hosted production candidate.

Operators remain responsible for secret management, TLS, network policy,
database and object-store durability, backups, restore rehearsals, monitoring,
provider configuration, incident response, and external review.
