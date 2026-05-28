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
  paths for all high-risk resource families;
- worker parser jobs re-read raw object-store payloads for key formats and
  validate durable state, but parser side effects still need to move
  independently out of the request path;
- OpenAPI precision is enforced across the registered public API. The generated
  matrix remains the source of truth for operation ids, scopes, idempotency,
  parameters, and request/response schemas;
- production KMS/HSM execution, full browser OIDC/SAML login flows, provider
  discovery/group sync, object-lock enforcement proof, and transparency
  inclusion proof verification remain provider- and deployment-dependent
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
  repositories for identity, idempotency, evidence, audit-chain entries,
  bundles, reports, packages, and secondary resources. Keep snapshots only for
  export/import and upgrade compatibility.
- Split the large application ledger aggregate into focused services or
  repositories once relational writes are in place, preserving tenant isolation
  and append-only behavior throughout.
- Move parser-owned side effects for SBOM, vulnerability scan, OpenAPI, VEX,
  and attestation payloads fully into worker processors while keeping upload
  responses backward compatible.
- Keep OpenAPI precision at zero broad operations as routes are added or
  changed, and expand generated SDK coverage from the committed contract.
- Add production signing-provider execution for a configured external provider
  profile without storing private key material in Evydence.
- Complete live OIDC/SAML browser login callbacks, provider discovery, JWKS
  refresh, logout, and optional group mapping where those profiles are enabled.
- Add provider-backed object-lock/WORM verification and optional transparency
  inclusion proof verification for deployments that require those controls.
- Run final product, codebase, security, documentation, and test audits before
  changing release status beyond controlled self-hosted production candidate.

Operators remain responsible for secret management, TLS, network policy,
database and object-store durability, backups, restore rehearsals, monitoring,
provider configuration, incident response, and external review.
