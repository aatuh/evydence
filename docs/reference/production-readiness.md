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
- OpenAPI schemas need endpoint-specific precision across the full public API;
- GitHub CI enforces live PostgreSQL release checks and the default 80 percent
  production coverage threshold, but the broader production exit review remains
  incomplete.

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
- backup and restore have been tested for the target deployment profile;
- OpenAPI and SDK drift checks pass;
- production hardening review is current;
- unresolved limitations are documented in release notes.

Operators remain responsible for secret management, TLS, network policy,
database and object-store durability, backups, restore rehearsals, monitoring,
provider configuration, incident response, and external review.
