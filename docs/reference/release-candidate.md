# Release Candidate Checklist

This reference defines the minimum evidence for a controlled self-hosted
Evydence release candidate such as `v0.1.0-rc.1` or `v0.9.0-rc.1`.

Release-candidate evidence supports reproducible engineering and operator
review. It is not a certification, legal compliance conclusion, complete SBOM
claim, authoritative vulnerability result, secure-release guarantee, regulator
acceptance, or auditor acceptance.

## Required Evidence

Before creating a release-candidate tag, collect:

- passing `make production-check` output with live PostgreSQL configured;
- `tmp/release-check-summary.txt` from the same run;
- `coverage.out` and the total coverage summary;
- `openapi.yaml` plus an OpenAPI checksum;
- migration checksum output for the directory or per-file migration checksums;
- signed release artifact manifest and manifest signature;
- checksums for every published binary, container image digest, chart package,
  and release archive;
- release notes with supported profile, upgrade notes, assumptions,
  limitations, and unresolved hardening work.

## Required Commands

Run from a clean checkout with a disposable PostgreSQL database:

```sh
set -a; . ./.test.env; set +a
export EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64="$(cat evydence-release-private.key)"
make release-candidate-check TAG=v0.1.0-rc.1
```

The target runs `scripts/release_candidate_package.sh`, which requires a clean
worktree, a release-candidate tag such as `v0.1.0-rc.1`, no existing local tag
unless the CI tag workflow explicitly allows it, live PostgreSQL through
`EVYDENCE_TEST_DATABASE_URL`, and release signing material. It runs
`make production-check`, builds the release archive matrix, writes checksums,
signs the release manifest, verifies the manifest signature, and validates the
release-note language.

Do not tag from a run where live PostgreSQL checks, migration compatibility,
coverage threshold enforcement, OpenAPI checks, docs checks, deployment checks,
SDK checks, lint, gosec, govulncheck, race tests, artifact checksums, or
manifest signature verification were skipped.

## Supported Profile Statement

Release notes must use this status unless the production exit review has
explicitly changed it:

> Controlled self-hosted production candidate for evaluation, pilots, and
> controlled internal production after operator review.

The notes must also state that broad production for most uses, regulated
production, and hosted SaaS production require additional review and controls.

## Deployment Constraints

- Use one API writer replica for the current production profile.
- Worker replicas may be scaled when PostgreSQL outbox locking is enabled.
- Use external PostgreSQL, external object storage, TLS ingress, non-default
  API-key pepper, externalized secrets, backup and restore rehearsal,
  monitoring, and documented incident response.
- Keep full repository decomposition, HA/multi-writer operation, direct KMS/HSM
  SDK adapters, live provider validation, and broader object-lock proof listed
  as unresolved hardening work until they are implemented and verified.
