# Release Evidence

This file is the release-evidence router. The canonical release validation
reference is:

- [`docs/reference/release-validation.md`](docs/reference/release-validation.md)

Local acceptance gates start with:

```sh
make release-acceptance
make release-check
make production-check
```

`make release-acceptance` is a deterministic local meta gate. It checks this
repository’s legal, governance, support, security, trademark, release-evidence,
Docker-build-context, docs, OpenAPI, deployment, SDK, and unit-test readiness
without requiring live PostgreSQL, Docker, KMS, S3, GitHub, GitLab, or other
external providers.

`make release-check` is the stronger project-owned release validation gate. It
runs `make finalize`, lint, gosec, govulncheck, race tests, and live PostgreSQL
checks when `EVYDENCE_TEST_DATABASE_URL` is configured.

`make production-check` is the strict self-hosted production-readiness gate. It
requires live PostgreSQL through `EVYDENCE_TEST_DATABASE_URL`, enforces the
coverage threshold, and runs a local release artifact signing smoke test. A
failure means the build has not yet met the self-hosted production profile.

Commercial release evidence packages may include signed release manifests,
image digests, SBOMs, vulnerability scan outputs, OpenAPI checksums, migration
checks, acceptance evidence, support notes, deployment hardening notes, and
upgrade guidance.

Release evidence is not a certification. It does not claim legal compliance,
secure releases, complete SBOMs, authoritative scanner results, regulator
acceptance, auditor acceptance, or provider-side completeness.
