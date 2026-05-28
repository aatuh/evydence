# Collector Supply Chain

This is a reference for collector release evidence.

Collector records describe automated ingesters such as GitHub Actions, GitLab CI, generic CI, and import-bundle collectors. A collector API key is tenant-scoped and should be stored in the CI secret store.

## Record A Collector Release

```http
POST /v1/collectors/{id}/releases
```

Representative request:

```json
{
  "version": "0.1.0",
  "artifact_digest": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  "signature_id": "sig_...",
  "sbom_id": "sbom_...",
  "scan_id": "scan_...",
  "pinned": true
}
```

Expected status is `201`. Optional fields should reference evidence already recorded in the same tenant.

## Review Collector Health

```http
GET /v1/collectors/{id}/health
```

The health report can show whether:

- a collector release record exists;
- the collector version is pinned;
- signature, SBOM, or vulnerability scan evidence was linked where available.

Health reports help operators see collector evidence gaps. They do not prove that a collector is free of vulnerabilities, provider-verified, or safe to run.

Marketplace collector package records have a separate health report:

```http
GET /v1/marketplace-collectors/{id}/health
```

That report checks whether package signature, SBOM, and vulnerability scan evidence references are present and still point to tenant-owned evidence. It is a package evidence-gap report, not a marketplace trust or endorsement decision.

## Related Docs

- [Integrate CI collectors](../how-to/integrate-ci.md)
- [Source snapshot collectors](source-snapshots.md)
- [GitHub Actions release evidence workflow](../github-actions/release-evidence-workflow.yml)
- [GitLab release evidence CI template](../gitlab/evydence-release-evidence.gitlab-ci.yml)
