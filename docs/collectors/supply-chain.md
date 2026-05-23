# Collector Supply Chain

This is a reference for collector release evidence.

Collector releases can be recorded with:

```http
POST /v1/collectors/{id}/releases
```

The release record includes version, artifact digest, optional signature evidence, optional SBOM, optional vulnerability scan, and whether the version is pinned. `GET /v1/collectors/{id}/health` returns the collector status and supply-chain evidence checks.

Collector health reports help operators see whether collector evidence exists and whether a version is pinned. They do not prove that a collector is free of vulnerabilities or safe at runtime.
