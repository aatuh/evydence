# Evydence Documentation

This documentation is organized by reader task. Implementation claims should be backed by committed code, `openapi.yaml`, tests, deployment files, or Makefile targets. `.initial_design.md` remains design intent.

## Start Here

- [Getting started](tutorials/getting-started.md): run the API locally and create a minimal release evidence flow.
- [Install and operate](how-to/install-and-operate.md): choose a local runtime mode, start dependencies, run migrations, and launch API/worker processes.
- [Operations](operations.md): find the canonical operator references for configuration, workers, CI, deployment, and validation.
- [API reference](api.md): integrate with the `/v1` HTTP API using authentication, idempotency, examples, and endpoint tables.

## How-To Guides

- [Integrate CI collectors](how-to/integrate-ci.md): connect GitHub Actions, the composite upload action, GitLab CI, source snapshots, and collector supply-chain records.
- [Kubernetes deployment](kubernetes.md): install the Helm chart and verify a self-hosted cluster deployment.
- [Air-gapped installation](air-gapped.md): build, sign, transfer, verify, and import an offline package.
- [Release signing](release-signing.md): create and verify local release artifact manifests.
- [Production hardening review](production-hardening.md): review production configuration, backups, ingress, diagnostics, and customer package controls.

## Reference

- [Configuration](reference/configuration.md): canonical environment variables and the roles of `.env.example`, `.api.env.example`, and `.test.env.example`.
- [OpenAPI contract](reference/openapi.md): generation, drift checks, and review tips for `openapi.yaml`.
- [Observability](reference/observability.md): readiness, admin metrics, Prometheus rules, and dashboard starter assets.
- [Worker outbox contract](reference/worker-outbox.md): durable job kinds, idempotency, and safe logging rules.
- [Release validation](reference/release-validation.md): canonical `make release-check` behavior and summary evidence.
- [SDK workflow](sdk/README.md): current Go, TypeScript, and Python wrapper usage and limitations.
- [Collector supply chain](collectors/supply-chain.md): collector release evidence and health checks.
- [Source snapshot collectors](collectors/source-snapshots.md): GitHub and GitLab source metadata upload examples.

## Workflow Examples

- [GitHub Actions release evidence workflow](github-actions/release-evidence-workflow.yml)
- [GitHub Actions upload-build composite action](github-actions/upload-build/action.yml)
- [GitLab release evidence CI template](gitlab/evydence-release-evidence.gitlab-ci.yml)

These examples require tenant-scoped API or collector secrets created through the API. They capture CI metadata as submitted evidence; provider-side truth still depends on the CI provider, workflow controls, and any verification receipts recorded separately.

## Explanation

- [Architecture](architecture.md): ports/adapters boundaries, persistence, object storage, append-only behavior, and current limitations.
- [Trust model](explanation/trust-model.md): what Evydence verifies, what it records as assumptions, and where external review remains required.

Evydence supports compliance readiness and technical evidence organization. The documentation avoids claims that Evydence makes legal compliance conclusions, grants certification, proves SBOM completeness, treats scanner output as authoritative, or guarantees release security.
