# Evydence Documentation

This documentation is organized by reader task. Implementation claims should be backed by committed code, `openapi.yaml`, tests, deployment files, Makefile targets, and the canonical references listed in [Documentation source of truth](reference/source-of-truth.md).

## Start Here

- [Buyer evaluation overview](buyer-overview.md): choose the package, demo, release-evidence, and API paths for customer-review evaluation.
- [Operator overview](operator-overview.md): choose the install, configuration, deployment, runbook, and production-gate paths for self-hosting.
- [Evaluate Evydence in 10 minutes](tutorials/evaluate-in-10-minutes.md): inspect the public release verifier, sample customer package, local package viewer, and VEX-first proof path.
- [Customer CVE review demo](tutorials/customer-cve-review-demo.md): run the deterministic package-scope CVE answer without external services.
- [Getting started](tutorials/getting-started.md): run the API locally and create a minimal release evidence flow.
- [Install and operate](how-to/install-and-operate.md): choose a local runtime mode, start dependencies, run migrations, and launch API/worker processes.
- [Operations](operations.md): find the canonical operator references for configuration, workers, CI, deployment, and validation.
- [API reference](api.md): integrate with the `/v1` HTTP API using authentication, idempotency, examples, and endpoint tables.
- [Rendered OpenAPI docs](openapi/index.html): browse the generated static operation and schema reference.

## How-To Guides

- [Integrate CI collectors](how-to/integrate-ci.md): connect the GitHub Actions quickstart, the scanner workflow, the composite upload action, GitLab CI, source snapshots, and collector supply-chain records.
- [Tool-specific integration templates](integrations/tool-templates.md): Syft, Grype, Trivy, GitHub Actions, GitLab CI, Dependency-Track, Jira metadata, and S3-compatible object storage handoff snippets.
- [Kubernetes deployment](kubernetes.md): install the Helm chart and verify a self-hosted cluster deployment.
- [Air-gapped installation](air-gapped.md): build, sign, transfer, verify, and import an offline package.
- [Release signing](release-signing.md): create and verify local release artifact manifests.
- [View packages locally](how-to/view-packages.md): inspect package, readiness, and evidence-bundle JSON without uploading it.
- [Review a customer package](how-to/review-customer-package.md): verify, inspect, and escalate a scoped package with checked fixtures.
- [Production hardening review](production-hardening.md): review production configuration, backups, ingress, diagnostics, and customer package controls.
- [Pilot deployment checklist](how-to/pilot-deployment-checklist.md): copy-paste checklist for the narrow design-partner pilot profile.
- [Publish the marketing site](how-to/publish-marketing-site.md): deploy the Astro site to GitHub Pages at `evydence.app` with consent-gated Google Analytics.
- [Backup and restore runbook](runbooks/backup-restore.md): rehearse paired database/object-store restore and verification.
- [Upgrade runbook](runbooks/upgrade.md): verify release artifacts, migrations, and post-upgrade checks.
- [Incident response runbook](runbooks/incident-response.md): handle operator incidents without leaking secrets or raw evidence.
- [Key rotation runbook](runbooks/key-rotation.md): rotate API, collector, SSO/session, portal, signing, and provider credentials.
- [Object store recovery runbook](runbooks/object-store-recovery.md): recover missing or mismatched raw payloads and package/export objects.

## Reference

- [Configuration](reference/configuration.md): canonical environment variables and the roles of `.env.example`, `.api.env.example`, and `.test.env.example`.
- [Documentation source of truth](reference/source-of-truth.md): canonical source map to keep commands, status, and limitations from drifting.
- [Capability map](reference/capability-map.md): advanced inventory of implemented capabilities, implementation limits, and implemented-but-partial areas.
- [API contract matrix](reference/api-contract-matrix.md): generated route-by-route contract precision inventory for production hardening.
- [OpenAPI contract](reference/openapi.md): generation, drift checks, and review tips for `openapi.yaml`.
- [Rendered OpenAPI docs](openapi/index.html): static page generated from the committed OpenAPI contract.
- [Vulnerability decisions](reference/vulnerability-decisions.md): current VEX/decision model, buyer-facing gaps, and planned API changes.
- [Customer package manifest](reference/customer-package-manifest.md): v2 package schema, included metadata, exclusions, and local viewer compatibility.
- [Observability](reference/observability.md): readiness, admin metrics, Prometheus rules, and dashboard starter assets.
- [Capacity and failure modes](reference/capacity-and-failures.md): supported concurrency profile, sizing inputs, and failure behavior.
- [Benchmark results](reference/benchmark-results.md): current local benchmark command and interpretation.
- [Production readiness](reference/production-readiness.md): self-hosted production profiles, production gates, and exit criteria.
- [Persistence decomposition inventory](reference/persistence-decomposition.md): generated map of focused and broad relational persistence call sites.
- [Production exit review](reference/production-exit-review.md): current release-positioning decision and unresolved blockers.
- [Stable v0.1.0 exit criteria](reference/stable-v0.1.0-exit-criteria.md): criteria for moving from release candidate to a stable `v0.1.0` tag.
- [Hardened reference deployment](reference/hardened-reference-deployment.md): controlled self-hosted topology with external PostgreSQL, object storage, TLS, secrets, backups, monitoring, and signing.
- [HA strategy](reference/ha-strategy.md): single-writer API decision, worker scaling stance, recovery boundaries, and multi-writer prerequisites.
- [External controls matrix](reference/external-controls-matrix.md): owner boundaries for regulated or high-trust self-hosted deployments.
- [Production gate troubleshooting](reference/production-gate-troubleshooting.md): safe diagnostics for `make production-check` failures.
- [Upgrade and compatibility policy](reference/upgrade-compatibility-policy.md): supported upgrade paths, migration expectations, and API compatibility rules.
- [Release candidate checklist](reference/release-candidate.md): required evidence before tagging a controlled self-hosted release candidate.
- [Release evidence index](reference/release-evidence-index.md): release artifact map, generation commands, and verification commands.
- [Release notes template](reference/release-notes-template.md): checked wording used by release-candidate packaging when a tag-specific note file is absent.
- [Release notes v0.1.0-rc.1](reference/release-notes-v0.1.0-rc.1.md): checked release-note wording for the first controlled self-hosted release candidate.
- [Maintainer review policy](reference/maintainer-review-policy.md): CODEOWNERS-backed review expectations for high-risk paths.
- [Roadmap and release cadence](reference/roadmap.md): current release-line focus, external trust controls, and cadence expectations.
- [Worker outbox contract](reference/worker-outbox.md): durable job kinds, idempotency, and safe logging rules.
- [Release validation](reference/release-validation.md): canonical `make release-check` behavior and summary evidence.
- [Upload manifest](reference/upload-manifest.md): schema, validation command, supported evidence request kinds, and safe payload-file handling.
- [SDK workflow](sdk/README.md): current Go, TypeScript, and Python wrapper usage and limitations.
- [SDK quickstarts](sdk/quickstarts.md): Go, TypeScript, and Python create/read snippets, Problem Details handling, idempotency, and package verification boundaries.
- [Collector supply chain](collectors/supply-chain.md): collector release evidence and health checks.
- [Source snapshot collectors](collectors/source-snapshots.md): GitHub and GitLab source metadata upload examples.

## Project Metadata

- [License](../LICENSE): `AGPL-3.0-only` public license text.
- [Commercial licensing](../COMMERCIAL.md): license decision table, commercial license exceptions, self-hosted support, release evidence packages, deployment review, and custom integration support.
- [Design partner pilot](commercial/design-partner-pilot.md): narrow paid pilot shape for one self-hosted release evidence workflow.
- [Product landing copy](commercial/product-landing-copy.md): conservative reusable positioning for README, website, outreach, or pilot materials.
- [Category comparison](commercial/category-comparison.md): fair positioning against Dependency-Track, GUAC, OpenVEX tooling, scanners, SBOM inventory tools, broad GRC, trust centers, and scripts.
- [Security policy](../SECURITY.md): vulnerability reporting guidance for tenant isolation, evidence integrity, credentials, collectors, object storage, signing, reports, exports, and raw evidence payloads.
- [Support](../SUPPORT.md): community support expectations, commercial support boundaries, and sanitized bug-report requirements.
- [Governance](../GOVERNANCE.md): maintainer-led decision process, contribution acceptance, release evidence expectations, and conservative product-language policy.
- [Contributing](../CONTRIBUTING.md): contribution workflow, CLA expectation, licensing compatibility, and implementation invariants.
- [Code of conduct](../CODE_OF_CONDUCT.md): participation expectations for public project spaces.
- [Trademarks](../TRADEMARKS.md): conservative use of the Evydence name and modified-build naming rules.
- [Release evidence](../RELEASE_EVIDENCE.md): release evidence routing, local acceptance checks, and limits of release validation.
- [Changelog](../CHANGELOG.md): unreleased and future public-release notes.
- [CODEOWNERS](../CODEOWNERS): expected maintainer ownership for high-trust code, release, deployment, and claim surfaces.

## Workflow Examples

- [GitHub Actions quickstart release evidence workflow](github-actions/quickstart-release-evidence.yml)
- [End-to-end GitHub Actions release evidence guide](github-actions/end-to-end-release-evidence.md)
- [GitHub Actions scanner release evidence workflow](github-actions/release-evidence-workflow.yml)
- [GitHub Actions upload-build composite action](github-actions/upload-build/action.yml)
- [GitHub release evidence manifest generator](../scripts/github_release_evidence_manifest.py)
- [GitLab release evidence CI template](gitlab/evydence-release-evidence.gitlab-ci.yml)
- [End-to-end release evidence example](../examples/end-to-end-release-evidence/README.md)
- [SDK examples](../examples/sdk)

These examples require tenant-scoped API or collector secrets created through the API. They capture CI metadata as submitted evidence; provider-side truth still depends on the CI provider, workflow controls, and any verification receipts recorded separately.

## Explanation

- [Architecture](architecture.md): ports/adapters boundaries, persistence, object storage, append-only behavior, and current limitations.
- [Architecture diagram](explanation/architecture-diagram.md): compact diagram of API, worker, storage, signing, and provider boundaries.
- [Trust model](explanation/trust-model.md): what Evydence verifies, what it records as assumptions, and where external review remains required.

Evydence supports compliance readiness and technical evidence organization. The documentation avoids claims that Evydence makes legal compliance conclusions, grants certification, proves SBOM completeness, treats scanner output as authoritative, or guarantees release security.
