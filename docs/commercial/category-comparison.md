# Category Comparison

This page explains where Evydence fits next to scanners, SBOM inventory tools,
GRC platforms, trust centers, and scripts. It is intended to help buyers choose
the right tool for the job. The categories below solve real problems; Evydence
exists because release-level evidence packaging and verification is usually a
separate workflow.

## Short Version

Evydence is a self-hosted release evidence ledger. It organizes technical
evidence, decisions, exceptions, bundles, audit chains, controls, and
customer-safe packages around a product release.

It complements tools that generate findings, inventories, questionnaires, or
customer portals. It does not replace them.

## Comparison

| Category | Strong At | Common Boundary | Where Evydence Fits |
| --- | --- | --- | --- |
| Vulnerability scanners | Finding known issues in source, containers, dependencies, or deployed surfaces. | Scanner output often needs release context, VEX decisions, exceptions, and customer-safe explanation. | Stores scanner output as evidence, links findings to releases and artifacts, records decisions and exceptions, and reports unresolved release blockers. |
| SBOM inventory tools | Tracking components, dependency inventories, and vulnerability exposure over time. | Inventory views do not always answer which evidence package supports a specific customer release. | Links SBOMs to artifacts/releases, preserves hashes, and exports release-scoped package material. |
| Broad GRC tools | Managing controls, tasks, vendor questionnaires, policies, and organization-wide compliance workflows. | Broad workflow can be too high level for reproducible release evidence and raw technical artifact verification. | Provides release-level technical evidence and control coverage inputs that can support GRC workflows without claiming to replace review. |
| Trust centers | Publishing selected security documents and package material to customers. | Public portals usually depend on curated upstream evidence and redaction decisions. | Generates scoped, verifiable package manifests and static reports that can feed a trust center or be shared offline. |
| DIY scripts and spreadsheets | Fast local coordination for one team or one release. | Harder to keep append-only history, tenant scope, signatures, audit chains, and repeatable package structure. | Provides a repeatable API, manifest schema, verification commands, and release evidence workflow. |

## Named Adjacent Tools

These examples are intentionally respectful and category-focused. The named
tools solve useful problems; Evydence is aimed at the release-level packaging
and verification workflow that usually sits beside them.

| Tool or family | How to think about it | Evydence boundary |
| --- | --- | --- |
| Dependency-Track | Strong SBOM and component-risk management for product portfolios. | Evydence can ingest SBOM and scan outputs, then bind them to a specific release, decision trail, signed bundle, and customer-safe package. |
| GUAC | Strong supply-chain graph exploration and relationship analysis. | Evydence stays on release records, package manifests, verification receipts, and reviewer-facing evidence rather than replacing graph analysis. |
| OpenVEX tooling | Strong at producing or consuming VEX statements. | Evydence stores OpenVEX as evidence, normalizes customer-visible vulnerability decisions, and links decisions to releases, scans, SBOM context, packages, and exceptions. |
| Vanta, Drata, and similar SaaS GRC platforms | Strong broad compliance workflow, policy/task tracking, and customer-trust operations. | Evydence is self-hosted and release-evidence-specific. It can produce technical evidence inputs, but it does not claim legal compliance or certification. |
| Syft, Grype, Trivy, and other scanners/generators | Strong at generating SBOMs, scan findings, and technical outputs. | Evydence records those outputs, preserves hashes, links them to release context, and documents decisions, gaps, limitations, and package verification. |
| Internal scripts, spreadsheets, object storage, and ad hoc databases | Flexible and fast for a small team. | Evydence provides stable API contracts, idempotency, tenant scope, append-only evidence behavior, audit-chain records, package schemas, and reusable verification commands. |

## Why Evydence Exists

Release review commonly needs a single answer to a concrete question:

> What technical evidence supports this release, what decisions were made, what
> gaps remain, and what can be shared safely?

Evydence focuses on that release-level answer:

- release-scoped artifacts, SBOMs, scans, VEX, provenance, controls, decisions,
  exceptions, and approvals;
- append-only evidence lifecycle and audit-chain records;
- signed release bundles and verification receipts;
- customer-safe packages with redaction, limitations, and non-claims;
- self-hosted storage and operator-controlled trust boundaries.

## When Another Tool Should Lead

- Use scanners to discover findings.
- Use SBOM generators to produce component lists.
- Use dependency-inventory tools for component management at scale.
- Use GUAC-style graph tooling when supply-chain graph exploration is the
  primary question.
- Use OpenVEX-focused tooling when the immediate task is authoring VEX
  statements outside a release package workflow.
- Use GRC platforms for broad organizational compliance workflow.
- Use trust centers for public or customer-facing distribution workflows.
- Use Evydence when the release team needs a reproducible evidence ledger and
  package for a specific product release.

## Boundaries

Evydence supports compliance readiness and technical evidence organization. It
does not make legal compliance conclusions, grant certification, prove SBOM
completeness, treat scanner output as authoritative, or guarantee release
security.
