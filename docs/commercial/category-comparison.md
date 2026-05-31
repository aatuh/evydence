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
- Use GRC platforms for broad organizational compliance workflow.
- Use trust centers for public or customer-facing distribution workflows.
- Use Evydence when the release team needs a reproducible evidence ledger and
  package for a specific product release.

## Boundaries

Evydence supports compliance readiness and technical evidence organization. It
does not make legal compliance conclusions, grant certification, prove SBOM
completeness, treat scanner output as authoritative, or guarantee release
security.

