# Design Partner Pilot

This page describes a narrow paid pilot shape for teams evaluating Evydence as a
self-hosted release evidence ledger. It is commercial positioning, not a legal
compliance statement, certification, audit opinion, complete SBOM claim,
authoritative vulnerability assessment, or secure-release guarantee.

## Pilot Offer

We wire one software product release into Evydence, ingest SBOM,
vulnerability-scan, VEX/provenance, and artifact evidence, produce one signed
customer-safe evidence bundle or package, and review the self-hosted deployment
profile with the operator.

The goal is to prove whether Evydence can organize, verify, and present the
technical evidence a release team already has, while making gaps, assumptions,
exceptions, and limitations explicit.

## Ideal Customer Profile

This pilot is a fit when the team:

- ships software products where release evidence is requested by customers,
  procurement, internal security, or engineering leadership;
- can run a self-hosted service with PostgreSQL, object storage, TLS, backups,
  and operator-owned secrets;
- already generates at least one SBOM and one vulnerability scan result in CI or
  release tooling;
- wants VEX-style vulnerability decisions and customer-safe package outputs;
- accepts a controlled self-hosted candidate profile with one API writer replica
  and scalable worker replicas.

It is not a fit when the team needs a hosted SaaS service, broad GRC workflow,
legal compliance determination, certification, scanner replacement, or
regulator/auditor-ready evidence without independent review.

## Deliverables

- One agreed product and release modeled in Evydence.
- One SBOM upload path and one vulnerability-scan upload path connected to the
  release.
- One VEX document, manual vulnerability decision, or approved exception path
  for an intentionally reviewed finding.
- One artifact digest and release bundle generated through Evydence.
- One customer-safe package or evidence bundle with manifest, verification
  material, limitations, and non-claims.
- One deployment-profile review using the
  [pilot deployment checklist](../how-to/pilot-deployment-checklist.md).
- One short findings summary covering implemented evidence, gaps, assumptions,
  and next steps.

## Non-Deliverables

- Legal compliance advice or certification.
- A guarantee that the release is secure.
- A completeness guarantee for SBOM contents.
- A completeness or authority guarantee for scanner output.
- Hosted SaaS operation by default.
- Replacement of customer security review, external audit, or legal review.
- Unlimited integration work, custom UI, or provider-specific development beyond
  the agreed pilot scope.
- Public disclosure of customer data, secrets, raw evidence payloads, private
  keys, bearer tokens, database URLs, provider credentials, or unreleased
  product details.

## License And Commercial Path

Evydence is available under `AGPL-3.0-only`. Teams that can comply with AGPL
obligations may evaluate and operate the public code under that license.

Commercial license exceptions and paid self-hosted support are available when
AGPL obligations are not suitable for a proprietary deployment, private
distribution model, or internal commercial use. See
[Commercial licensing](../../COMMERCIAL.md) for the current license boundary.

## Support Boundary

Pilot support focuses on the agreed deployment, evidence workflow, package
verification, and documentation. Operators remain responsible for infrastructure
controls such as TLS, network policy, backup tooling, secret storage, object
storage retention, KMS/HSM configuration, identity-provider configuration, and
incident response.

Bug reports and security reports must be sanitized. Do not send raw customer
evidence, tokens, private keys, database URLs, object-store credentials, or
unredacted vulnerability reports through public channels.

## Pilot Exit Criteria

- The agreed release evidence flow runs end to end.
- The customer-safe package verifies offline and states its limitations.
- The deployment checklist is completed or has explicit accepted gaps.
- The operator can explain backup, restore, signing, redaction, and scoped
  access responsibilities.
- Follow-up work is separated into repo-local product gaps, deployment
  responsibilities, and external provider dependencies.
