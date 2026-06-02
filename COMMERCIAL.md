# Commercial Licensing

Evydence is publicly available under the GNU Affero General Public License
version 3.0 (`AGPL-3.0-only`). The public license is suitable for users who can
comply with AGPL obligations, including source-availability obligations for
modified network-service deployments.

Commercial license exceptions are available for organizations that want to use
Evydence in proprietary products, private SaaS systems, closed internal
deployments, or other contexts where AGPL obligations are not suitable.

This is not legal advice. Have counsel review AGPL and any commercial agreement
before relying on it.

## License Decision Table

This table is a practical routing aid, not legal advice.

| Situation | Likely path to review | Why |
| --- | --- | --- |
| Evaluating Evydence locally, reading source, or running non-production tests | Public `AGPL-3.0-only` license may be enough if your use complies with AGPL. | The public repository remains available under AGPL. |
| Self-hosting Evydence for an internal team that can satisfy AGPL obligations | Public `AGPL-3.0-only` plus operator review may be enough. | You keep the public-license obligations and run your own deployment. |
| Modifying Evydence for a network service where AGPL source-availability obligations are acceptable | Public `AGPL-3.0-only` may be enough after counsel review. | AGPL is designed to preserve source availability for modified network services. |
| Embedding Evydence into proprietary products, private SaaS, closed appliances, or closed internal platforms where AGPL obligations do not fit | Discuss a commercial license exception. | A written exception can grant extra permission for a defined organization, product, deployment, or distribution model. |
| Needing private deployment review, upgrade planning, release evidence review, or integration support | Discuss commercial support. | Support scope, response expectations, and deliverables should be written down before relying on them. |
| Needing legal compliance conclusions, certification, secure-release guarantees, complete SBOM proof, or authoritative vulnerability results | Evydence is not the right source for that conclusion. | Evydence organizes technical evidence and limitations; legal, certification, audit, and security conclusions require separate review. |

For contribution rights, see [Contributing](CONTRIBUTING.md). For support
boundaries, see [Support](SUPPORT.md). For decision authority and product
language rules, see [Governance](GOVERNANCE.md).

## Paid Options

| Offer | Customer hosts? | Evydence hosts? | Notes |
| --- | ---: | ---: | --- |
| Commercial license exception | Yes | No | Written permission for agreed proprietary use cases. |
| Self-hosted support | Yes | No | Deployment review, upgrade help, troubleshooting, and security notices. |
| Release evidence readiness review | Yes | No | One scoped release workflow: install/configuration review, CI evidence upload, first customer-safe package, verification walkthrough, and limitations. |
| Release evidence package | Yes | No | SBOMs, vulnerability scan results, OpenAPI checksum, acceptance evidence, and hardening notes. |
| Production readiness review | Yes | No | Configuration, backup, restore, evidence handling, and deployment review. |
| Custom integration work | Yes | No | Collector adapters, evidence workflows, report templates, or deployment hardening. |

## Release Evidence Readiness Review

The default paid services shape is a scoped self-hosted release evidence
readiness review. It is meant for teams that want to prove one practical
workflow before deciding whether Evydence belongs in their release process.

Typical scope:

- install or review a self-hosted Evydence deployment profile;
- configure one product, project, release, artifact digest, and redaction
  profile;
- connect one CI path for SBOM, vulnerability scan, build, artifact, and release
  bundle evidence where the operator already has those files or commands;
- generate one customer-safe package or evidence bundle;
- run the package verifier and walk through reviewer-facing limitations,
  assumptions, gaps, and non-claims;
- document follow-up work as repo-local product gaps, operator-owned deployment
  responsibilities, or external provider dependencies.

Deliverables:

- short written readiness summary;
- completed or gap-marked deployment checklist for the reviewed profile;
- example upload or CI command path for the agreed release;
- one generated package or bundle with manifest, hashes, verification material,
  assumptions, limitations, and non-claims;
- prioritized next-step list for production hardening, integrations, or package
  sharing.

Out of scope unless separately agreed:

- legal compliance advice, certification, audit opinion, regulator acceptance,
  secure-release guarantee, complete SBOM proof, or authoritative vulnerability
  coverage;
- hosted SaaS operation by Evydence;
- unlimited custom collectors, scanner replacement, broad GRC workflow, or
  customer portal development;
- public handling of raw customer evidence, tokens, private keys, database URLs,
  provider credentials, or unreleased product details.

## Commercial License Scope

A commercial license is a separate written agreement. It does not remove or
reduce the rights granted to the public under AGPL. It can grant extra
permission for a named organization, product, deployment, or distribution model
where AGPL terms are not a fit.

Commercial terms can cover:

- proprietary embedding or distribution,
- closed-source network-service operation,
- private modifications without AGPL redistribution obligations,
- support and upgrade commitments,
- signed release and evidence delivery,
- self-hosted deployment review,
- collector or report integration work.

Commercial terms do not imply legal compliance, certification, secure releases,
complete SBOMs, authoritative vulnerability results, regulator acceptance, or
auditor acceptance. Evydence supports compliance readiness and technical
evidence organization only.

No SLA, warranty, compliance certification, hosted service, provider-side
completeness guarantee, or legal conclusion is included unless a written
agreement explicitly says so.

## Contact

For commercial licensing or paid support, contact Aatu Harju through LinkedIn:

<https://www.linkedin.com/in/aatu-harju>
