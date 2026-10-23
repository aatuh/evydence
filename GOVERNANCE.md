# Governance

Evydence is currently maintainer-led.

## Maintainer

The project maintainer is Aatu Harju.

Evydence is maintained by one person. The
[ownership and recovery plan](docs/reference/continuity-plan.md) records the
maintainer's release and security duties and a private recovery checklist.
There is no backup maintainer or guaranteed response time; work may wait while
the maintainer is unavailable. Additional maintainers are optional future
capacity, not a prerequisite for continued development.

Commercial, support, trademark, security, or governance questions can be routed
through LinkedIn:

<https://www.linkedin.com/in/aatu-harju>

## Decision Model

The maintainer has final decision authority over:

- roadmap and release scope,
- license and commercial terms,
- security response,
- contribution acceptance,
- release evidence requirements,
- trademark and naming permission,
- claims and non-claims,
- supported collector, report, and deployment boundaries.

Large changes should preserve the project’s core invariants:

- evidence core fields remain immutable after creation,
- transitions, approvals, waivers, exceptions, audit entries, and chain entries
  stay append-only,
- every primary resource is tenant-scoped,
- API keys, collector keys, session tokens, portal tokens, private keys, raw
  evidence payloads, customer data, and unnecessary PII are not logged or
  exported,
- raw payload integrity, canonical hashes, signatures, and verification
  receipts remain reproducible,
- reports show evidence, gaps, assumptions, exceptions, and limitations,
- compliance and legal language stays conservative.

## Commercial Boundary

The public repository remains available under AGPL. Separate commercial license
exceptions, support agreements, release evidence packages, and self-hosted
support packages are handled outside the public issue tracker unless the
maintainer explicitly chooses otherwise.

Commercial work does not broaden Evydence’s public non-claims unless a signed
agreement explicitly narrows scope for that engagement.
