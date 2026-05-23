# Trust Model

Evydence records technical evidence, hashes payloads, links evidence to products and releases, and records append-only audit-chain entries. It supports reproducible review by exposing evidence gaps, assumptions, exceptions, waivers, verification receipts, and report limitations.

Evydence trusts tenant-scoped API keys and SSO session tokens after server-side hash verification. Collector identity is derived from the collector API key binding. Customer portal access uses expiring package tokens and exposes scoped package manifests, not raw tenant evidence.

Provider metadata such as GitHub Actions, GitLab, DSSE, VEX, SBOM, OpenAPI, and scanner payloads is treated as uploaded evidence unless a configured trust root or verification path proves more. Structural parsing is not the same as provider truth or cryptographic trust.

Reports are readiness and evidence-organization outputs. They do not state legal compliance, certification, complete SBOM coverage, authoritative vulnerability results, or secure releases.
