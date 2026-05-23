# Trust Model

Evydence records technical evidence, hashes payloads, links evidence to products and releases, and records append-only audit-chain entries. It supports reproducible review by exposing evidence gaps, assumptions, exceptions, waivers, verification receipts, and report limitations.

Evydence trusts tenant-scoped API keys and SSO session tokens after server-side hash verification. Instance-wide diagnostics require the explicit `instance:admin` scope; tenant `admin` and wildcard tenant keys remain tenant-scoped unless that scope is also present. Collector identity is derived from the collector API key binding. Customer portal access uses expiring package tokens and exposes scoped package manifests, not raw tenant evidence. Repeated failed portal attempts revoke the access record without storing the supplied token.

Provider metadata such as GitHub Actions, GitLab, DSSE, VEX, SBOM, OpenAPI, scanner payloads, and SSO provider records is treated as uploaded evidence unless a configured trust root or verification path proves more. Current SSO support records provider metadata, identity links, and expiring sessions; it does not perform live OIDC or SAML login verification. Structural parsing is not the same as provider truth or cryptographic trust.

Reports are readiness and evidence-organization outputs. They do not state legal compliance, certification, complete SBOM coverage, authoritative vulnerability results, or secure releases.
