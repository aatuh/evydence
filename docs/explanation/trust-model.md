# Trust Model

Evydence records technical evidence, hashes payloads, links evidence to products and releases, and records append-only audit-chain entries. It supports reproducible review by exposing evidence gaps, assumptions, exceptions, waivers, verification receipts, and report limitations.

Evydence trusts tenant-scoped API keys and SSO session tokens after server-side hash verification. Instance-wide diagnostics require the explicit `instance:admin` scope; tenant `admin` and wildcard tenant keys remain tenant-scoped unless that scope is also present. Collector identity is derived from the collector API key binding. Customer portal access uses expiring package tokens and exposes scoped package manifests, not raw tenant evidence. Repeated failed portal attempts revoke the access record without storing the supplied token.

Provider metadata such as GitHub Actions, GitLab, DSSE, VEX, SBOM, OpenAPI, scanner payloads, and SSO provider records is treated as uploaded evidence unless a configured trust root or verification path proves more. Current SSO support records provider metadata, identity links, expiring sessions, local OIDC token verification, local SAML assertion verification against tenant-configured trust material, OIDC discovery/JWKS refresh, optional OIDC UserInfo validation when a caller supplies an access token, and an optional operator-controlled provider validation gateway. It does not include direct provider-specific management API clients, browser login callbacks, or external group synchronization. Structural parsing is not the same as provider truth or cryptographic trust.

Verification endpoints return a versioned machine result and a named assurance
profile. A result is `passed` only when every check required by that profile
was recorded and passed. Missing, warning, unknown, or mixed skipped checks are
`limited`; all required checks deliberately skipped are `skipped`; absent
profile or evaluation evidence is `not_verified`; a failed required check is
`failed`; and an evaluation error is `error`. The profile records non-secret
trust-material identifiers or classes, canonical input, identity and issuer
policy, transparency, clock and revocation treatment, payload scope/digest,
required checks, offline inputs, and limitations.

Recorded metadata, cryptographic validity, trusted identity, and transparency
verification are separate layers. A submitted certificate identity does not
prove who signed a payload until a profile has verified the certificate and
compared it with an expected identity supplied by the caller or tenant policy.
The Cosign endpoint verifies explicit offline Sigstore bundles with
operator-configured trust material. Keyless requests must provide exact expected
identity and issuer values; the receipt records only verified values and safe
library/trust-root versions. An online-required request fails rather than
downgrading to metadata. The offline DSSE profile verifies DSSE PAE, in-toto Statement v1,
the SLSA provenance v1 predicate, a configured builder and required claims, and
registered release-artifact subjects against an explicit tenant Ed25519 root.
It does not establish certificate-chain trust, transparency, CI runtime
integrity, provenance completeness, or historical-key validity. See [the
cryptographic trust-model ADR](../adr/0002-cryptographic-trust-model.md)
and [Verification results](../reference/verification-results.md).

## Audit-Chain Tamper Evidence

Audit-chain verification recomputes the versioned canonical hash for each stored entry, then checks tenant ownership, sequence continuity, previous-entry linkage, entry hash, and any referenced signature. A signed Merkle checkpoint or signed release-manifest checkpoint also binds a selected sequence range or head hash, so verification can detect a missing prefix or a rewritten covered entry after that checkpoint was created. Legacy `audit-chain-entry.v1.0.0` records use their documented legacy canonical fields; when PostgreSQL has retained only microseconds, verification deterministically checks the compatible sub-microsecond timestamp values. New entries use `audit-chain-entry.v2.0.0`, whose canonical timestamp is normalized to PostgreSQL microsecond precision and whose hash covers identifiers, request and idempotency metadata, payload reference hash, signature reference, and metadata.

These mechanisms provide tamper evidence for the records and signing material being verified. They do not independently protect against a privileged database administrator who can rewrite every database record, replace tenant signing keys, and alter or remove all checkpoints. Operators should protect signing-key custody separately and preserve or independently verify checkpoints outside the mutable database when protection against that threat matters. A local signed checkpoint is not evidence of external publication or third-party log inclusion.

Reports are readiness and evidence-organization outputs. They do not state legal compliance, certification, complete SBOM coverage, authoritative vulnerability results, or secure releases.
