# Incident Response Runbook

Use this runbook for self-hosted Evydence operational incidents. It does not
replace the operator's security incident process.

## First 15 Minutes

1. Preserve logs, metrics, release evidence, and relevant configuration names.
2. Do not paste secrets, raw evidence payloads, customer data, bearer tokens,
   private keys, provider credentials, or database URLs into public channels.
3. Identify the affected boundary:
   API, tenant isolation, collector identity, SSO/session, object storage,
   signing provider, release package, customer portal, provider integration, or
   deployment infrastructure.
4. If API write integrity is uncertain, stop additional API writer processes and
   keep worker processing paused until object/database consistency is reviewed.
5. If a secret may be exposed, revoke or rotate the affected key/token before
   collecting broader diagnostics.

## Containment Checklist

- API key or collector key exposure: revoke the key, create a new scoped key,
  and review audit-chain entries for the affected actor.
- SSO/session exposure: revoke sessions, refresh trust material if needed, and
  review provider verification receipts.
- Object-store exposure: rotate object-store credentials, review bucket policy,
  and verify tenant-prefixed object access.
- Signing provider exposure: disable the provider, rotate/revoke keys according
  to provider policy, and verify valid-at-signing behavior for historical
  signatures.
- Customer package exposure: expire portal access, create a new redaction
  profile if required, and review package access records.
- Release artifact concern: verify `SHA256SUMS`, manifest signature, OpenAPI
  checksum, migration checksum, SBOM metadata, and provenance metadata.

## Communication

Use concise, factual updates. Do not claim legal compliance, certification,
complete SBOM coverage, scanner authority, or secure releases. State what is
known, what evidence was checked, what remains under review, and what operators
should do next.

## Post-Incident Evidence

- Incident timeline and remediation tasks in Evydence when the deployment is
  trusted again.
- Audit-chain verification result.
- Backup/restore verification if data integrity was in scope.
- Secret rotation evidence.
- Release or customer package re-issue evidence when affected.
- Limitations and assumptions for any report shared externally.
