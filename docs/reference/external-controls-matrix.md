# External Controls Matrix

This reference separates what Evydence implements from what operators,
providers, and reviewers must configure or assess for regulated or high-trust
self-hosted deployments. It supports readiness review only. It is not legal
compliance proof, certification, complete SBOM proof, authoritative
vulnerability coverage, auditor acceptance, or a secure-release guarantee.

Owner labels:

- `repo-owned`: implemented, documented, or checked by this repository.
- `operator-owned`: deployment team must configure, run, or retain evidence.
- `provider-owned`: cloud, identity, registry, KMS, storage, or CI provider
  supplies the authoritative control surface.
- `legal/review-owned`: counsel, auditor, customer, or internal risk owner must
  review suitability.

| Control area | Primary owner | Evydence repo evidence | External evidence required |
| --- | --- | --- | --- |
| PostgreSQL durability | operator-owned | Production startup requires `EVYDENCE_DATABASE_URL`; migrations and restore rehearsals are checked by project gates. | Backup schedule, retention, restore test logs, access controls, encryption settings, and target RPO/RTO acceptance. |
| Object storage durability | operator-owned/provider-owned | S3/MinIO adapter, tenant-prefixed object keys, object digest checks, and retention-intent records. A current `verified` retention result requires a recorded provider/bucket observation, mode, duration, applicable sample-object/legal-hold evidence, and a bounded observation age; unavailable, incomplete, or stale observations remain distinct. | Bucket policy, versioning, lifecycle, replication, encryption, retention, object-lock/WORM configuration, provider audit output, and deployment-specific review of the recorded observation. |
| KMS/HSM signing custody | operator-owned/provider-owned | Signing executor ports, AWS KMS, GCP KMS, Azure Key Vault, HTTPS signing gateway, and custody review records. | Key policy, hardware or service custody proof, rotation procedure, break-glass procedure, provider logs, and role separation review. |
| TLS and network exposure | operator-owned/provider-owned | Helm/Compose docs require external TLS and protected diagnostics. | Ingress/TLS config, certificate lifecycle, firewall rules, private network boundaries, and authenticated metrics/admin access proof. |
| Identity provider and SSO | operator-owned/provider-owned | OIDC/SAML trust material records, local assertion/token verification, session records, and audit entries. | Provider tenant config, issuer/audience ownership, MFA policy, group lifecycle, disabled-user sync, and provider availability evidence. |
| CI provider provenance | operator-owned/provider-owned | GitHub Actions build metadata, structural DSSE/in-toto/SLSA parsing, collector keys, and CI upload examples. | Branch protection, required workflow policy, runner trust, OIDC token policy where used, protected environments, and provider audit logs. |
| Container registry trust | operator-owned/provider-owned | Optional maintainer GHCR workflow, image digest evidence, cosign verification output, and release evidence index. | Registry access policy, image admission policy, mirror/rebuild evidence, vulnerability scan evidence, and deployed immutable digest records. |
| Backup and restore operations | operator-owned | Backup/restore runbook and repository-owned restore rehearsal checks. | Deployment-specific restore rehearsal, credential recovery procedure, object/database consistency checks, and escalation ownership. |
| Monitoring and alerting | operator-owned/provider-owned | Safe metrics, readiness endpoints, starter Prometheus rules, and dashboard assets. | Scrape authentication, alert routing, on-call schedule, log retention, incident escalation, and dashboard review for the deployment. |
| Incident response | operator-owned/legal/review-owned | Incident resources, signed webhook-safe ingestion, incident package reports, and runbook guidance. | Incident commander ownership, disclosure policy, customer notification process, evidence retention, and post-incident review. |
| Retention, legal hold, and WORM | operator-owned/legal/review-owned/provider-owned | Retention markers, legal-hold records, tombstones, append-only verification observations, freshness status, and audit-chain entries. Local intent alone is `not_verified`; this evidence does not establish legal sufficiency. | Applicable retention schedule, legal-hold approval, provider-enforced retention proof, current provider configuration, and deletion/exception review. |
| Customer package sharing | operator-owned/legal/review-owned | Redaction profiles, package manifests, package downloads, viewer, portal access, and package verification commands. | Recipient authorization, NDA or sharing policy, package expiry, customer-specific redaction approval, and legal/commercial review. |
| Audit/legal sufficiency | legal/review-owned | Tamper-evident records, release bundles, reports, limitations, assumptions, and verification receipts. | Auditor/customer acceptance criteria, legal interpretation, framework-specific control mapping review, and sign-off outside Evydence. |

Evydence can record external evidence and verify the local records it generates.
It cannot independently prove provider-side configuration, legal sufficiency,
regulatory acceptance, scanner completeness, or that a release is secure.
