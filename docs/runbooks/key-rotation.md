# Key Rotation Runbook

Use this runbook when rotating Evydence API keys, collector keys, SSO/session
trust material, customer portal tokens, release signing keys, tenant signing
keys, or external signing-provider credentials. It is an operator procedure,
not a certification, compliance, or secure-release statement.

## Scope

Repository-owned behavior can revoke, replace, and audit Evydence-managed
credentials. Operator-owned infrastructure remains outside repository control:
identity-provider policy, KMS/HSM key custody, object-store credentials,
GitHub/GitLab secrets, branch protection, and incident notifications.

## Before Rotation

1. Identify the credential class and affected tenant, collector, release,
   package, or provider boundary.
2. Preserve current release, audit-chain, package, and verification evidence.
3. Decide whether rotation is routine, suspected exposure, confirmed exposure,
   provider compromise, or operator policy change.
4. Pause affected automation if the old credential may still be used.
5. Prepare a rollback or forward-fix plan. For suspected compromise, prefer
   revocation plus replacement over rollback.

## Rotation Steps

| Credential | Repository-owned step | Operator-owned step |
| --- | --- | --- |
| API key | Create a new scoped key, update callers, revoke the old key, and verify audit entries. | Remove the old secret from CI, shell history, secret managers, and runbooks. |
| Collector key | Create or update the collector-scoped key, restart the collector, and verify last-seen metadata. | Rotate provider-side CI secrets and pin the collector version used by jobs. |
| SSO/session trust | Revoke sessions and update configured trust material. | Rotate provider certificates, client credentials, group mappings, and session policy. |
| Customer portal token | Expire old package access, issue a new scoped token, and verify package access records. | Notify the recipient through an approved private channel. |
| Tenant signing key | Rotate the tenant signing key, keep historical public material, and verify valid-at-signing behavior. | Review custody policy and provider access for private signing material. |
| Release signing key | Generate a new release signing key, publish the new public key, and sign the next release manifest. | Protect the private key in the release workflow secret store. |
| KMS/HSM provider credential | Disable the old provider credential and record signing-provider verification receipts. | Rotate provider IAM, HSM partitions, network access, and audit logs. |

## Verification

After rotation:

1. Verify the affected actor can perform only the expected scoped operations.
2. Verify the old key, token, session, or provider credential is rejected.
3. Run the relevant package, release bundle, or audit-chain verification.
4. Check logs and metrics for authentication failures without recording the
   supplied secret value.
5. Record the rotation reason, actor, time, affected IDs, and residual
   limitations.

For release artifacts, verify the manifest and signature with
[Release signing](../release-signing.md). For customer packages, use
[Review a customer package](../how-to/review-customer-package.md). For
production readiness gates, use [Release validation](../reference/release-validation.md).

## Failure Handling

- If the new credential fails, keep the old credential revoked when exposure is
  suspected and issue a corrected replacement.
- If historical signatures fail, do not rewrite past evidence. Record a
  verification failure and investigate valid-at-signing semantics.
- If a provider cannot prove custody or revocation, keep the affected profile
  marked as a limitation until provider evidence is available.
- Do not place replacement secrets, private keys, bearer tokens, database URLs,
  or raw evidence payloads in public issues, support requests, logs, or
  customer packages.
