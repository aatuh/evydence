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
| Tenant signing key | Rotate the tenant signing key, record the key version, provider, fingerprint, validity window, and reason, then verify valid-at-signing behavior. | Review custody policy and provider access for private signing material. |
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

## Tenant Signing-Key Lifecycle

Tenant signing keys are versioned per signing provider. Evydence permits one
active key for a tenant/provider pair; a routine rotation retires the prior key
and records its `valid_until` time before publishing the replacement. Public
material is retained for historical verification, while private material is
never returned by the key-list or transition APIs.

Use an ordinary revocation when the key is no longer authorized but historical
signatures made inside its recorded validity window remain acceptable. Supply a
non-empty reason. Use `compromised` semantics only for a confirmed compromise,
with an explicit historical-validity policy:

- `preserve` keeps signatures that were valid at signing time.
- `invalidate_from_compromise` rejects signatures made at or after the recorded compromise time.
- `invalidate_all` rejects all signatures made by that key, including historical signatures.

The verification result is based on the persisted signature timestamp, key
lifecycle facts, and supplied verification time; it does not depend on the
operator's current wall clock. A compromise policy is evidence policy, not a
claim that every downstream package or external verifier has been notified.

## Rotation Rehearsal

Run this rehearsal before a planned production rotation and retain the resulting
audit entry and verification result with the change record.

1. Select a non-production tenant and create a release bundle signed by the current key.
2. List tenant signing keys and record the active key's version, provider, and public-key fingerprint; do not copy private material.
3. Rotate the key with a non-empty operational reason. Confirm the former key is `retiring`, has `valid_until`, and the replacement is the only `active` key for that provider.
4. Re-verify the bundle created before rotation and confirm it passes under the ordinary historical-validity policy.
5. Create and verify a new bundle with the replacement key.
6. Revoke the rehearsal replacement with an ordinary reason, confirm the audit transition, and archive the test-tenant results.

## Emergency Compromise Rehearsal

1. Pause the affected signing automation and identify affected tenant, provider, key version, and public-key fingerprint.
2. Create a replacement key through rotation; do not reactivate a suspected compromised key.
3. Revoke the affected key using `compromised` semantics with the approved historical-validity policy. Use `invalidate_all` only when the incident decision explicitly requires invalidating every historical result.
4. Re-run release-bundle and customer-package verification for every affected package scope. Record failures as new verification evidence; never edit old signatures or bundles.
5. Review provider/KMS/HSM audit logs and rotate any provider-side credentials separately. Record unavailable provider evidence as a limitation.
6. Resume automation only after it uses the replacement key and the tenant has exactly one active key for the provider.

## Rollback and Package Re-verification

Do not roll back by reactivating a retired or revoked signing key. If a newly
rotated key fails, keep the prior key's historical material intact, issue a
corrected forward replacement, and record the failure. For an ordinary
revocation, re-verify the affected release bundles and customer packages at the
documented verification time. For a compromised key, re-run verification using
the recorded compromise policy and distribute only newly generated package
verification results through the approved customer-access scope.

## Failure Handling

- If the new credential fails, keep the old credential revoked when exposure is
  suspected and issue a corrected replacement; do not reactivate it as a rollback.
- If historical signatures fail, do not rewrite past evidence. Record a
  verification failure and investigate valid-at-signing semantics.
- If a provider cannot prove custody or revocation, keep the affected profile
  marked as a limitation until provider evidence is available.
- Do not place replacement secrets, private keys, bearer tokens, database URLs,
  or raw evidence payloads in public issues, support requests, logs, or
  customer packages.
