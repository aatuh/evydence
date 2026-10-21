# Maintainer Continuity Plan

This reference is for the maintainer and a designated recovery operator. It
defines responsibilities, access evidence and recovery decisions for Evydence.
Operational commands remain in the linked release and incident runbooks.

**Status: prepared plan; continuity is not established.** No independent backup,
accepted succession appointment or funded continuity arrangement has been
verified. EVY-1601 remains incomplete. This document does not establish
independent review, uninterrupted support or a 9/10 trust assessment.

## Current Evidence

On 2026-10-21, the [live controls report](repository-controls-2026-10-21T110422Z.json)
passed all 18 observations for remote `master` at
`d77b612bc72192f9ef97283c83aa5e9d7bb26aab`. It observed one human writer and
zero required independent approvals. The unchanged verifier ran from clean
local commit `04579681c3cd692cf3ad6266952c9d22cd39e5ee`; this is distinct from
the remote source and does not prove hosted CI for local development.

`GOVERNANCE.md` identifies Aatu Harju (`@aatuh`) as the current maintainer.
`CODEOWNERS` names only this existing reviewer. Existing authority is documented
below; acceptance of this continuity plan and independent coverage remain open.

| Function | Current authority | Coverage still needed |
| --- | --- | --- |
| Maintainer | `@aatuh`: scope, contributions, trust policy and public claims | Named accepting backup; owner-transfer and account-recovery evidence |
| Release manager | `@aatuh`: release decisions and protected-environment review | Accepted delegate, publisher authority and a nonpublishing recovery rehearsal |
| Security responder | `@aatuh`: security decisions through the private route in `SECURITY.md` | Accepted responder and backup with verified private-intake access |
| Independent reviewer / continuity operator | No appointment verified | Named acceptance and verified permissions, or a documented funded mechanism with named operators |

Do not add a proposed person to `CODEOWNERS` or describe an invitation as an
accepted role. A funded arrangement needs a named operator, agreed scope, funded
term, escalation route and verified recovery access; a proposal alone is not
evidence. Keep contractual details and private contact information outside Git.

## Authority And Least Privilege

The current maintainer approves appointments, asset transfer and trust-policy
changes. A release manager can coordinate a reviewed release but receives only
the permissions needed for its approved workflow. A security responder uses
private intake and coordinates triage, containment and disclosure. A backup's
written delegation must name which functions it can assume, activation triggers
and the person who authorizes activation.

This is a personal-account repository. GitHub distinguishes its single owner
from collaborators, whose access includes writes; it does not offer the same
role granularity as an organization. Record each actual grant rather than
assuming that a role title confers administration or recovery rights. See
[personal repository permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository).

An additional human writer requires the team profile in
[repository controls](repository-controls.md): at least one non-author approval
and latest-push approval, with all required app-bound checks and administrator
enforcement preserved. Verify that profile before relying on the new access.
`CODEOWNERS` currently documents ownership, not independent approval enforcement.

## Asset And Recovery Register

The maintainer owns completion of this register. Public configuration identifies
an asset; it does not establish billing, registrar, account-recovery or backup
access. Record private recovery-material locations as opaque references only.

| Asset | Observed configuration or source | Required recovery evidence / present gap |
| --- | --- | --- |
| GitHub account `aatuh` and repository `aatuh/evydence` | Personal ownership and live repository controls verified | Owner's separate recovery methods and accepted successor/backup not verified |
| Release environment `release-production` | Signing policy names reviewer `aatuh`, branch `master`; live custody check passed on 2026-10-21 | Backup review/administration and token replacement authority not verified |
| Release publisher credentials | `EVYDENCE_RELEASE_PUBLISH_TOKEN` and `EVYDENCE_GHCR_PUBLISH_TOKEN` are environment-scoped; repository copies/old signing secret retired | Private inventory must name issuers, owners, expiry, rotation and recovery operators; secret presence does not prove grants or expiry |
| Signing trust and historical releases | `release/signing-policy.json`, per-run keys and workflow identity; preserved legacy pins | Delegate must verify exact issuer/workflow/ref/source and retain historical evidence; retired private keys are not a recovery route |
| GHCR target `ghcr.io/aatuh/evydence` | Configured by `.github/workflows/container-image.yml` | Package metadata returned HTTP 403 to the audit identity; package ownership, inheritance and backup publishing rights remain unverified |
| Domain `evydence.app` | Committed CNAME and live Pages custom-domain setting with HTTPS enforcement | Registrar, DNS administrator, renewal payer/date, transfer authority and backup access are not verified |
| GitHub Pages | Workflow deployment for `https://evydence.app/` observed | Verify delegate access to Pages/environment and domain recovery separately; use the canonical site guide |
| Private security intake | GitHub private reporting enabled in the controls report | Each appointed responder must demonstrate access without copying private reports into public evidence |

The [asset observation](continuity-2026-10-21-observations.json) separates provider
reads, source configuration and unknowns. Update this register after verification;
do not infer a domain owner or registry administrator from a GitHub username.

## Activate A Role

1. Record the person's GitHub handle, accepted responsibilities, activation
   authority, acceptance date and public acknowledgement reference. Retain
   private contact and recovery details in the owner's access-controlled store.
2. Grant only the approved access through provider-supported mechanisms. The
   assignee uses their own identity and authentication methods. Verify accepted
   grants; an invitation or a maintainer's unconfirmed assertion is insufficient.
3. Recheck repository controls and release custody using the canonical guides.
   Verify private-intake, Pages, registrar/DNS and package permissions separately
   for any delegated function; the repository verifier does not cover them all.
4. Rehearse a read-only inspection and a nonpublishing local release verification
   from the recorded source. Confirm that the assignee can find recovery records
   without exporting their contents. Publishing, token rotation and ownership
   transfer require their own approved execution and retained receipts.
5. Have the maintainer review the evidence and update `CODEOWNERS` only for actual
   reviewers. Record remaining gaps before considering EVY-1601 complete.

Use an acceptance record with: role, handle, scope, accepted-at date, evidence
reference, verified provider grants, rehearsal date/result and next review date.
No such new acceptance record is established by this prepared plan.

## Recover Access Or Transfer Ownership

For temporary account lockout, follow GitHub's
[account recovery procedure](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/recovering-your-account-if-you-lose-your-2fa-credentials).
Keep multiple recovery methods available privately. GitHub cannot restore an
account when all required recovery methods are lost. Never put recovery codes,
passwords, security-key material or session credentials in this repository.

A GitHub successor must accept the appointment. That mechanism covers public
repository transfer/archive after GitHub's deceased-user process; successors
cannot sign into the original account. It does not provide routine incident
coverage or domain/package recovery. See
[successor appointment](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/maintaining-ownership-continuity-of-your-personal-accounts-repositories)
and [successor capabilities](https://docs.github.com/en/repositories/creating-and-managing-repositories/access-to-repositories#about-successors).

For a planned transfer, agree the recipient and delegated authority first, then
follow [GitHub's transfer procedure](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository).
Preserve Git history, release tags and published artifact digests. Recheck
repository protection, package ownership/linkage, environment reviewers, Pages
and custom-domain control after transfer; GitHub documents that repository,
package and Pages behavior differ.

Repository/owner changes also affect Evydence's pinned publisher identity,
workflow subjects, links and Go module paths. Prepare a reviewed compatibility
and trust-policy change before moving publication. Preserve old verification
identities and historical evidence rather than silently rewriting them.

For credential loss, an authorized issuer replaces and revokes publisher tokens
through [release signing](../release-signing.md). Verify custody, exact scopes
and expiry before relying on replacement credentials. Per-run signing keys are
ephemeral; never reintroduce `EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64` as a
fallback. Existing copies outside the repository cannot be assumed destroyed.

For domain or registry loss, the accepted operator uses the provider's verified
recovery route and private asset record. Confirm domain renewal and DNS/HTTPS
state, and package owner, access and immutable digests. Until ownership/access is
restored, stop affected publication and report the limitation through the
authorized project channel. The [site guide](../how-to/publish-marketing-site.md)
owns site/DNS validation; the signing guide owns publisher verification.

## Emergency Patch Authority And Review

The current maintainer authorizes emergency fixes. An accepted backup may act
only within recorded delegation. Use the normal protected PR and required CI
path, approved release workflow and verification policy. Emergency status does
not waive checks, permit edits to historical evidence or authorize unsigned
replacement assets. If access or required checks are unavailable, contain the
incident and suspend publication while escalating privately.

Follow [incident response](../runbooks/incident-response.md),
[key rotation](../runbooks/key-rotation.md) and
[release withdrawal](release-revocation.md) for compromise. Keep sensitive
details private and preserve earlier releases with explicit withdrawal notices.

Review role acceptance, private contact reachability, recovery records and asset
renewal at least monthly and after any role, access, account, token or ownership
change. Record the review date, reviewer, evidence and unresolved gaps. Repeat
the nonpublishing rehearsal when recovery authority changes. No rehearsal or
independent continuity coverage has yet been verified for this plan.
