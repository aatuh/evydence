# Solo-Maintainer Ownership And Recovery

This reference records who runs Evydence and how to recover its project assets.
Aatu Harju (`@aatuh`) is the sole maintainer, release decision-maker and security
responder. On 2026-10-21 the maintainer confirmed this operating model and
requested a plan proportionate to a solo-maintained repository.

There is no backup maintainer or funded continuity arrangement. If the owner is
unavailable, reviews, releases and security response may wait. Another person is
optional future capacity, not a prerequisite for development or EVY-1601.
This plan does not establish independent review, tested account recovery or
uninterrupted support, and does not raise the project's trust score.

## Ownership And Access

`CODEOWNERS` names the actual owner, `@aatuh`. The owner makes release and
security decisions and handles private reports through [SECURITY.md](../../SECURITY.md).
Use the normal protected PR path, maintainer self-review and every required CI
check, including for emergency patches. See [review policy](maintainer-review-policy.md).

No additional access is needed for the current model. If another person joins,
agree their responsibilities, grant only the necessary permissions and verify
access before listing them as a reviewer. A second human writer activates the
team approval requirements in [repository controls](repository-controls.md).

## Owner's Recovery Checklist

Keep credentials, recovery codes, private contacts and billing details in a
private password manager or other access-controlled recovery store, never Git.

| Asset | Recovery action |
| --- | --- |
| GitHub account and repository | Keep separate account recovery methods available; follow [GitHub account recovery](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/recovering-your-account-if-you-lose-your-2fa-credentials) if access is lost. |
| Release publishing | Keep publisher token issuer, expiry and replacement instructions privately. Replace/revoke credentials using [release signing](../release-signing.md), then verify custody. Retain the protected environment and exact publisher identity policy. |
| Signing and historical evidence | Preserve published tags, artifact digests and trust records. Per-run keys are ephemeral; do not restore the retired repository signing secret as a fallback. |
| `ghcr.io/aatuh/evydence` | Keep the package account and access information privately; verify ownership and publishing access before replacing a token or transferring a repository. |
| `evydence.app` and Pages | Keep registrar/DNS access and renewal details privately. Use the [site guide](../how-to/publish-marketing-site.md) to verify DNS, HTTPS and deployment after recovery. |

If access is lost or compromise is suspected, suspend affected publication and
follow [incident response](../runbooks/incident-response.md),
[key rotation](../runbooks/key-rotation.md) and
[release withdrawal](release-revocation.md). Preserve historical evidence; an
emergency does not waive checks or permit replacing published assets in place.

For a future ownership transfer, agree the recipient first and use
[GitHub's transfer procedure](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository).
Review repository controls, environments, package access and domain ownership
separately. Owner changes also need a reviewed publisher-identity and module-path
compatibility plan; preserve the verification identities of older releases.

Review the checklist before a release and after account, token or ownership
changes. Check domain renewal and recovery-method availability periodically.
Private recovery custody and a recovery rehearsal have not been verified by
this documentation work.

## Observed State And Limits

The [2026-10-21 controls report](repository-controls-2026-10-21T114107Z.json)
passed all 18 observations for remote `master` at
`d77b612bc72192f9ef97283c83aa5e9d7bb26aab`, with one human writer. The unchanged
verifier ran from clean local commit `144b45418f2ebd5b8fb1b80cd99bf82231a32a07`.
This verifies settings, not hosted CI for unpublished local commits.

Earlier [asset observations](continuity-2026-10-21-observations.json) confirmed
Pages at `evydence.app` with HTTPS. Package metadata returned HTTP 403, so registry
permissions remain unknown; registrar, renewal and private recovery access were
not verified. That dated record describes the earlier, broader proposal. The
maintainer's solo-maintenance decision supersedes its delegated-role requirement
without changing the observations or claiming those gaps were tested.
