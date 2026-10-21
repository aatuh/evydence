# GitHub repository controls

This reference is for maintainers verifying provider-side controls on
`aatuh/evydence`. Configuration files and local tests cannot establish that
GitHub enforces a setting. The live verifier reads the provider and emits a
dated, allowlisted JSON assessment. It never changes settings.

## Verify the provider

Install Python 3 and GitHub CLI, authenticate `gh` for `github.com`, and use
an identity with repository administration access and permission to read
collaborators, rulesets, branch protection, security settings, and CodeQL
analyses. Credentials stay in the operator's existing `gh` authentication;
never put tokens in command arguments, report files, or the repository.

```sh
scripts/verify_github_controls.sh > /tmp/evydence-repository-controls.json
# Equivalent live target:
make repository-controls-check
```

Exit `0` means every required observation passed. Exit `1` means at least one
control failed or is unknown. Invalid arguments exit `2`. Read the `controls`
and `observations` objects before diagnosing a failure. Missing access, malformed
responses, pagination exhaustion, or provider timeouts cannot produce a pass.
The script supports `--repo owner/repository`; the policy always inspects
`master` and requires that it is the repository's default branch.

Each report records UTC observation time, remote `master` SHA, local verifier
commit and dirty status, and the verifier file's SHA-256. These are distinct
identities: a local commit may not be published. A dirty report identifies the
checked script bytes but does not prove the complete local tree is committed.
Do not cite a successful settings report as CI evidence for an unpublished
commit. Retain the report with the corresponding source and validation logs.

## Required profile

| Surface | Required observation |
| --- | --- |
| Repository | Expected owner/name, active repository, default branch `master`, administrative visibility |
| Master checks | `Production Check`, `CodeQL Analyze`, and `Race and Stress`, each bound to GitHub Actions app `15368`; strict/up-to-date enforcement |
| Master updates | Pull requests required, stale approvals dismissed, no PR bypass users/teams/apps, administrator enforcement enabled, conversations resolved; force pushes and deletion disabled |
| Independent review | One human writer: zero required independent approvals. Two or more human writers: at least one approval and approval of the latest push by another reviewer |
| Release tags | Active tag ruleset covering `refs/tags/v*`, without exclusions or bypass actors; updates/deletion blocked and the same app-bound checks enforced on creation |
| Security features | Secret scanning, push protection, Dependabot alerts/security updates, and private vulnerability reporting enabled |
| Code scanning | Successful CodeQL analysis for the observed remote `master` SHA and `refs/heads/master` |

The collaborator list is paginated and must be fully visible. Bots do not count
as independent human reviewers. A solo profile still requires a pull request,
maintainer self-review, and passing checks; it does not provide independent
review. Add an independent maintainer and raise the approval count before
claiming a two-person review control. `CODEOWNERS` describes ownership; it is
not an enforced approval gate in the solo profile.

GitHub rejects organization-only user/team bypass restrictions on a personal
repository. The verifier accepts an absent bypass-allowance field only when
the authenticated repository response identifies a personal (`User`) owner;
administrator enforcement is still mandatory. Organization-owned repositories
must expose explicitly empty user, team, and app bypass lists.

Existing status-check aggregation is deliberate: `.github/workflows/ci.yml`
runs `make openapi-breaking-check` and `make production-check` under
`Production Check`; the latter includes SDK validation. API compatibility and
SDK checks therefore have a required aggregate gate. CodeQL and race/stress
have their own required jobs. Scheduled Scorecard and tag-triggered artifact
packaging must not be required to create the very tag that triggers them.

Commit-signature enforcement is recorded as an optional observation. It is not
required by this profile, and this profile does not claim signed Git tags.
Release artifact signatures and trust-policy verification are separate from
GitHub reference protection; see [release signing](../release-signing.md).
Normal merge commits remain allowed. The verifier checks this canonical
branch-protection profile and a complete tag ruleset; it does not attempt to
prove arbitrary combinations of partially overlapping rulesets equivalent.
Tag rules enforce commit checks and reference immutability; they do not prove
that a commit is an ancestor of `master`, that an artifact matches the tag, or
that a person reviewed it. Maintainers must release reviewed `master` commits
and retain the separate release-validation evidence.

## Verified observation

The [2026-10-21 11:55:52 UTC refresh](repository-controls-2026-10-21T115552Z.json)
again passed all 18 observations for the same remote `master` source, with one
human writer. It used the unchanged verifier from clean local commit
`a1205e2b4129b6a7c789744d0625d056955790cf`. The
[11:41 refresh](repository-controls-2026-10-21T114107Z.json) and
[11:04 refresh](repository-controls-2026-10-21T110422Z.json) are retained.
This is a settings observation;
it does not establish new role acceptance or hosted CI for local development.

### Original configuration record

On 2026-10-19 at 09:30:20 UTC, the live script exited `0`: all 18 required
observations passed for remote `master`
`d77b612bc72192f9ef97283c83aa5e9d7bb26aab`, with one human writer and zero
required independent approvals. GitHub returned active tag ruleset `25392663`
with no bypass actors. This replaced the earlier administrator-bypass posture;
the three existing app-bound required checks and strict master enforcement
were preserved. The [sanitized provider report](repository-controls-2026-10-19T093020Z.json)
records clean local verifier source `3a60efa5ff61a5fb3611b61a085484043f4e08ed`
and verifier SHA-256
`a7b0470ab91c3f2f6878c27606f496e041f5e25c9254e75b125ef20d4efc14c8`.
The root backlog retains local validation and archive evidence. This report
does not establish hosted CI success for that unpublished verifier commit.

## Refresh and limitations

Run the live verifier after settings or collaborator changes and before each
release. Recheck monthly while the repository is active. The maintainer owns
remediation; retain the previous dated report when collecting a new one.
Administrators can change repository settings themselves, so a passing report
does not establish permanent or tamper-proof governance.

Offline regression checks require no GitHub credentials or network:

```sh
make repository-controls-test
make docs-check
```

Only the first target is a small Python/shell test. Documentation and broader
project gates can compile Go and must use the host RAM coordinator where the
host requires it. Offline checks run in CI; live administrative reads remain
an explicit operator action. Tests use a fake `gh` and cover app bindings,
review/bypass rules, release-tag creation checks, pagination, malformed and
oversized responses, provider timeouts, wrong CodeQL references/commits, and
secret-free output.

GitHub's [ruleset reference](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
and [REST rules API](https://docs.github.com/en/rest/repos/rules) define the
provider semantics. This control report supports engineering review; it is
not legal compliance proof, certification, or a secure-release guarantee.
