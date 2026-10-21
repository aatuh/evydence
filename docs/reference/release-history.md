# Release History Reference

This reference describes source change fragments for contributors and release
maintainers. Publication and reviewer custody remain in
[release signing](../release-signing.md); support and withdrawals are defined by
[release support](release-support.md).

## Source Change Fragments

Each material source delivery after the adoption commit in
[`changes/policy.json`](../../changes/policy.json) must add or update a fragment
in `changes/fragments/`. A fragment covers its own commit, or the combined
first-parent delivery of a normal merge. An older unchanged fragment does not
cover a later source change. Commit subjects such as `chore:` or `refactor:` do
not exempt material changes. Tests, execution tracking and test fixtures alone
do not require a release entry; unknown paths are treated conservatively.

Use [`EVY-1408-release-history.json`](../../changes/fragments/EVY-1408-release-history.json)
as a shape example, choosing a distinct `EVY-<ticket>-<slug>` identity. Match the
filename to the `id` and supply every field:

| Field | Meaning |
|---|---|
| `schema` | `evydence-change-fragment.v1` |
| `id` | Stable ticket and change identity, matching the filename |
| `category` | `security`, `added`, `changed`, `fixed`, `deprecated`, or `removed` |
| `summary`, `details` | Bounded public change descriptions; Markdown is escaped |
| `compatibility` | Explicit `api` and `sdk` states (`unchanged` or `changed`), `migrations` (`none` or `required`), and explanatory `notes` |
| `security` | Security implications, including explicit limits |
| `limitations` | Nonempty list of remaining assumptions or limits |

Fragment contents are public. Do not put credentials, internal incident details,
or customer evidence in them. The schema rejects a claimed `reviewed` field:
local formatting cannot establish independent review. Published fragments are
immutable; add a new fragment for a correction.

## Generation And Checks

Preview to stdout, or explicitly replace the generated changelog after all
inputs validate:

```sh
python3 scripts/release_history.py render
python3 scripts/release_history.py render --write
make changelog-check
```

Do not redirect the preview into `CHANGELOG.md`: the shell would truncate the
input before generation. The write option checks the original file before an
atomic replacement and preserves it if validation fails or concurrent edits
are detected. `make docs-check` also runs this check.

The checker needs the recorded release and adoption Git ancestors, so CI must
use a full-history checkout. It does not fetch missing history. Pending source
edits need a pending valid fragment, which permits checking work before commit.
To check an open pull request as one delivery, use its GitHub number:

```sh
python3 scripts/release_history.py --pull-request 42 check
```

The reader authenticates through `gh` and fetches the PR from
`aatuh/evydence`. It requires `master` as the base, the exact current head or
GitHub's base/head synthetic merge, and the exact `no-changelog` label for a
delivery without a fragment. A local argument selects the PR to verify; it does
not grant an exemption. Provider failure or stale source identity fails closed.
Committed first-parent deliveries without fragments require a matching merged
PR, bound to its exact merge commit and label through the associated-PR and
full-detail APIs. Label removal causes subsequent checks to reject the waiver.
Use the label only when the maintainer has explicitly decided a public change
description is unnecessary. The generic generated entry still records that
other source changes exist.

Normal merges and squash merges group a PR delivery. Rebase merges must carry a
fragment in each material commit; do not use them to distribute a single final
fragment across earlier commits. No provider data is stored as claimed review
proof. Fragment-only delivery checking works offline; label waivers require
live read access. GitHub documents the
[PR detail](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request) and
[associated PR](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit)
APIs and their read permissions. CI supplies the number through
`EVYDENCE_CHANGELOG_PULL_REQUEST` and a read-only Actions token; label changes
rerun ordinary PR CI without executing contributor code in a privileged
`pull_request_target` workflow.

## Earlier History

The adoption policy pins the real earlier release source and the SHA-256 of the
manual `Unreleased` section at the adoption source. Generation moves that exact
section under a historical source heading in the same file, preserving its links
and all previously published sections. Its contents describe development at
that snapshot; they do not assert a new release, current qualification, or
independent review. The generated section links this history while the selected
public release predates adoption. Later release ranges use their new fragments.
