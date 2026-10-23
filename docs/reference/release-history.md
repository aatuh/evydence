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

Release helpers are included in the native-boundary source review. After
reviewing a helper change, refresh its checksum and scoped findings in
`internal/platform/config/testdata/native-boundary-review.json`. Preserve the
checksum guards; this local source review does not establish independent review.

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
The PR that first introduces this policy may target a pre-adoption base: the
recorded public release must precede that base, and the pinned adoption source
must belong to the exact PR head. The whole PR still needs a changed fragment
or verified label. Existing post-adoption base deliveries retain their checks;
the bootstrap path does not waive missing notes on already governed commits.
Committed first-parent deliveries without fragments require a matching merged
PR, bound to its exact merge commit and label through the associated-PR and
full-detail APIs. Label removal causes subsequent checks to reject the waiver.
Use the label only when the maintainer has explicitly decided a public change
description is unnecessary. The generic generated entry still records that
other source changes exist.

The first policy integration requires a normal merge that preserves the pinned
adoption commit as an ancestor. Squashing that initial integration removes the
required ancestor and causes subsequent checks to fail. On an already governed
base, normal merges and squash merges group a PR delivery. Rebase merges must
carry a fragment in each material commit; do not use them to distribute a single
final fragment across earlier commits. No provider data is stored as claimed review
proof. Fragment-only delivery checking works offline; label waivers require
live read access. GitHub documents the
[PR detail](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request) and
[associated PR](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit)
APIs and their read permissions. CI supplies the number through
`EVYDENCE_CHANGELOG_PULL_REQUEST` and a read-only Actions token; label changes
rerun ordinary PR CI without executing contributor code in a privileged
`pull_request_target` workflow.

## Candidate Notes And Local Tagging

`scripts/release_notes.py` inventories the actual OpenAPI contract, SDK paths,
and SQL migration changes against the selected public release source. New
changes in these inventories require matching fragment impact declarations.
Pre-adoption changes remain in the inventory and preserved history, without
being attributed to a new tooling fragment. File inventories do not establish
semantic API compatibility or a successful upgrade; the corresponding project
gates and operator review remain required.

Choose a candidate version, replace the placeholder below, and generate its
source notes through a temporary preview. Copy only after generation succeeds,
so an invalid input cannot truncate existing candidate notes:

```sh
TAG=vX.Y.Z-rc.N
python3 scripts/release_history.py render --write
mkdir -p tmp
python3 scripts/release_notes.py --tag "$TAG" render > tmp/release-notes-preview.md &&
  cp tmp/release-notes-preview.md "docs/reference/release-notes-$TAG.md"
make changelog-check
```

Review the fragments, compatibility declarations, migration inventory, security
notices and limitations, then commit the notes and matching source changes.
The template supplies the supported profile and non-claims; a generated draft
does not prove qualification or independent review. Source identity is bound
by the packaging manifest, allowing notes to be committed without a circular
reference to their own future commit SHA.

After the required release qualification, run the local preflight:

```sh
python3 scripts/release_notes.py --tag "$TAG" check
python3 scripts/release_notes.py --tag "$TAG" tag
```

The `tag` command is read-only by default. Explicit `tag --create` creates a
local unsigned annotated tag only on clean `master`, after verifying exact
committed notes, generated changelog, withdrawal policy and source identity.
It records the notes SHA-256 in the annotation and never pushes or overwrites
a tag. The operator's configured Git identity is used; hooks and automatic
tag-signing commands are disabled. Publisher authentication remains the
separate manifest/workflow identity profile.

The helper does not establish passing production gates or authorize publication.
Run every [candidate gate](release-candidate.md#required-commands) and satisfy
provider protection before pushing a tag or dispatching publication. Privileged
raw Git/provider actions can bypass local tooling; no stronger provider
enforcement is implied by this helper.

Candidate packaging requires this matching committed notes file before running
production validation or replacing an artifact directory. It emits the exact
validated text into `release-notes.md`, which remains in the checksum and signed
manifest subjects. Validation, attestation and draft publication compare the
packaged notes with the same source projection. There is no static-template
fallback for missing candidate notes. The release workflow retains a concrete
notes preview before builds and protected-environment approval.

## Earlier History

The adoption policy pins the real earlier release source and the SHA-256 of the
manual `Unreleased` section at the adoption source. Generation moves that exact
section under a historical source heading in the same file, preserving its links
and all previously published sections. Its contents describe development at
that snapshot; they do not assert a new release, current qualification, or
independent review. The generated section links this history while the selected
public release predates adoption. Later release ranges use their new fragments.

The [2026-10-21 local qualification record](release-history-2026-10-21-local.json)
identifies the tested source, compiler security repair, full matrix, preserved
attempts and evidence archive. It does not establish current-source hosted CI,
independent review or publication.
