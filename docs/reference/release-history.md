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
The CLI currently requires fragments for material deliveries; provider label
verification is a separate integration step.

## Earlier History

The adoption policy pins the real earlier release source and the SHA-256 of the
manual `Unreleased` section at the adoption source. Generation moves that exact
section under a historical source heading in the same file, preserving its links
and all previously published sections. Its contents describe development at
that snapshot; they do not assert a new release, current qualification, or
independent review. The generated section links this history while the selected
public release predates adoption. Later release ranges use their new fragments.
