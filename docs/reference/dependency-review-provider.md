# Dependency Review Provider Reader

This reference is for maintainers integrating PR dependency checks. The reader
in `scripts/dependency_review_provider.py` observes authenticated GitHub metadata
for one open PR against `aatuh/evydence`'s `master`. It does not execute PR code,
change GitHub settings or approve dependencies.

The output explicitly sets `dependency_coverage_verified: false`. A successful
read is a source observation, not a passing dependency-policy or hosted CI check.
Full inventory coverage, trusted policy selection and workflow integration are
still required under EVY-1407.

## Source Binding

The caller supplies the PR number, exact target-base and head commit SHAs, and
expected head repository. The reader checks the live PR before and after its
requests. A changed head, base, fork identity, file count or open state fails.
`--event` instead accepts a GitHub `pull_request` or `pull_request_target`
payload with the same fields; unsupported event types and conflicting explicit
arguments fail. Parsing an event file does not authenticate its origin. A CI
caller must use GitHub's actual event and a trusted reader checkout.

The authenticated commit comparison identifies the merge base separately from
the target base. The source comparison therefore preserves `base`,
`comparison_base` and `head`, plus their tree identities. GitHub's
[dependency-diff API](https://docs.github.com/en/rest/dependency-graph/dependency-review)
resolves the effective merge base for the supplied commit pair. This endpoint
has no documented page parameter; the reader makes one bounded request rather
than inventing pagination.

The PR file list is paged and checked against the reported file count. Both
recursive Git trees must be untruncated. The reader reconstructs Git's tree
objects, verifies directory ordering and modes, and checks their SHA-1 Git
identities. It then requires the listed file paths/blob IDs to match the entire
merge-base/head tree difference. Renames include the old path; mode changes
remain changes even with an unchanged blob ID. Git filenames such as Astro's
`[...slug].astro` stay data, with traversal, control characters and ambiguous
paths rejected. Nothing is extracted, checked out or executed from these trees.

These checks prove the observed Git/file correspondence; they do not verify the
content, license or security of every changed blob. Dependency manifests in the
provider response must be regular blobs in the corresponding source tree.

## Dependency Rows

The reader validates every dependency record with
`scripts/dependency_comparison.py`, retaining exact manifest/package identity,
license and advisory ID/severity fields. Provider prose, PR bodies, labels,
contact fields, patch bodies and arbitrary URLs are omitted from output.
Raw-response byte counts and SHA-256 receipts identify the authenticated reads.

GitHub's Go versions are normalized to the inventory's `v`-prefixed coordinates
by the comparison adapter. Observed legacy Go removals may have an unversioned
package URL; these still require an explicit valid version and exact name and
are never admitted as additions. Added dependencies require the URL's exact
version. Unknown licenses and advisory severity remain subject to the strict
[offline admission rules](dependency-policy.md#implemented-admission-rules).

An empty dependency diff is not proof of complete coverage. Fixture, custom
Go/scanner locks, downloaded tools and image scopes need explicit comparison
against trusted source observations. Returned rows alone cannot establish that
GitHub recognized every relevant dependency source.

## Requests And Limits

Only fixed-repository GET endpoints on `github.com` are permitted through an
authenticated GitHub CLI. The environment passes only the CLI path/home and its
GitHub credentials; ambient proxy and other project credentials are omitted.
Authentication/provider/JSON failures have no anonymous or empty-success fallback.
Errors omit tokens, raw responses and CLI diagnostics. The
[documented API permissions](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files)
are contents read for dependency/Git data and pull requests read for PR metadata.
No write permission or PR-comment permission is needed.

Each JSON response is limited to 4 MiB, all responses to 32 MiB, API requests
to 48, files to 2,048, and each recursive tree to 8,192 entries and 64 path
components. PR file pages contain at most 100 rows. GitHub documents a
3,000-file API ceiling; this reader uses a stricter local bound and fails on
excess, missing pages, duplicates, tree truncation or inconsistent identities.
Successful output replaces only the same schema with explicit `--replace`;
symlinks, unrelated files and concurrent output edits are protected.

## Run And Check

For the previously pushed PR #30 source, the verified read command was:

```sh
"$HOME/.local/bin/codex-ramgate" 1 -- python3 scripts/dependency_review_provider.py \
  --pull-request 30 \
  --base d77b612bc72192f9ef97283c83aa5e9d7bb26aab \
  --head efced49e2837c5369f0a89f4a6b46e5b6ceba512 \
  --head-repository aatuh/evydence \
  --output tmp/takeover/evy1407-pr30-review-observation.json --replace
```

Those identities describe the earlier public branch, not current local `master`
or a new CI qualification. A changed PR source requires new expected identities;
a saved observation must not be treated as a fresh authenticated decision.
The local qualification used a 512 MiB cgroup memory cap and no swap.

`make dependency-review-provider-test` runs isolated provider/event/tree/CLI
regressions. Git's local `hash-object` supplies an independent tree-hash oracle;
no tests make real provider calls. `make dependency-policy-test` includes the
comparison adapter regressions. Both are included in `make docs-check`, which
also compiles Go tools and must use a suitable RAM reservation.
