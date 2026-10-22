# Trusted Dependency Review Caller

This reference is for maintainers integrating the dependency admission gate.
`scripts/dependency_review.py` connects the authenticated GitHub reader,
Git-verified source collection, source-package decisions and scoped exception
review. It runs trusted code from its own checkout; proposed source remains data.

**Complete admission remains in progress under EVY-1407.** The caller never turns
a partial package decision into a passing check. Declared image admission and
non-package scope/applicability work remain unfinished. Current successful
observations therefore exit 1 with explicit coverage gaps. The final required
`make dependency-policy-check` and hosted workflow are not installed by this unit.

## Caller Sequence And Outputs

The caller checks the expected PR/base/head/head-repository through authenticated
GETs and requires an up-to-date source branch: the comparison merge base must
equal the current target base. It loads policy from that target's Git blob and
validates proposed policy and its review records before heavy collection.
Proposed rules are checked but never applied to this dependency change. Neither
proposed policy nor an older merge base can authorize a change.

Both source catalogs are checked before helper builds. One verified target-base
classifier is shared across serial base/head collection, using its private home,
temporary directory and credential-free subprocess environment. No proposed
Python, Go helper, shell or package lifecycle code is executed. Every stage
retains the existing byte/path/size/identity limits.

Before writing output, the caller rechecks the PR, active reviews, executable,
trusted driver bytes and the UTC assessment day. A source or approval change
fails without an observation. Crossing midnight requires a rerun, preventing
waivers from surviving their expiry day because collection began earlier.
Outputs omit raw source, review bodies, private paths and provider prose. They
include source metadata, hashes of canonical collection JSON, trusted driver
hashes, provider receipts, decisions and coverage gaps. These semantic hashes
are not claimed as hashes of a separately saved byte stream.

Use a trusted checkout, the exact compiler selected by the target support policy
and existing VM scratch/cache configuration:

```sh
"$HOME/.local/bin/codex-ramgate" 4 -- python3 scripts/dependency_review.py \
  --pull-request "$EVYDENCE_PULL_REQUEST" \
  --base "$EVYDENCE_TARGET_BASE" --head "$EVYDENCE_SOURCE_COMMIT" \
  --head-repository "$EVYDENCE_HEAD_REPOSITORY" \
  --work-root /mnt/vm-storage/VMs/evydence-dev-1001/tmp \
  --output tmp/takeover/dependency-review.json
```

All IDs are expected live PR values, not a request to trust supplied JSON.
Exit 0 is reserved for a complete verified passing verdict, 1 means a written
blocked/incomplete observation, and 2 means invalid context, failed providers,
unsafe output or unavailable trusted policy. `--replace` only replaces the same
schema and protects concurrent output edits. No push, review/comment creation,
merge, dispatch, branch-protection update or publication occurs.

## Provider Findings And Source Observations

`scripts/dependency_review_join.py` requires authenticated exact-source provider
context. It normalizes Go version prefixes and Python names, unions findings
using the most conservative severity, and forces assessment for provider-added
components even if source identity/origin observations already existed.
Neither provider may erase the other's severe/unknown findings.

Verified artifact license observations are not replaced by missing GitHub
license metadata. Conflicting known provider/source licenses block. Cross-manifest
findings are preserved; unmatched additions remain visible and block the join.
Removed components are not readmitted. Known provider findings remain separately
visible even when the OSV lookup is unavailable and coverage stays unknown.

An explicit recognized GitHub Action comparison row supplies that Action's
GitHub advisory observation when OSV marks the ecosystem unsupported. It does
not supply arbitrary ecosystem coverage or replace failed OSV queries with an
empty list. Action entrypoints, bundled libraries and runtime downloads retain
their existing source-observation limits; this is not a complete artifact SBOM.

## Exact Exception Review

The [policy](../../release/dependency-policy.json) currently has no exceptions.
For an actual proposed waiver, the maintainer must approve its exact material
fields through an authenticated GitHub record. The verifier supports an owner
issue comment on a PR or a submitted `APPROVED` PR review. The reviewer profile
is the current sole maintainer, `aatuh`; an owner's comment works on their own
PR without requiring a second maintainer.

The raw comment/review body must be exactly the JSON object returned by
`dependency_exception_reviews.approval_payload(exception)`: schema
`evydence-dependency-exception-review.v1`, action `approve` and the canonical
exception SHA-256. The digest covers ID, dependency/version, kind/value, owner,
reason, review date and expiry. Only `review_url` is excluded because its comment
ID does not exist until publication. A general PR approval or prose comment
does not approve a waiver.

Prepare the exception data on a proposal branch with the intended UTC review
date, bounded expiry and a provisional PR URL. From trusted tooling, compute the
approval payload for those fields. The maintainer posts that JSON themselves,
then records its exact `#issuecomment-ID` or `#pullrequestreview-ID` reference in
the exception. The reference must be in `aatuh/evydence`. A plain PR/commit URL or
line-review comment is not accepted by this live profile. Normal reviewed policy
integration is still required; proposed policy cannot activate itself.

The read-only verifier checks actor/type/owner association, resource ID, parent,
URL, submission/update date, approved review state and payload. It checks again
after assessment; edits, dismissal or mismatched details fail. Request/response
hashes are provider receipts; review bodies and contact metadata are not exported.
GitHub documents the [comment GET](https://docs.github.com/en/rest/issues/comments#get-an-issue-comment)
and [review GET](https://docs.github.com/en/rest/pulls/reviews#get-a-review-for-a-pull-request).

Every proposed waiver needs valid review evidence before heavy collection. Old
base approvals are checked when a decision would actually apply their waiver.
An unrelated or removed waiver is not applied. This allows cleanup to remove a
revoked or deleted old approval without first restoring it. Changing a proposed
waiver cannot authorize the dependency in the same PR; only current base rules
are used for that decision.

Expired but otherwise well-formed base exceptions are recorded as inactive and
cannot waive findings. This permits a cleanup PR to remove them under the old
base. Invalid scope, duplicate IDs, malformed dates or a window over 90 days
remain errors. Working-tree policy validation still requires current entries.

## Qualification Limits

The isolated suites cover provider joins, scoped reviews, serial caller binding,
shared artifacts and fail-closed outputs. A read-only real PR #30 probe retained
280 dependency rows and 262 unmatched additions when deliberately supplied no
source graph; an existing owner comment did not authorize a synthetic waiver.
No real exception approval was created or inferred from those negative cases.
Current public master predates this policy/tooling, so the actual caller must
reject it until normal trusted adoption. Those observations are not passing
current-source hosted enforcement evidence.
