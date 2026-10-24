# Trusted Dependency Review Caller

This reference is for maintainers integrating the dependency admission gate.
`scripts/dependency_review.py` connects the authenticated GitHub reader,
Git-verified source collection, source-package decisions and scoped exception
review. It runs trusted code from its own checkout; proposed source remains data.

**Hosted qualification remains in progress under EVY-1407.** The caller connects
declared source, image and pinned Go tool changes through an explicit combined
coverage profile. `make dependency-policy-check` and the trusted workflow are
implemented; successful local tests do not prove hosted enforcement. Unsupported
scope or missing evidence cannot become a passing check.

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
trusted driver bytes, Action repository visibility/tag bindings and the UTC
assessment day. A source or approval change
fails without an observation. Crossing midnight requires a rerun, preventing
waivers from surviving their expiry day because collection began earlier.
Outputs omit raw source, review bodies, private paths and provider prose. They
include source metadata, hashes of canonical collection JSON, trusted driver
hashes, provider receipts, source, image and bundled tool decisions and coverage gaps.
These checks share the advisory client and combine their actually used
exception reviews for a final approval recheck. These semantic hashes
are not claimed as hashes of a separately saved byte stream.

Use a trusted checkout, the exact compiler selected by the target support policy
and existing VM scratch/cache configuration:

```sh
"$HOME/.local/bin/codex-ramgate" 4 -- python3 scripts/dependency_review.py \
  --pull-request "$EVYDENCE_PULL_REQUEST" \
  --base "$EVYDENCE_TARGET_BASE" --head "$EVYDENCE_SOURCE_COMMIT" \
  --head-repository "$EVYDENCE_HEAD_REPOSITORY" \
  --syft "$DEPENDENCY_IMAGE_SYFT" \
  --work-root /mnt/vm-storage/VMs/evydence-dev-1001/tmp \
  --output tmp/takeover/dependency-review.json
```

All IDs are expected live PR values, not a request to trust supplied JSON.
`DEPENDENCY_IMAGE_SYFT` selects the existing qualified scanner installation.
`--syft` can be omitted when no changed registry image requires scanning.
Exit 0 is reserved for a complete verified passing verdict, 1 means a written
blocked/incomplete observation, and 2 means invalid context, failed providers,
unsafe output or unavailable trusted policy. `--replace` only replaces the same
schema and protects concurrent output edits. No push, review/comment creation,
merge, dispatch, branch-protection update or check publication occurs in this CLI.

## Final Gate And Combined Coverage

The Makefile command reads these environment values as argument data:

| Variable | Value |
| --- | --- |
| `DEPENDENCY_PULL_REQUEST` | Current open PR number targeting `master`. |
| `DEPENDENCY_TARGET_BASE` | Exact current target commit, full Git SHA. |
| `DEPENDENCY_SOURCE_COMMIT` | Exact current PR head commit, full Git SHA. |
| `DEPENDENCY_HEAD_REPOSITORY` | Current PR head repository, `owner/repository`. |
| `DEPENDENCY_WORK_ROOT` | Existing private scratch directory outside the proposed tree. |
| `DEPENDENCY_OUTPUT` | New relative report filename under the trusted checkout; parent directory must exist. |
| `DEPENDENCY_SYFT` | Optional qualified Syft executable; changed registry images require it. |

Set these from the live PR and existing VM scratch configuration, then run:

```sh
"$HOME/.local/bin/codex-ramgate" 4 -- make dependency-policy-check
```

The target calls the same CLI with `--environment`. Missing or malformed context
fails before provider work. Values are never expanded into shell source, and
`--environment` cannot be combined with CLI overrides. The gate performs actual
authenticated review, not just offline regression tests. `GH_TOKEN` or existing
GitHub CLI authentication must permit the required read APIs.

`scripts/dependency_coverage.py` qualifies
`declared-dependency-changes-linux-amd64.v1`. Both fresh in-memory collections
must match freshly read immutable Git inputs, required manifest families and
schema checks, the exact trusted collector drivers, generator hashes, compiler
and base-built classifier receipt. Known source types also require the expected
verification profile and origins. Images are resolved by the separate image
profile; local Action references and unsupported scopes remain explicit gaps.

The combined decision requires both qualified source profiles, image coverage,
tool coverage and all package decisions. The standalone source library retains
its partial coverage flag; it cannot authorize the complete result itself.
The collector's inventory `complete: false` is preserved. This profile covers
declared dependency changes, with the documented scanner/source limits; it is
not a complete artifact SBOM or assurance of license compatibility or safety.

## Trusted Hosted Workflow

[`.github/workflows/dependency-review.yml`](../../.github/workflows/dependency-review.yml)
runs on every PR targeting `master`, using `pull_request_target` and an explicit
checkout of the event's base SHA. The evaluation job has only contents/PR read
permissions, disables checkout credentials and shared Go caches, and installs
target-pinned Python wheels and scanner tooling. Proposed Git bytes are data;
no proposed workflow, Makefile, Python/Go code or package lifecycle hook runs.
Actions use full commit pins. Hosted jobs use dedicated ephemeral runners;
local work on the shared development machine still requires the host RAM gate.

The evaluation job runs regressions and the actual final gate. It uploads only
the sanitized fixed report path for 14 days, including a blocked report when
available; private scratch and proposed source are not uploaded. Failure and
missing-context exits remain failures. No path filters or manual input can
skip admission while claiming success.

`pull_request_target` uses the base-branch context, so a separate reporter job
posts the fixed **Dependency Policy** check on the exact PR head. It has the
additional `checks: write` permission, executes only target-base reporter code,
and never consumes proposed artifacts or report bodies. The reporter validates
the Actions event/repository/ref/base, run identity and actual evaluation job
result, then rechecks the current PR/base/head/repository before writing.
Only evaluation `success` produces check success; failure/skipped/cancelled
outcomes map to failure. The trusted evaluation records its UTC day immediately
before admission; missing/stale day metadata also produces failure, so reporter
setup cannot carry an expiring waiver across midnight. The response must retain the exact head/check identity
and GitHub Actions app binding. A cancelled workflow may leave no new head
result and needs a normal rerun. See GitHub's
[trusted-event guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
and [required-check SHA rules](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

The reporter is a provider mutation reserved for this trusted hosted path.
Local qualification uses mocked write responses and does not publish checks.
Activating the workflow, verifying success/negative cases and adding the exact
head check to required branch protection still need real hosted evidence and
the corresponding maintainer approval. Existing required checks are preserved.

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

An empty GitHub Action comparison finding list cannot supply independent advisory
coverage for a commit pin. The separate profile below is required; an unsupported
or unavailable lookup retains null findings and blocks. Action entrypoints,
bundled libraries and runtime downloads retain their existing source-observation
limits; this is not a complete artifact SBOM.

## SHA-Pinned Action Advisories

GitHub documents that Action alerts are generated for semantic versions, not SHA
versions in its [ecosystem reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems).
`scripts/dependency_action_advisories.py` addresses that gap using the fresh
trusted collection's exact repository, subdirectory and commit identities.
Public visibility and repository identity are checked before reading tags.
All full release tags pointing to the pin are retained, including their actual
`v` prefixes. Floating major aliases cannot establish a full version. A pin
without a usable full release tag remains unsupported with null findings.
Subactions query their parent repository while retaining their actual component
path/commit for policy and waiver scope.

For every mapped version, the client reads GitHub's
[global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories#list-global-security-advisories)
with an exact `ecosystem=actions` and `affects=repository@version` filter. It
checks reviewed, unreviewed and malware records. It follows bounded cursor
pagination and requires next-page URLs to preserve the fixed host, endpoint and
filters. Results must name the requested Action repository. Severity is combined
conservatively across records, versions and the ordinary dependency comparison;
missing labels stay unknown. A failed page/type/query cannot become an empty
passing observation. These are catalog observations, not proof of code safety or
complete vulnerability detection.

The public repository and full tag associations are rechecked before caller
output. Moving/deleting a tag, adding another matching full version, changing
visibility or exhausting bounds fails verification. Tags are publisher metadata;
this dated association check does not make them immutable. No Action entrypoint
or bundled program is executed. Raw descriptions, contact fields and archive
URLs are omitted. `action_advisories` contains filtered bindings, observations,
rechecks and separate tag/advisory receipts. Its advisory receipt indexes refer
to that section's advisory receipts; top-level `advisory_receipts` contains the
ordinary OSV request receipts.

Tag and advisory clients each allow 256 requests, 4 MiB per response and 32 MiB
total response bytes. Tags use at most 20 pages of 100 entries and 32 matching
full tags per pin. Advisory pages use 100 records; each kind is bounded by 20
pages and 128 findings, with at most 128 combined active findings per query.
HTTP headers are capped at 64 KiB. Exhaustion produces unknown coverage. A live
qualification control retained the known high-severity historical
`GHSA-mrrh-fwg8-r2c3` through the direct GitHub API; OSV version queries did not
retain that control finding during qualification. This profile therefore uses
the directly qualified GitHub source for Actions. The historical control is
independent of the repository's currently collected pins and is not a hosted
admission verdict.

## Declared Image Changes

`scripts/dependency_image_admission.py` derives both declaration sets from their
verified Git inputs and freshly collected Action references. It writes a separate
private discovery view, replacing proposed generator code with actual trusted
Python bytes and target-base helper source bytes. Original and substituted hashes
are distinct. Its small Action-reference projection is bound to the complete
source inventory by separate hashes; unrelated package graphs are not copied
into the image-discovery input. Files stay private and non-executable. Discovery
checks the export before/after and rechecks trusted generator bytes.

The profile covers changes at stable declaration locations for Linux amd64.
An Action commit change alone does not rename its runtime-image origin.
Unchanged declarations and removals require no scan or new approval. New origins
are reassessed even when that image already appears elsewhere. Local fixture
recipes bind the Dockerfile and exact supported Compose build context/target;
changing the recipe under the same tag is a change. Additional unsupported build
arguments fail validation. New source-built artifacts and unresolved operator
choices produce blocking coverage gaps until qualified artifact handling exists.

Changed registry images use the qualified scanner's fixed platform/cataloger
profile, selected manifest/config identities and actual scanner-output digest.
Image entrypoints are not executed. Baseline package observations can reduce
reassessment only for an immutable digest declaration at the same origin.
A floating baseline tag cannot prove prior contents; its omission means all
proposed packages need admission. Changed versions, license/source observations
and new origins are checked; unknown package versions remain blocking when an
image is replaced. A scan with no package observations cannot pass.
Each side's package/origin join is capped at 8,192 records, preventing many
origins from multiplying otherwise bounded package lists without a total limit.

Scanner license declarations stay distinct from module-source candidates. A
missing Go license can use a verified source observation only when exact module
coordinates and the binary build-info `h1` sum match. Conflicting observations
stay unknown and block. Version strings alone do not establish this binding or
prove binary/source equivalence. APK records qualified as metadata-only by the
[source projector](dependency-policy.md#declared-image-observations) have explicit
`not-applicable-package-record` advisory status, null findings and
`not-applicable-no-payload` license applicability. Other unknowns retain ordinary
license/advisory enforcement and the existing reviewed-waiver requirements.

`image_coverage_verified` describes coverage of changed declarations in this
bounded profile, not an exhaustive artifact SBOM or baseline approval.
`image_decision_passed` also requires every assessed package to pass. Both are
required by the caller. Source-level provider Docker/root-image additions still
remain visible and blocking as unmatched records until their exact-source join
is completed; an image package result cannot erase them. Runtime downloads,
arbitrary build outputs, other architectures and hosted enforcement remain
outside this qualification.

## Pinned Go Tool Artifacts

`scripts/dependency_tool_admission.py` handles changed Helm and oasdiff roots
from the fresh trusted collection. A provider-forced root assessment takes the
same path. The published archive version, binary-recorded main module/version
and Go compiler version remain distinct. The main module must match the closed
tool profile and exact release version, including Helm's recorded `v` prefix.

The profile fetches the official checksum-pinned archive, rechecks its binary
digest and classifies its root notices with the shared base-built helper.
`scripts/dependency_tool_buildinfo.py` validates the complete bounded archive
before writing only the named executable to a private, exclusive mode-0600 file.
It runs the qualified local `go version -m -json` reader on that file as data;
the downloaded tool is never executed. The binary digest is checked again after
inspection. Output retains public module coordinates/checksums and Linux amd64
platform metadata, omitting linker flags, VCS settings and local replacement paths.

Bundled dependency entries require exact versions and checksums; the root main
version is bound separately to the checksum-pinned release archive. The profile
requires no replacements and recorded CGO disabled. Unknown/development versions, missing dependency checksums,
unsupported platform/native linkage and inconsistent metadata fail validation.
They cannot acquire an empty advisory list or a passing tool verdict.

`scripts/dependency_tool_sources.py` downloads explicit public Go modules with
credentials, VCS fallback and toolchain switching disabled. It copies bounded
module ZIPs into private scratch, recomputes Go's `dirhash.Hash1` over their
sorted filenames/content and requires the binary-recorded `h1` checksum.
ZIP paths, duplicate entries, file types, CRCs and compressed/expanded budgets
are checked before root license bytes reach the verified classifier. Cached
metadata alone cannot establish those source bytes. Source hashing follows
the qualified Go reader's `cmd/vendor/golang.org/x/mod/sumdb/dirhash/hash.go`.

Compiler license observations come from that exact Go release's Linux amd64
`golang.org/toolchain` module, fetched into a fresh private cache with SumDB
enabled and its ZIP checksum independently recomputed. Compiler binaries in
that archive are data and are never executed. The recorded compiler version
supplies the explicit Go `stdlib` advisory query; it does not supply versions
for unknown main modules or dependencies.

Every bundled module and the standard library receive separate license and
advisory decisions under current-target policy. Their exact-scope waiver proofs
join the caller's final live recheck. Root Apache/MIT notices cannot admit a
child package. Unknown or conflicting license classifications and unavailable
advisories remain blocking. A changed tool readmits its bundled modules because
it creates a new artifact context even when a module already occurs elsewhere.

Limits are 512 distinct source requests, 500 MiB per compressed or expanded ZIP,
65,536 ZIP entries, 32 root notices of at most 1 MiB each and 2 GiB aggregate
expanded source bytes. The parent retains its 8,192 decision bound. The scope is
changed pinned Go tool artifacts, not a complete artifact SBOM, cryptographic
proof of binary/source equivalence, reachability analysis or license approval.

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
That historical probe preceded normal trusted adoption. The policy/tooling
was adopted through [PR #30](https://github.com/aatuh/evydence/pull/30), followed
by the compiler-bootstrap correction in
[PR #38](https://github.com/aatuh/evydence/pull/38) on 2026-10-24. Their merges
do not turn the earlier probe into passing hosted enforcement evidence.
Fresh unmerged controls [#39](https://github.com/aatuh/evydence/pull/39),
[#40](https://github.com/aatuh/evydence/pull/40), and
[#41](https://github.com/aatuh/evydence/pull/41) targeted the adopted source.
Their source-bound artifacts verified complete declared-change coverage and
the expected native results: allow CC0, reject CC-BY-3.0, and reject high
`GHSA-cxww-7g56-2vh6`. The reporter created the exact app-bound head checks but
then rejected GitHub's canonical `/runs/<check-id>` response URL. These controls
were closed unmerged with their branches retained; their failed reporting jobs
do not qualify the full workflow. A test-first response-compatibility repair
accepts only the requested workflow URL or the exact returned check's canonical
URL, preserving check/head/run/app validation. Normal adoption, fresh full
workflow controls and required-check activation remain pending.
