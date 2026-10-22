# Source Package Admission Decisions

This reference is for maintainers integrating dependency checks.
`scripts/dependency_admission.py` applies the repository policy to changes between
fresh in-memory [trusted Git collections](dependency-collection.md). It has no
CLI that accepts a PR-supplied saved report as verified evidence.

This is a **partial source-package decision**. The result separately records
`package_decision_passed` and `dependency_coverage_verified: false`. Image/package
joins, complete scope handling and hosted workflow
enforcement remain incomplete under EVY-1407. A passing partial decision must
never be used as the final CI admission verdict.

## Policy And Change Selection

[`release/dependency-policy.json`](../../release/dependency-policy.json) is the
initial machine-readable policy. It lists exact allowed identifiers and
license/exception pairs, with no exception entries. The existing offline
SPDX/exception parser validates it; these are technical review rules, not a
determination of legal compatibility or license obligations. Existing inventory
records are not retroactively approved by adding this file.

The policy loader reads only this path from the explicitly selected **current
target base** using Git objects. It verifies regular-blob mode, bytes and hashes
before parsing. Neither the proposed head, the older comparison merge base nor
the owner's working-tree policy supplies a fallback. The trusted caller must
bind that base to authenticated PR context. Git identity alone is not independent
review proof. A proposed policy change cannot authorize its own dependency change.
The public branch lacks this policy until normal reviewed integration occurs.

Component identities use ecosystem, name and exact version. New identities,
new origins and changes to source/license observations are reassessed. An
existing QA dependency moved into an application origin is not silently treated
as unchanged. Removing a component or only removing origins does not cause it to
be readmitted. Duplicate identities, invalid context, unsupported origins and
oversized component sets fail validation. Public decisions omit raw source and
provider prose and retain source-observation hashes.

Effective licenses come from the collector's candidate, artifact-declaration or
recorded-fixture-declaration states. Unknown/ambiguous/missing states supply an
unknown license. Candidate text remains a heuristic observation. For supported
advisory observations, the existing strict policy evaluator blocks disallowed or
unknown licenses, high/critical findings and unknown-severity findings. A removed
dependency is not admitted just because it appears in a diff.

Exception syntax still requires exact scope, owner, reason, bounded expiry and
review. The [live review verifier](dependency-review.md#exact-exception-review)
now requires an authenticated owner-authored exact-scope payload, rechecked after
assessment. URL syntax alone cannot activate a waiver. Expired well-formed base
entries are inactive and cannot prevent their own cleanup. There are no fabricated
approvals or blanket waivers for current unknown inventory records.

## Advisory Observations

`scripts/dependency_advisories.py` queries OSV for Go, npm and PyPI names/versions.
It sends the exact collected version, normalizes Python names and retains Go's
version prefix. OSV interprets its ecosystem version rules; an observation
describes indexed matches, not complete vulnerability detection or symbol
reachability. See [OSV's package/version API](https://google.github.io/osv.dev/post-v1-query/).

The client uses a fixed HTTPS POST endpoint, no inherited proxy/authentication,
no redirects and bounded JSON. It follows pagination fully or returns unknown.
A complete empty provider response means no indexed match was returned for that
query. Unsupported ecosystems, unavailable responses, invalid/mismatched package
records, unmapped advisory IDs and exhausted bounds retain `vulnerabilities:
null`; they never become an empty passing list.

Matching records retain policy-supported GHSA/GO/CVE identities, using aliases
where available. Public summaries, details, references and contact fields are
omitted. Qualitative provider severity labels are combined conservatively;
unknown labels or absent labels remain unknown. The client does not calculate
CVSS scores or infer low severity from an unparsed vector. Valid withdrawn
records are recorded separately. A provider match is an input for review, not
scanner authority or proof of exploitability.

Each observation has its query coordinates/time and response-receipt indexes.
Receipts hash actual request/response bytes without publishing their bodies.
Per-response JSON is limited to 4 MiB; a client permits 64 MiB total responses,
1,024 requests, 4,096 cached components, eight pages and 128 source advisory
records per component. Exhausted/incomplete lookups block package admission as
`advisory_coverage_unknown`. Calls are serial; run local collection/decision
orchestration under the host RAM gate.

## Verification And Remaining Work

`make dependency-admission-test` runs advisory, admission, review and trusted
caller regressions without network access. It is included in `make docs-check`, which
also compiles Go tools and requires a suitable RAM reservation.

Real OSV queries for historical lodash, jwt-go and PyYAML versions returned
indexed findings. A fixture scope stayed unsupported with unknown findings.
A separate integration probe used real OSV data with explicitly synthetic Git/
collection contexts and the actual policy bytes; it blocked known findings and
disallowed/missing licenses. Those are not current-repository vulnerability
findings, verified archive-license evidence or hosted CI proof.

The final `make dependency-policy-check` is not present yet. Complete scope and
provider joins and hosted negative cases must be integrated before that gate can
certify the ticket. The [trusted caller](dependency-review.md) connects current
source-package decisions and live review checks while preserving coverage gaps.
Required vulnerability/release gates remain pending until EVY-1407 is ready for
closure. No repository setting, push, workflow dispatch or release is performed
by these libraries or their tests.
