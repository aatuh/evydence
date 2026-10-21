# Dependency Policy

This reference is for contributors selecting dependencies and maintainers
reviewing their admission. **EVY-1407 is in progress.** The offline admission
rules and their regression tests exist. A bounded Go license-classification
helper passes focused tests on both supported compilers. The Go/Node collector
produces source-bound observations; complete scope, live PR review and the final release gate
are not yet integrated.
Passing these tests does not establish that the current dependency set has been
audited or that a real dependency addition would be rejected by hosted CI.

## Selection And Removal

Before adding a dependency, explain the concrete behavior it supplies and why
the standard library or an existing dependency is insufficient. Preserve the
required API toolkit foundation. Keep SDK wrappers minimal; a server or build
dependency is not automatically an SDK requirement.

Review the pinned source/version, release activity, archived status, security
advisories, license and redistribution requirements, platform/toolchain support,
transitive graph and replacement cost. An old release is a review signal, not
proof that a project is abandoned or vulnerable. Pin build tools and fixtures
as deliberately as runtime libraries. Do not automatically merge an update
without the required tests and review.

Remove unused dependencies when their imports or build steps disappear. Recheck
the graph and supported API/SDK behavior; do not retain a dependency solely for
an obsolete fixture or silently break a published interface to remove it.

## Implemented Admission Rules

`scripts/dependency_policy.py` is an offline library without network, subprocess
or filesystem effects. Its caller must provide trusted policy and verified
component metadata. `assess_component` requires explicit ecosystem, name,
version, license and vulnerability records. Missing or malformed records do
not become an empty, passing assessment.

- A license must satisfy the policy's explicit identifier list. Unknown values,
  including `NOASSERTION`, `UNKNOWN` and missing metadata, fail admission.
- Compound expressions preserve `WITH`, `AND`, `OR` and parenthesis precedence.
  An `OR` alternative can satisfy the license policy; every `AND` obligation
  must satisfy it. License identifiers ignore case; operators remain uppercase.
  A `WITH` permission applies only to the named license/exception pair. See
  [SPDX expression semantics](https://spdx.github.io/spdx-spec/v2.3.1/SPDX-license-expressions/).
- Expressions are limited to 2,048 ASCII characters, 128 tokens and 16 nested
  groups. Unsupported syntax and unresolved document-qualified references are
  rejected. The evaluator does not fetch or infer the terms behind a custom
  license reference, nor independently validate the SPDX license registry.
- Known high/critical advisories and unknown-severity advisories block admission
  for runtime, development and fixture components alike. Low/moderate findings
  still need triage; their admission is not a claim of safety.
- The JSON parser rejects duplicate keys, nonfinite numbers, invalid UTF-8 and
  documents over 4 MiB. Public errors omit raw manifest/provider content.

These are automated review rules, not a determination of legal compatibility
or fulfillment of attribution, source-offer or other license obligations.

## Exceptions

An exception must name one exact ecosystem/name/version and one license
expression or advisory ID. It cannot use wildcards, waive a different version,
or turn a license exception into an advisory waiver. Missing-license exceptions
must explicitly target `NOASSERTION` for that dependency.

Every entry requires an ID, owner, public reason, review date, expiration date
and a review URL in `aatuh/evydence`. Expiration is exclusive at the start of
that UTC date and cannot exceed 90 days after review. Future-dated reviews,
expired entries, duplicate identities/scopes and unknown fields fail validation.
Renewal requires another review; it is not automatic.

A syntactically valid review URL or owner field does not prove approval.
Enforcement must load policy from a trusted reviewed source and bind provider
data to the actual comparison. That integration remains incomplete. Test
exceptions are synthetic and do not approve any real dependency or advisory.

## License Classification Helper

The build-tool helper under `tools/cmd/license-inventory/` uses the checksum-pinned
`github.com/google/licensecheck v0.3.1` already selected by the release scanner.
It adds no runtime or SDK dependency. It accepts license bytes through stdin;
it does not open supplied paths, run package code, access the network or read
credentials.

The v1 scan protocol accepts a JSON array of unique `sha256` and
`content_base64` string pairs, with canonical base64 matching the exact digest.
Batches are limited to 64 files and 8 MiB of JSON; each UTF-8 license text is
limited to 1 MiB. Unknown/duplicate fields, digest mismatches, malformed input
and a late invalid record must fail without emitting a partial result.

Results distinguish a single text-match **candidate** at at least 95% coverage,
**ambiguous** multiple license IDs, and **unknown** text or URL-only matches.
Multiple detected terms do not imply an `OR` choice. Candidate classification
does not grant policy admission, establish legal rights or replace a reviewed
source/license record. The file digest binds the observed bytes; it is not a
publisher-authentication or artifact-signing claim.

The [upstream repository](https://github.com/google/licensecheck) was not archived when checked on 2026-10-21, with its
last recorded push on 2024-04-14. This is a maintenance-review signal, not proof
of abandonment. The complete inventory and maintenance report remain pending.

## Collect Source Observations

`scripts/dependency_inventory.py` resolves the application, QA and scanner
module graphs from isolated copies of their manifests and locks. It downloads
their selected module ZIPs through the Go proxy/checksum database and requires
`go mod verify` before reading root license/notice bytes from those archives.
Inspection does not run dependency install scripts or package executables.
Temporary work and bounded tool diagnostics are retained in a private directory
under the configured work root; cache paths and raw diagnostics are omitted from
the report.

The collector requires the current compiler from the support matrix, disables
automatic switching and workspace overrides, and serializes downloads. It
omits provider credentials from the tool environment. ZIP reads never extract
files, reject escaping/symlink paths and enforce entry/file limits. Input hashes
are checked again before writing a report; changed inputs abort collection.

The marketing lock contributes all package locations, exact versions, registry
URLs, SHA-512 integrity declarations and declared license expressions. The
collector fetches each exact HTTPS registry archive serially, without inherited
proxy credentials or redirects. It verifies compressed bytes against the lock
before bounded gzip/tar inspection, without extracting files. The archive's
root `package.json` must match the locked name/version; its digest, license
declaration and root license/notice observations are recorded.

`artifact-declared` means the archive and lock declare the same expression.
`license_text_status` and `license_text_candidate` describe the separately
classified root text. They do not override the declaration or grant approval;
disagreements and unknown results require review. Declaration mismatches set
the effective license to unknown/ambiguous and preserve both observations.
Legacy or unsupported declarations are not silently converted into SPDX.
See npm's [license declaration reference](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#license).
The collector does not invent empty vulnerability lists.

Use the host RAM coordinator for this command; downloading, verifying and
classifying the complete graphs is a memory-intensive operation:

```sh
make dependency-inventory-generate
```

The target writes `docs/reference/dependency-inventory.json` atomically and
replaces only an existing inventory of the same schema. It refuses unrelated
files and unsafe paths. Configure `DEPENDENCY_INVENTORY_WORK_ROOT` to an existing
scratch directory, preferably on the build-storage volume. The CLI also accepts
`--output` as a path relative to the checkout for a private qualification report.

This stage sets `complete: false`. Python, redistributed fixtures, additional
build-tool archives, Actions/images and maintenance/live
review evidence remain to be integrated before EVY-1407 can close. Go graph
observations cover available modules, not only dependencies linked into a
particular binary; they are separate from artifact-bound release SBOMs.

The [2026-10-21 snapshot](dependency-inventory.json) contains 1,522 Go
module/version observations after real download/checksum verification and 327
Node source archive observations. Go license observations include 1,411 candidates,
76 ambiguous results, 26 unknown and nine with no root license file. None of
those classifications grants approval. All 327 npm manifest declarations match
the lock. Their separate root-text observations are 241 candidates, three
ambiguous, 17 unknown and 66 with no root license file. A candidate for one
license does not discharge a compound declaration's additional obligations;
bundled native dependencies and nested notices still require review.
The snapshot binds generator/input
hashes and records the missing scopes; the unit tests reject a stale snapshot
after those inputs change. The missing scopes and policy enforcement are still
required, so this does not complete EVY-1407 or enforce live PR policy.

## Verify This Unit

```sh
make dependency-policy-test
make dependency-inventory-test
```

The first target is offline Python. The inventory target compiles and runs Go
tests; it and `make docs-check` must use the host RAM coordinator. Neither test
requires provider credentials. `make docs-check` includes both. Regression evidence covers expression semantics,
unknown metadata, exact and expiring exceptions, advisory severity, resource
bounds and safe error handling. It does not replace the remaining ticket gates.
