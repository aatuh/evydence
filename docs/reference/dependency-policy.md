# Dependency Policy

This reference is for contributors selecting dependencies and maintainers
reviewing their admission. **EVY-1407 is in progress.** The offline admission
rules and their regression tests exist; complete inventories, live PR review,
license-source verification and the final release gate are not yet integrated.
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

## Verify This Unit

```sh
make dependency-policy-test
```

The tests are offline Python tests and require no credentials or installation.
`make docs-check` includes them; that broader command can compile Go and must use
the host RAM coordinator. Regression evidence covers expression semantics,
unknown metadata, exact and expiring exceptions, advisory severity, resource
bounds and safe error handling. It does not replace the remaining ticket gates.
