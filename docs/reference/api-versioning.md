# API Versioning And Deprecation

Evydence exposes its public HTTP contract below `/v1`. This policy makes API
changes reviewable and reversible where possible. It does not assert release
security, legal compliance, certification, complete coverage, or customer
upgrade success without operator review.

The generated [`openapi.yaml`](../../openapi.yaml) is the machine-readable
contract. [API Reference](../api.md) is the integration entry point, while
[Upgrade And Compatibility Policy](upgrade-compatibility-policy.md) is the
operator-facing upgrade policy.

## Compatibility Gate

`make openapi-breaking-check` compares the generated contract with the
selected release artifact in [`openapi-baseline.json`](openapi-baseline.json).
The manifest records the release tag, published asset URL, artifact path, and
SHA-256. The gate verifies that digest before it compares contracts.

The CI workflow downloads the pinned `oasdiff` `v1.29.1` Linux binary, verifies
its published SHA-256, and runs the same command. Local callers provide that
exact executable through `OASDIFF_BIN`:

```sh
OASDIFF_BIN=/path/to/oasdiff make openapi-breaking-check
```

The comparison fails for an operation or path removal, operation-ID change,
new required request fields or parameters, request-shape restriction, changed
scopes or idempotency-key policy, removed response status or required response
field, response type changes, and enum changes. The gate treats additions and
removals in `components.schemas.ErrorCode` as client-visible compatibility
changes because typed SDK switches can be exhaustive.

The gate never fetches a baseline or resolves external OpenAPI references. It
uses only the checked-in release artifact and invokes `oasdiff` with structured
arguments and external-reference loading disabled.

## Prerelease Baseline Reconciliation

The current baseline is the published `v0.1.0-rc.7` OpenAPI asset with digest
`4c4ebb9e25a17f40a77ad206e927660cde68aa63dec45be3982f51c2541a6364`.
The committed prerelease contract contains 135 changes selected by the
compatibility policy. The exact set and its digest are recorded in
[`.github/openapi-breaking-exceptions.json`](../../.github/openapi-breaking-exceptions.json):

- 16 generated Problem Details error-code additions;
- 4 required request-header additions and 6 required request-field additions;
- 9 request requirement/shape restrictions;
- 16 response property removals or type/optionality changes; and
- 84 client-visible response-enum additions.

This repository-controlled prerelease change record is deliberately exact: the
baseline digest, change count, rule summary, and complete normalized change-set
digest must all match. It is not evidence of a published stable release or of
external approval. Any additional or altered breaking change fails until a new
repository-owned prerelease exception, migration note, and Unreleased changelog
entry are reviewed and committed together.

The migration impact is already reflected in the Unreleased changelog: clients
must use the current documented request fields and response envelopes, send
`If-Match` for protected transitions, use cursor pagination, and handle typed
Problem Details codes rather than parsing strings. A client moving from
`v0.1.0-rc.7` should regenerate its client from the current OpenAPI before it
sends writes to an Unreleased build.

### Source Snapshot Schema Reconciliation

The EVY-905 repository-controlled prerelease record retains the preceding 133
changes and adds two schema corrections: `pull_request.title` is required for
GitHub and GitLab source snapshots. Both the legacy and focused commands already
reject missing/blank titles; the schema previously omitted that runtime rule.
The exact 135-change digest is
`c9bf7cc92a54def6cb3bff2dc5bf0329fcec93fd3f51d479a82096e59f5d19d9`.
The prior 133-change record remains available for its exact historical input.
Neither record approves additional changes or claims external review.

Regenerate clients from the current contract and include a title whenever a
pull request is supplied. Commit time remains optional with its existing server
default. In PostgreSQL mode, omit optional source components and fields rather
than sending null, and expect one transaction for all supplied components.
These contracts are documented under
[provider source snapshots](../api.md#provider-source-snapshots). No stored
schema migration is required, and historical source rows remain unchanged.

## Stable-Line Rule

A stable `/v1` line permits additive fields, endpoints, and optional filters.
It must reject a breaking compatibility result. The only supported exception is
a documented security emergency: the exception must be exact, identify a
security advisory, link a migration note and changelog entry, and be committed
with the affected contract. Routine correctness, product, or implementation
work is not a stable-line exception.

## Deprecation Lifecycle

No operation is currently marked deprecated. When one is, the operation must
remain available until its advertised removal version and include all of the
following in the generated OpenAPI:

- `deprecated: true` and the matching `x-sunset` HTTP-date;
- `x-evydence-deprecation` with a distinct `replacement_operation_id`, a
  `removal_version`, RFC 3339 `deprecated_at`, `minimum_notice_days` of at
  least 180, the matching HTTP-date sunset, and a repository migration-guide
  link; and
- documented `Deprecation`, `Sunset`, and `Link` response headers on every
  declared response. `Link` identifies the replacement or migration guide
  using `rel="successor-version"` or `rel="deprecation"` as appropriate.

The route implementation must emit those headers on every successful and
Problem Details response for the deprecated operation. The OpenAPI gate rejects
incomplete deprecation metadata before a change can enter CI; route tests must
verify the runtime headers when a route is first deprecated. Removal requires
the documented removal version, a current migration guide, a changelog entry,
and a compatibility exception if the selected baseline still contains the
operation.
