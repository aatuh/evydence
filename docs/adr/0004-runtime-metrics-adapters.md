# ADR 0004: Runtime Metrics Adapter Dependencies

Status: accepted for the private metrics adapter unit of EVY-1211, reviewed
2026-10-16. Dependency resolution, focused tests/race/lint/security and package
vulnerability checks pass; the full release compatibility gate remains required
before closing EVY-1211. This reference is for developers maintaining the
operational metrics adapter.

## Decision

Keep the standard-library-only observation port in `internal/platform/telemetry`.
Use concrete dependencies only in `internal/adapters/telemetry/metrics`:

- `github.com/aatuh/api-toolkit/contrib/v3 v3.1.2` supplies the required
  toolkit's HTTP Prometheus recorder. Its module requires core v3.1.1; Evydence
  retains its existing core v3.1.2 selection. The project explicitly requires
  the v3 API foundation, so this change does not migrate to toolkit v4.
- `github.com/prometheus/client_golang v1.25.0` supplies private registries,
  counters and histograms. Its Go 1.26 requirement fits this repository's
  Go 1.26.9 toolchain. Breaking query-client API changes in that release do not
  affect the collector packages selected here.
- `github.com/prometheus/common v0.72.1` supplies standard text exposition.
  This is the current patch release of the v0.72 line required by client v1.25.

The standard library does not provide Prometheus collectors, histogram
aggregation or its exposition format. Reusing maintained implementations avoids
creating another metric framework. A project adapter still owns route allowlists,
finite operation/outcome values, a hard HTTP-series budget, private registration
and authorization at scrape boundaries. It never registers default process/Go
collectors or uses raw paths, identifiers, errors or payloads as labels.

## Maintenance, License And Security Evidence

All three upstream repositories declare Apache-2.0; the pinned toolkit module's
LICENSE was also inspected locally. GitHub's repository/release API showed:

- Toolkit: not archived, most recent push 2026-08-22; core v3.1.1 and v3.1.2
  releases on 2026-05-21, followed by v4.0.0/v4.0.1 in July. The matching
  `contrib/v3.1.2` tag exists. This establishes observed activity, not a v3
  support or backport commitment.
- Prometheus client: v1.24 releases in July and v1.25.0 on 2026-10-08.
- Prometheus common: v0.71 in August, v0.72.0 in September and v0.72.1 on
  2026-10-11. Release cadence is observed history, not a maintenance guarantee.

The client advisory CVE-2022-21698 concerned unbounded method-label cardinality
and was fixed in v1.11.1. The selected client is newer, and the application also
tests normalization and a series budget rather than relying on version alone.
Toolkit/common public advisory API responses contained no published entries at
review time. This is not proof of an advisory-free dependency graph: run
`govulncheck` against the actual resolved packages and the final project gate.

Primary sources: [toolkit releases](https://github.com/aatuh/api-toolkit/releases),
[toolkit v3.1.2 package](https://pkg.go.dev/github.com/aatuh/api-toolkit/contrib/v3@v3.1.2/middleware/metrics),
[client v1.25.0](https://github.com/prometheus/client_golang/releases/tag/v1.25.0),
[client advisory](https://github.com/prometheus/client_golang/security/advisories/GHSA-cg3q-j54f-5p7p),
[common releases](https://github.com/prometheus/common/releases), and upstream
[toolkit](https://github.com/aatuh/api-toolkit/blob/master/LICENSE),
[client](https://github.com/prometheus/client_golang/blob/v1.25.0/LICENSE) and
[common](https://github.com/prometheus/common/blob/v0.72.1/LICENSE) licenses.

## Footprint And Replacement

The initial resolved module graph grows from 593 to 612 entries: 19 additions
and 20 version changes. This graph includes test and unlinked adapter requirements;
it is not a count of packages included in the service binary. New graph entries
include toolkit contrib, validation/environment helpers, Cedar, Stripe, Redis
test fixtures, Markdown and an OTLP HTTP exporter module. The metrics import
does not enable those other adapters. `go list -deps -json
./internal/adapters/telemetry/metrics` resolves 257 packages: 195 standard-library
packages, two Evydence packages and 60 packages from 12 external modules. The
toolkit contrib closure contains three packages and core toolkit eleven; there
are no Stripe, Cedar, Redis or OTLP HTTP exporter packages in that closure.
This is the metrics package's dependency inventory, not the complete service's
binary size or proof of dead-code elimination.

Selected shared upgrades include Prometheus model/procfs/common/client modules,
`klauspost/compress` v1.18.6 to v1.20.1, protobuf v1.36.11 to v1.36.12,
`x/crypto` v0.57.0 to v0.58.0, `x/net` v0.60.0 to v0.61.0, `x/oauth2` v0.36.0
to v0.37.0, and the matching `x/sync`, `x/sys`, `x/term` and `x/text` updates.
The graph also advances unused or test-only OTLP/test/tool modules. Retain the
before/after module inventories with local validation evidence and verify the
complete resolved service tree with the required release gate before EVY-1211
closure. No toolkit core major upgrade or Go toolchain change is selected.

`go mod tidy` classifies the three selected imports as direct dependencies and
retains only the required checksums. Focused `govulncheck
./internal/adapters/telemetry/metrics` reports no vulnerabilities. Registry unit
and race tests, scoped golangci-lint and gosec pass; gosec reports zero issues
and zero suppressions. The tests first reproduced an exposition-size bypass
through an embedded writer's promoted `WriteString`; the private writer now
checks the byte bound on all three writing interfaces.

The neutral observation port and private registry boundary isolate callers from
these SDKs. If toolkit v3 becomes unsupported, replace its concrete recorder
with an equivalent supported adapter, preserving metric names, label budgets
and tests. A later toolkit-major migration needs its own compatibility review.
If an exporter is disabled or fails, application evidence and request/worker
outcomes must remain independent; tracing is handled separately by EVY-1213.
