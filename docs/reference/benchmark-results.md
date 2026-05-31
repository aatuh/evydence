# Benchmark Results

This reference records lightweight local benchmark evidence for the supported
single-writer profile. It is not a broad throughput claim and should not be used
as capacity planning without target-environment tests.

## Benchmark Command

```sh
go test ./internal/app -bench BenchmarkReleaseEvidenceIngestion -benchtime=100x -run '^$'
```

The project-owned gate is:

```sh
make benchmark-check
```

`make production-check` runs this gate before release-candidate packaging
evidence is accepted.

## Current Interpretation

The benchmark exercises in-process release evidence creation through the app
service and audit-chain path. It does not include HTTP routing, PostgreSQL,
object storage, signing providers, or worker parser side effects.

Use it to detect obvious local regressions in the core evidence path. For
production sizing, run API-level tests against the target PostgreSQL and object
store and record:

- Evydence commit/tag;
- database and object-store versions;
- payload sizes;
- API writer count;
- worker count;
- request rate;
- outbox backlog age;
- failed verification or parser checks;
- assumptions and limitations.

## Latest Local Result

Last recorded local run:

```text
goos: linux
goarch: amd64
pkg: github.com/aatuh/evydence/internal/app
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkReleaseEvidenceIngestion-16    	     100	   1426426 ns/op	  499913 B/op	    2543 allocs/op
```

Interpretation: this is a narrow app-layer benchmark for regression tracking.
It does not prove HTTP throughput, PostgreSQL throughput, object-store
performance, signing-provider latency, parser throughput, or multi-writer API
safety.

## Current Known Limit

The supported production profile remains one API writer replica. Worker replicas
may scale through PostgreSQL outbox locking, but this benchmark does not prove
multi-writer API safety.
