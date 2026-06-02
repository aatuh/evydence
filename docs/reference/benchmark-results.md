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

`make benchmark-check` always runs the app-layer benchmark. When
`EVYDENCE_TEST_DATABASE_URL` is set, it also runs:

```sh
scripts/production_benchmark_check.sh
```

The production-like benchmark writes regression-friendly output to:

```text
tmp/production-benchmark/production-benchmark-summary.json
tmp/production-benchmark/production-benchmark-summary.txt
```

The JSON summary uses schema
`evydence-production-benchmark.v1.0.0`. `make production-check` runs this gate
before release-candidate packaging evidence is accepted, and production-check
requires `EVYDENCE_TEST_DATABASE_URL`.

## Current Interpretation

The benchmark exercises in-process release evidence creation through the app
service and audit-chain path.

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

The production-like benchmark is based on
`examples/end-to-end-release-evidence/run-local-demo.sh`. It starts the API and
worker against a disposable PostgreSQL schema and filesystem object store, then
exercises HTTP API calls, persistence, API restart, release-readiness reporting,
customer package creation, and audit-chain verification. It records total
scenario wall-clock time, an estimated operation rate for the checked scenario,
demo JSON output count, object file count, object bytes, and explicit
limitations.

This is still a local regression benchmark. It does not prove S3/MinIO network
latency, live KMS/HSM signing latency, identity-provider latency, registry
behavior, public transparency provider behavior, multi-writer API safety, or
target-environment capacity.

## Latest Local Result

Last recorded local run:

```text
goos: linux
goarch: amd64
pkg: github.com/aatuh/evydence/internal/app
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkReleaseEvidenceIngestion-16    	     100	   1392755 ns/op	  499973 B/op	    2543 allocs/op
```

Interpretation: this is a narrow app-layer benchmark for regression tracking.
It does not prove HTTP throughput, PostgreSQL throughput, object-store
performance, signing-provider latency, parser throughput, or multi-writer API
safety.

Last recorded production-like benchmark evidence should be read from
`tmp/production-benchmark/production-benchmark-summary.json` after running
`EVYDENCE_TEST_DATABASE_URL=... make benchmark-check`. Commit or attach that
generated JSON only as release evidence for the exact environment that produced
it; do not treat the local result as a general throughput claim.

## Current Known Limit

The supported production profile remains one API writer replica. Worker replicas
may scale through PostgreSQL outbox locking, but this benchmark does not prove
multi-writer API safety.
