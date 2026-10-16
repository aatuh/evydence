# Observability

Evydence exposes low-detail runtime checks for operators. These signals support operational review and incident response; they do not prove legal compliance, complete evidence coverage, or release security.

## Process diagnostics

API, worker and migration commands write structured diagnostics to stderr using
standard-library `slog`. Set `EVYDENCE_LOG_FORMAT=json` (default) or `text` and
`EVYDENCE_LOG_LEVEL=debug`, `info` (default), `warn`, or `error`; see the
[configuration reference](configuration.md). Both formats use the same fields.
Invalid settings stop the process before database/provider startup and produce
a fixed rejection record without echoing the supplied value.

Each emitted record contains timestamp (`time`), `level`, fixed event (`msg`),
`service`, exact supported build `version`, `commit`, `build_time`, `dirty`,
`go_version`, and `release_manifest_digest`. Startup and shutdown use the same
immutable build identity. Unsupported metadata formats are reported as
`unknown`; a development binary may also legitimately have unknown fields.
Level filtering applies to lifecycle records too.

The operational schema also includes `request_id`, `tenant_id`, `resource_id`,
`job_id`, `receipt_id`, `operation_id`, `duration_ms`, numeric HTTP `status`,
`attempt`, `result_code`, and `retry_class`. Missing identifiers are empty;
non-applicable numeric fields are zero. Results are `started`, `succeeded`,
`rejected`, `failed`, `uncertain`, or `unknown`; retry classes are `none`,
`transient`, `permanent`, `poisoned`, or `unknown`.

Identifiers are domain-separated SHA-256 references, never raw text:
`SHA256("evydence-log.v1" + NUL + kind + NUL + identifier)`, displayed as
`sha256:` followed by the 64 lowercase hexadecimal digest characters.
Kinds are `request`, `tenant`, `resource`, `job`, `receipt`, and `operation`.
Inputs beyond 4096 bytes yield `invalid`. References support joining records
with authorized durable identifiers; they provide no authorization or
anonymization and can still be sensitive operational metadata.

Logging accepts fixed events and typed fields rather than arbitrary messages,
errors, request/response bodies or attributes. Credentials, evidence bytes,
provider responses, database URLs, customer names, email addresses, client IPs,
and URL paths/query strings have no raw diagnostic field. Internal `net/http`
diagnostics may contain panic values or request details: their bytes are
discarded and represented by a fixed `http_request` / `uncertain` record.
Command JSON/results and an explicitly requested local bootstrap-secret return
remain separate stdout interfaces. Operators own log access, retention and
collection; logging does not add a durable audit guarantee.

## Request and durable-work correlation

HTTP observations retain the existing `X-Request-ID` response contract but log
only its `request` reference. The operation is resolved from the registered
route contract; unmatched paths have no operation ID. A tenant reference is
added only after authentication succeeds. Edge denials and panics also produce
observations; a panic has an uncertain outcome. For Problem Details responses,
the diagnostic retry class is `transient` when the existing catalog permits a
retry and `none` otherwise. Clients must use the response's finer retry policy
and headers to decide how to retry.

Migration `20261016000100_outbox_log_correlation` adds dedicated
`outbox_jobs.log_request_id` and `log_operation_id` columns. Enqueue captures
validated references in the same transaction as the job. Deduplication retains
the original job's references, and claims restore them into the worker context.
These fields are operational metadata: they do not enter evidence bytes,
audit-chain hashing, idempotency fingerprints or outbox deduplication inputs.
Old jobs have empty references; restore from a historical backup may also omit
these diagnostic fields. Apply migrations before starting the updated workers.
Older binaries ignore the extra columns. Downgrading this migration loses
correlation only; it preserves jobs and evidence.

Native command transactions emit audit receipt references only after a
successful PostgreSQL commit. Rollback and uncertain commit outcomes never emit
a successful audit receipt. Provider observations carry the request reference,
operation, safe identifiers, duration and typed result/retry class; the provider
request, response and error remain outside the log schema. Logging does not
change provider ownership, cancellation or returned results.

## Endpoints

`GET /v1/health` is an unauthenticated liveness check. It does not contact
PostgreSQL, object storage, a signing provider, or tenant evidence.

`GET /v1/ready` is an unauthenticated, low-detail readiness check. When the
durable API profile is configured, it runs bounded probes for PostgreSQL
connectivity, migration state, the production API writer lease, object-store
access, and required signing configuration. It returns `200` only when every
required check is available and `503` with `"status":"unavailable"` when one
is not. The response exposes check names and statuses only; it excludes raw
dependency errors, credentials, database hosts, object-store paths, and tenant
data.

`GET /v1/admin/readiness` returns vetted per-check diagnostic text to a caller
with the explicit `instance:admin` scope. Tenant admin and ordinary wildcard
tenant keys are not enough. This diagnostic surface still excludes raw
dependency errors, credentials, paths, and tenant data.

`GET /v1/version` returns the immutable API build identity: version, commit,
build time, dirty marker, Go version, and the digest of the pre-build release
input manifest. Release-candidate packaging includes that manifest in the final
signed release artifact set. The endpoint reports provenance fields; it does
not prove that a binary, deployment, or release package is trustworthy without
independent checksum and signature verification.

`GET /v1/metrics` requires an admin API key. By default it returns JSON. When the request includes `Accept: text/plain`, it returns Prometheus exposition text for safe tenant-scoped counters and gauges:

```sh
curl -sS \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Accept: text/plain" \
  "$EVYDENCE_API_URL/v1/metrics"
```

Expected result: metric names such as `evydence_resource_count`, `evydence_customer_portal_failed_access_count`, and `evydence_customer_portal_revoked_access_count`. An API key with the explicit `instance:admin` scope additionally receives bounded instance-wide `evydence_outbox_pending_jobs`, `evydence_outbox_running_jobs`, `evydence_outbox_terminal_jobs`, and `evydence_outbox_oldest_pending_age_seconds` gauges. These outbox metrics have no tenant labels and disclose no job IDs, payloads, or failure details. The response omits API keys, portal tokens, raw evidence payloads, signing-key private material, customer names, and email addresses.

## Deployment Artifacts

The repository includes starter observability assets:

```text
deploy/observability/prometheus-rules.yaml
deploy/observability/grafana-dashboard.json
```

The Prometheus rules assume a scrape job named `evydence-api` and an authenticated scrape configuration for `/v1/metrics`. The dashboard assumes a Prometheus datasource. Adjust labels, scrape authentication, and routing policies for the deployment environment.

## Limitations

- `/v1/metrics` is tenant-scoped to ordinary admin actors. The explicit `instance:admin` scope adds only aggregate, unlabeled outbox gauges; it does not expose tenant evidence or job details.
- The starter alert rules are examples and need production routing, silence, and escalation policy review.
- OpenTelemetry tracing/exporter wiring is deployment-specific and not required for the local self-hosted runtime.
