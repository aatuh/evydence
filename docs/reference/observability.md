# Observability

Evydence exposes low-detail runtime checks for operators. These signals support operational review and incident response; they do not prove legal compliance, complete evidence coverage, or release security.

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
