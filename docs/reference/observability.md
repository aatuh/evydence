# Observability

Evydence exposes low-detail runtime checks for operators. These signals support operational review and incident response; they do not prove legal compliance, complete evidence coverage, or release security.

## Endpoints

`GET /v1/ready` returns unauthenticated readiness JSON with only component status names such as `ledger`, `store`, and `object_store`.

`GET /v1/metrics` requires an admin API key. By default it returns JSON. When the request includes `Accept: text/plain`, it returns Prometheus exposition text for safe tenant-scoped counters and gauges:

```sh
curl -sS \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Accept: text/plain" \
  "$EVYDENCE_API_URL/v1/metrics"
```

Expected result: metric names such as `evydence_resource_count`, `evydence_customer_portal_failed_access_count`, and `evydence_customer_portal_revoked_access_count`. The response omits API keys, portal tokens, raw evidence payloads, signing-key private material, customer names, and email addresses.

## Deployment Artifacts

The repository includes starter observability assets:

```text
deploy/observability/prometheus-rules.yaml
deploy/observability/grafana-dashboard.json
```

The Prometheus rules assume a scrape job named `evydence-api` and an authenticated scrape configuration for `/v1/metrics`. The dashboard assumes a Prometheus datasource. Adjust labels, scrape authentication, and routing policies for the deployment environment.

## Limitations

- `/v1/metrics` is tenant-scoped to the authenticating admin actor; instance-wide metrics require separate operator aggregation.
- The starter alert rules are examples and need production routing, silence, and escalation policy review.
- OpenTelemetry tracing/exporter wiring is deployment-specific and not required for the local self-hosted runtime.
