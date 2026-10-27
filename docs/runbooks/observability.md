# Diagnose monitoring alerts

This how-to is for the operator responding to the repository's example alerts.
Use the [observability reference](../reference/observability.md#deployment-artifacts)
for setup, metric semantics, threshold rationale and calibration. Record the
deployment, target, observation window and deployed version before changing
anything. Keep credentials and detailed internal diagnostics in restricted
operator systems; sanitize information before opening a public issue.

## Exporter

1. In Prometheus's target view, inspect the failing target's last scrape time,
   status and scrape error. A missing configured target produces no `up` series;
   compare the target list with the intended API and worker inventory too.
2. For connection failures, check the process listener and network namespace.
   The example's loopback addresses work only from that same namespace.
   Compare `/v1/health` and `/v1/ready` on the API, and the worker's separate
   lifecycle listener. A healthy process can still fail a resource snapshot.
3. For `401`/`403`, check the mounted credential file and its intended authority.
   `/v1/metrics` needs an API key with explicit `instance:admin` to include the
   private registry; tenant admin is insufficient even if the scrape returns
   `200`. Confirm text negotiation and the always-emitted
   `evydence_telemetry_series_overflow_total` family. The worker `/metrics`
   listener uses its distinct private token and must be enabled deliberately.
   Follow [worker scraping](../reference/observability.md#worker-scraping) for
   permissions and restart-based rotation; do not print either token.
4. For `503` or timeout, check database projection availability, target load,
   concurrent scrapes and the documented snapshot deadlines. Repeated scraping
   cannot repair the dependency. Check the database section below before
   changing scrape timing or process limits.
5. For series overflow, compare deployed route-template instrumentation and
   rollout changes with the fixed HTTP-series budget. Unknown routes must stay
   grouped. Use aggregate HTTP outcome counters while diagnosing; do not add
   request paths, identities or customer labels to recover detail.

Verify that `up` returns to `1`, that the private family is present, and that
scrapes remain fresh for the alert's hold interval. This proves collection
recovery, not successful business processing or evidence verification.

## Worker

1. Compare eligible, overdue, expired-lease and oldest-eligible gauges for the
   same database deployment. Pending age alone includes future retries.
   Check worker lifecycle readiness and `worker_process` outcomes; successful
   empty claims or failure/defer acknowledgements do not prove processing.
2. Use authorized `GET /v1/admin/outbox` diagnostics to inspect safe job state
   and failure codes. The [outbox contract](../reference/worker-outbox.md)
   owns claim fencing, retry, terminal state and replay permissions. Check the
   database, object-store or provider section according to the failure class.
3. Preserve the job disposition and relevant audit entries. Correct the cause
   before using the existing authorized, idempotent
   `POST /v1/admin/outbox/{id}/replay` operation. Do not edit durable rows, leases,
   immutable evidence or attempt numbers by hand.
4. Retained dead letters can keep the state alert active after review. Record
   an operator-owned disposition and a narrowly scoped, expiring silence when
   appropriate. Retention or restore can change the gauge; do not convert it to
   a counter or delete evidence to clear an alert.

Verify overdue work and expired leases recover, and check durable job outcomes.
An idle, empty queue cannot establish that a worker is alive; retain lifecycle
monitoring and the intended target inventory.

## Database

1. Identify the `job`, `instance`, `service` and `pool` on the alert. Compare
   acquired/maximum, waited acquisitions, canceled acquisitions and wait time
   for that process. Do not combine primary and package-read pool maxima into
   a fictitious shared pool.
2. Check low-detail readiness, then authorized `/v1/admin/readiness` diagnostics.
   Confirm database reachability, configured connection budgets and recent
   migration/rollout changes. Monitoring reads themselves use connections.
3. With an authorized PostgreSQL monitoring account, inspect transaction age
   and waits without selecting SQL text, credentials or customer data. For
   example, in a connection already opened to the intended database:

   ```sql
   SELECT state, wait_event_type, count(*) AS connections,
          max(clock_timestamp() - xact_start) AS oldest_transaction
   FROM pg_stat_activity
   WHERE datname = current_database() AND backend_type = 'client backend'
   GROUP BY state, wait_event_type;
   ```

   Visibility depends on the monitoring role's grants. Identify long-running
   work or contention before changing limits; do not terminate transactions
   from an alert alone. Review the [upgrade runbook](upgrade.md) for schema
   changes and [backup/restore runbook](backup-restore.md) for recovery.

Verify sustained waits and occupancy subside and readiness recovers. These
observations do not establish database capacity, durability or a tested RPO.

## Object store

1. Compare bounded `object_*` operation/outcome rates with storage readiness and
   recent endpoint, permissions, retention or network changes. Nested operations
   can each report a failure; their sum is not a distinct-object failure count.
2. Follow the [object-store recovery runbook](object-store-recovery.md#triage)
   for digest checks, reconciliation and database/object pairing. Do not delete
   payloads, bypass digest checks or disable retention to clear the signal.
3. Keep provider diagnostics restricted and use sanitized failure classes in
   reports. Follow [incident response](incident-response.md) for suspected
   credential, integrity or tenant-boundary incidents.

Verify readiness and the relevant authorized operation, including its durable
receipt or verification result. A successful metric sample is not proof of
payload integrity or successful recovery of every object.

## Provider

1. Identify the bounded `provider_*` operation and whether the result is failed,
   uncertain or canceled. Check configured provider readiness, network access,
   time validity and recent policy or credential changes in the restricted
   operator system. Do not add provider URLs, key identities or raw errors as
   metric labels.
2. Use the configured provider's authorized diagnostics to check permission and
   availability. Readiness metadata does not prove future signing permission or
   hardware custody. Use [key rotation](key-rotation.md) and
   [incident response](incident-response.md) when their conditions apply.
3. Preserve limited/not-verified results and ambiguous operation outcomes.
   Correct the dependency before replaying the existing authorized workflow;
   do not substitute a signer or mark evidence verified to restore the graph.

Verify the affected operation's actual result and durable receipt. Provider
reachability and an observation labeled `succeeded` do not independently prove
provider trust or that evidence passed verification.

## API

1. Compare server-error observations with aggregate HTTP outcomes, bounded route
   templates and dependency readiness in the same deployment and time window.
   Check exporter overflow before interpreting detailed route counts as complete.
2. Use restricted internal request correlation and the current error catalog to
   identify the failing path. Do not paste credentials, raw evidence or detailed
   diagnostics into public issues. Separate rejected client requests from server
   errors and canceled/uncertain work.
3. Follow the relevant dependency section above or the
   [incident-response runbook](incident-response.md). Validate recovery with an
   authorized operation appropriate to the failure, then observe the alert clear.

Low or zero traffic can yield empty rates and undefined histogram quantiles.
An absent error line is not a successful synthetic request or an availability
guarantee.
