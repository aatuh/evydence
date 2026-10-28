# Observability

Evydence exposes low-detail runtime checks for operators. These signals support operational review and incident response; they do not prove legal compliance, complete evidence coverage, or release security.

## Process diagnostics

API, worker, migration and online CLI commands write structured diagnostics to stderr using
standard-library `slog`. Set `EVYDENCE_LOG_FORMAT=json` (default) or `text` and
`EVYDENCE_LOG_LEVEL=debug`, `info` (default), `warn`, or `error`; see the
[configuration reference](configuration.md). Both formats use the same fields.
Invalid settings stop the process before database/provider startup and produce
a fixed rejection record without echoing the supplied value. Online CLI records
use the fixed service name `cli`; offline and help operations do not start that
lifecycle logger.

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

Migration `20261028000100_outbox_trace_context` adds operational `trace_id`,
`trace_parent_span_id` and `trace_sampled` columns to `outbox_jobs`. Both enqueue
paths save only an explicitly supplied internal trace carrier, in the job's
transaction. Duplicate delivery retains the winning job's context; claims and
lease reclaims restore that context after a process restart. Trace metadata
does not grant tenant access or replace lease fencing. Jobs without metadata
clear any previous job's trace from the worker context.

Apply the migration before starting the updated binaries. Existing jobs and
older writers default to empty identifiers and `false`; older readers ignore
the columns. The down migration drops diagnostic context only. Evidence bytes,
deduplication inputs and all five frozen backup commitment profiles remain
unchanged; restored historical jobs may have no trace context. The persistence
carrier has no HTTP-header, baggage or free-form attribute parser. This stage
does not enable a collector or create spans; optional trace export and daemon
entry-point spans remain part of EVY-1213.

The migration takes an exclusive table lock to add columns and validate their
shape. Both directions limit lock waits to three seconds and each statement to
30 seconds within the migration transaction. Contention, validation timeout or
cancellation rolls back the migration; schedule a quiet maintenance window and
retry after resolving the contention. These budgets do not prove that a large
production outbox can migrate within the window.

Native command transactions emit audit receipt references only after a
successful PostgreSQL commit. Rollback and uncertain commit outcomes never emit
a successful audit receipt. Provider observations carry the request reference,
operation, safe identifiers, duration and typed result/retry class; the provider
request, response and error remain outside the log schema. Logging does not
change provider ownership, cancellation or returned results.

## Operational metrics

`GET /v1/metrics` keeps its tenant-scoped JSON and text metrics. Request text
with `Accept: text/plain`. In the native API runtime, only an actor with explicit
`instance:admin` also receives the private API process registry. Tenant admin,
tenant wildcard and another tenant's credentials do not grant this authority.
Authorization precedes process snapshot access and is checked again before the
response. JSON does not read the process registry. Responses use
`Cache-Control: no-store`; snapshot failure produces retryable `503` without
partial output or raw errors.

The API records HTTP counts and durations using the required toolkit adapter,
and provider counts and durations for signing, OIDC discovery, provider identity,
transparency fetch and Cosign verification. Provider wrappers preserve returned
values/errors, cancellation and port ownership. Request observers also cover
early denials; an interrupted/panicking response is measured as uncertain, even
if a success header had already been written. Recorder failure cannot replace
the business response or an existing handler panic.

Native evidence parser adapters and actual worker replay calls measure SBOM,
vulnerability scan, OpenAPI and VEX normalization. The worker's
`verify_attestation` observation covers attestation parsing during replay; it
does not assert cryptographic signature verification. Work rejected before
parsing, such as a foreign-tenant subject, does not count as a parser invocation.
A successful parse can still be followed by a failed comparison with durable
state or a failed mutation; the separate worker processing outcome reflects
that failure. The worker's `sign_bundle` and `verify_subject` jobs inspect
already-persisted results and do not count as new signing or verification.

Focused signing-operation and Merkle-creation commands measure `signing`,
including their transaction outcome. Focused verification commands measure
`verification`, while dispatch to those commands adds no duplicate observation.
The metric outcome follows the returned error: a failed verification verdict
which returns an error counts as failed; a normally returned `limited` or
`not_verified` result counts as an operationally completed command. It does not
mean the evidence passed verification. Read the durable result, assurance
profile and limitations to assess evidence.

Release-bundle, evidence-bundle and customer-package commands measure
`package_generation`, including failed commits. Bundle signing port calls have
a separate `package_sign` observation: a successful signature can precede a
failed bundle transaction. Tenant-bound object reconciliation measures
`object_reconciliation` for both dry-run and apply requests; a successful dry run
does not mean a repair was applied. These observations preserve the existing
authorization, idempotency, hashes, redaction, receipts and error contracts.
Command measurements describe returned outcomes and cannot resolve an ambiguous
database commit; use the existing durable receipt and replay interfaces when
deciding whether to retry.

| Family | Type | Dimensions |
| --- | --- | --- |
| `http_requests_total` | Counter | `service`, normalized `method`, route template, numeric `status`. |
| `http_request_duration_seconds` | Histogram | Same HTTP dimensions. |
| `evydence_http_outcomes_total` | Counter | `service`, fixed `outcome`; independent of detailed-series overflow. |
| `evydence_operations_total` | Counter | `service`, fixed `operation`, fixed `outcome`. |
| `evydence_operation_duration_seconds` | Histogram | Same operation dimensions. |
| `evydence_operation_attempt_number` | Histogram | Same operation dimensions; actual worker attempt number is the sample, never a label. |
| `evydence_active_operations` | Gauge | `service`, fixed `operation`; currently admitted measured operations. |
| `evydence_telemetry_series_overflow_total` | Counter | `service`; explains collapsed HTTP observations. |
| `evydence_db_pool_connections` | Gauge | `service`, fixed `pool` (`primary` or `package_read`), fixed `state` (`acquired`, `idle`, `constructing`, `maximum`). |
| `evydence_db_pool_acquires_total` | Counter | `service`, `pool`; successful process-local acquires. |
| `evydence_db_pool_canceled_acquires_total` | Counter | `service`, `pool`; canceled acquires. |
| `evydence_db_pool_waited_acquires_total` | Counter | `service`, `pool`; successful acquires which waited, a subset of successful acquires. |
| `evydence_db_pool_acquire_duration_seconds_total` | Counter | `service`, `pool`; cumulative duration of successful acquires. |
| `evydence_db_pool_wait_seconds_total` | Counter | `service`, `pool`; cumulative wait time for successful acquires which found the pool empty. |
| `evydence_queue_jobs` | Gauge | `service`, fixed `state` (`queued`, `retrying`, `running`, `succeeded`, `dead_letter`). |
| `evydence_queue_attempts` | Gauge | `service`; sum of current attempt numbers on retained jobs. |
| `evydence_queue_eligible_jobs` | Gauge | `service`; queued/retrying jobs due by `run_after`. |
| `evydence_queue_overdue_jobs` | Gauge | `service`; queued/retrying jobs at least five minutes past `run_after`. |
| `evydence_queue_expired_leases` | Gauge | `service`; running jobs with missing or expired five-minute leases. |
| `evydence_queue_oldest_pending_age_seconds` | Gauge | `service`; creation age of the oldest queued/retrying job, including future scheduled work. |
| `evydence_queue_oldest_eligible_age_seconds` | Gauge | `service`; creation age of the oldest currently eligible queued/retrying job. |

Native filesystem and S3 adapters measure object reads (including bounded
reads), writes, inventory, staging, finalization and their existing cleanup
deletes. The S3 adapter also measures retention queries. Results, errors,
payload bytes, tenant/digest checks, cancellation and concrete capabilities
remain unchanged. Readiness checks do not count as business storage work.
Existing cancellation-independent cleanup retains that policy; measurement does
not add retries, I/O, background work or a new cancellation boundary.

Each admitted measured operation increments its active gauge and finishes once,
including concurrent finalization attempts. Normal completion records actual
success/failure/cancellation and duration. A panic keeps its original value,
records uncertainty and releases activity; recorder faults do not change the
call's result. Operation/outcome names are finite, and attempts remain numeric
measurements. Finalization includes separately measured read/write/delete
suboperations: nested operations are distinct, so do not sum their durations
as process wall time. Active storage work measures utilization, not provider
capacity, available disk/bucket space or a throughput guarantee.

Worker measurements separate `worker_claim`, `worker_process`, `worker_complete`,
`worker_fail` and `worker_defer`. A successful claim can be an empty poll. A
successful failure/defer acknowledgement confirms that transition, not successful
job processing; the queue gauges show retained terminal states. Process and
acknowledgement phases record their independently confirmed outcomes and actual
attempt number, with invalid numeric attempts clamped to the unsigned range.
If a drain deadline expires, or an acknowledgement cannot be confirmed, the
owner records `uncertain` and preserves the existing lease/exit policy. A late
noncooperative processor cannot emit a second worker-phase outcome or trigger a
late acknowledgement. Nested parser/storage measurements retain their own call
lifetimes and do not confirm a job acknowledgement. Activity gauges cover the
owner's admitted phase lifetime;
they are not a count of arbitrary callbacks surviving a forced-exit boundary.

Registry construction accepts only `api` or `worker` service names and at most
256 code-owned route templates. A hard budget of 1024 distinct HTTP label
combinations folds further new combinations into `OTHER` / `unknown` / `0`,
preserving all request and duration observations. Unknown operations/outcomes
collapse to finite fallback values. Tenant/resource/job/customer IDs, CVEs,
trace IDs, URLs, headers, credentials, bodies and raw errors are not labels.
The registry does not register the global/default Go or process collectors.
The private registry's text output is capped at 8 MiB; a canceled snapshot
returns no partial data.

Authorized native API text scrapes also read a fixed scalar PostgreSQL projection
through the existing read-only package preparation pool. Its one-second deadline
includes connection waiting and SQL execution, and respects earlier caller
cancellation. It neither loads the Ledger nor reads job payloads/identifiers or
changes claims, attempts, leases, audits or evidence. Failed, canceled, invalid
or panicking reads publish no partial or cached stale sample. Each scrape owns
its resource value copy, including concurrent scrapes. Pool statistics are
process-local; the read pool's activity includes metric scrapes themselves.

Queue gauges cover the shared database, so API and worker targets connected to
the same database repeat those values: do not sum them across process targets.
Retained succeeded/dead-letter jobs and current attempt-number sums are gauges,
not lifetime completion or attempt-event counters. Retention/restore can change
them. An old future-scheduled retry can raise pending creation age without being
overdue; use eligibility/overdue/lease signals to diagnose stalled work. Empty
or future creation timestamps produce zero age. Exact scalar aggregation can
scan retained history; sufficiently large/contended histories may hit the query
deadline and make a scrape unavailable. This is no database-capacity guarantee.

Counters and histograms are process-local and reset on restart. Scrape each
process separately and use reset-aware rates; these measurements are operational
observations, not durable evidence or audit totals. A scrape reflects previously
completed requests; its own completed request is recorded after the response.
Application hooks use the caller's context-scoped recorder. Standalone one-shot
commands, including `reconcile`, do not serve a scrape endpoint or persist the
new process counters. Existing tenant metrics still expose reconciliation
receipt totals and last-run age; result and receipt interfaces remain
authoritative.
The dashboard/rule examples require operator calibration. Optional trace export
and daemon entry-point spans remain incomplete under EVY-1213; the operational
worker carrier is described above.

### Worker scraping

The worker can serve `GET/HEAD /metrics` on a separate optional listener. It
exposes the worker's own registry and the shared database queue projection,
without a tenant view or a public API/SDK route. Both metrics variables unset
leaves this listener disabled. The existing loopback lifecycle listener and its
healthcheck commands retain their own port and admission pool.

An operator enables scraping with `EVYDENCE_WORKER_METRICS_TOKEN_FILE`, an
absolute path to a private regular secret file. The default bind is
`127.0.0.1:9091`; set `EVYDENCE_WORKER_METRICS_ADDR` to a literal private address
for a monitoring client on the private network. Public, wildcard, hostname and
zoned binds are rejected. IPv6 addresses use brackets, such as
`[fd00::10]:9091`. Monitoring traffic crossing an untrusted network needs an
operator-managed TLS proxy; the listener itself serves HTTP. Private IP binding
does not encrypt the bearer credential or its response.

Generate a distinct credential on the operator host, outside the checkout
(this example uses Python 3):

```sh
install -d -m 700 "$HOME/.config/evydence"
umask 077
python3 -c 'import secrets; print("evymetrics_" + secrets.token_hex(32))' > "$HOME/.config/evydence/worker-metrics-token"
export EVYDENCE_WORKER_METRICS_TOKEN_FILE="$HOME/.config/evydence/worker-metrics-token"
export EVYDENCE_WORKER_METRICS_ADDR=127.0.0.1:9091
```

Have the monitoring client load the bearer value from this file without
placing it in command arguments, logs or a checked-in configuration. The
credential grants only instance-wide worker metrics reads. It is separate from
API key/session/collector credentials, is not authenticated through tenant
roles, and requires no additional worker database identity permissions. The
file format is `evymetrics_` followed by 64 lowercase hexadecimal characters,
with at most one final LF. POSIX mode `0600`, `0640` or `0440` is suitable:
group write and all other-user permissions are forbidden. Bounded reads follow
relative projected-secret aliases only within the configured parent directory.
The worker retains a hash, loads the file once at startup, and does no per-request
credential-file reads. Replace the file and restart the worker to rotate or
revoke the old value; removing a file does not revoke an already loaded hash.
The lifecycle configuration monitor does not hot-reload this credential.

Exactly one valid Bearer header is required before snapshot access; cookies,
tenant/API/SSO keys, duplicate headers and malformed credentials are rejected
without resource reads. Four scrapes may be active at once. Further requests
return retryable `503` with `Retry-After`; canceled requests do no new snapshot
work. The two-second snapshot budget respects earlier request cancellation,
and its PostgreSQL projection still has its own one-second bound. Invalid,
failed, oversized or panicking snapshots return no partial data or raw errors.
All responses use `Cache-Control: no-store`.

The daemon owns both listeners and the worker loop. Failure of either listener
stops the loop, publishes draining, and closes both listeners. HTTP drains share
one deadline and overlap the native job drain. A noncooperative handler forces
the same nonzero-exit boundary as a stuck lifecycle probe, preserving resource
ownership until process exit. A blocked metrics reader does not block liveness.

## Endpoints

| Endpoint | Purpose | Authority | Result |
| --- | --- | --- | --- |
| `GET /v1/health` | Process liveness; no dependency I/O. | Public. | `200` while the process can answer its handler. |
| `GET /v1/startup` | Initialized runtime and configured database/schema/configuration prerequisites. | Public. | `200` when startup prerequisites are available; otherwise `503`. |
| `GET /v1/ready` | Supported-work readiness across all configured dependencies. | Public. | `200` only when all required checks are available; otherwise `503`. |
| `GET /v1/admin/readiness` | Vetted dependency and lifecycle diagnostics. | Explicit `instance:admin`. | `200` for an authorized diagnostic read, including an unavailable overall state. |

The process binds HTTP only after runtime initialization and migration checks.
During that initialization a startup probe cannot connect; it must allow enough
startup time before treating that as failure. A later schema/configuration
prerequisite failure blocks startup and readiness. A serving-only dependency
outage blocks readiness while liveness and completed startup prerequisites
remain independent. Liveness cannot detect a failure isolated to unrelated
business logic; the probe observes whether its handler can respond.

Startup returns only status and, when unavailable, typed retry metadata. Public
readiness retains configured check names/statuses, excluding raw errors,
credentials, dependency addresses, filesystem paths and tenant data. There is
no synthetic `ledger: ok` row: a check must represent an actual configured
probe. Unavailable startup/readiness include `Retry-After` and the existing
retry policy. All lifecycle and diagnostic responses use `Cache-Control:
no-store` so an intermediary cannot extend snapshot freshness.

Startup, readiness and authorized diagnostics share a process-local dependency
snapshot. Default cache reuse is two seconds after a refresh, and the entire
refresh has a three-second budget. Thus a reused result can reflect work begun
at most five seconds earlier. Individual probes also have deadlines. Concurrent
callers coalesce behind one caller-owned refresh; no background refresh is
started. Cancelled owners publish no partial cache result, and each waiting
caller can cancel independently. Cached failures expire too, permitting recovery
after a dependency is restored. A backward clock invalidates cache reuse.

The API's `outbox` dependency checks for queued/retrying work at least five
minutes past `run_after`, or running work with a missing/expired five-minute
worker lease. Recent eligible work, future scheduled retries and historical
dead letters/completed jobs do not block readiness. The database query uses
existence checks over active-work indexes, returns no tenant/job data, and
does not claim, renew or replay work. An empty queue alone cannot establish
that a worker is running; this probe detects stalled work once it exists.

In production, the historical `signing_config` check now probes the required
signer's operational availability rather than merely checking that an executor
exists. Probes never create a signature, evidence record or signing receipt:

- AWS KMS uses `DescribeKey` for the configured key, requiring enabled state,
  signing usage and the configured algorithm. Grant `kms:DescribeKey` on that
  key in addition to the existing signing/verification permissions.
- GCP KMS reads the configured default key version, requiring `ENABLED` state
  and a supported SHA-256 signing algorithm. Grant
  `cloudkms.cryptoKeyVersions.get` for that version. Health credential exchanges
  use their caller's context and a separate short-lock token cache; they never
  wait on the signing path's contextless OAuth refresh. JSON-based ADC uses
  the pinned Google credential parser; metadata-backed ADC uses its
  context-aware metadata client. Credential HTTP response reads are capped.
- Azure Key Vault fetches the configured default key/version's public metadata
  under a caller-bounded credential exchange. It checks key identity, enabled
  and validity attributes, signing operations and the supported EC public key.
  The operation requires `keys/get` access.
- External/PKCS#11 gateways require an explicit same-origin readiness URL and
  the small response contract in the [configuration reference](configuration.md).
  The gateway owns the meaning of its availability report.

GCP and Azure metadata bodies are capped at 64 KiB; AWS uses the pinned SDK's
typed metadata decoder under the probe deadline.
Metadata checks observe provider reachability, credentials and the configured
default key's reported state. They do not prove `Sign` permission, hardware
custody, every tenant-selected key's availability or successful future signing.
Public responses contain only the existing safe dependency name/status; raw
provider errors, URLs, tokens and key identifiers are excluded.

Canonical GET/HEAD requests to the three public lifecycle paths are independent
of application edge quotas and in-flight admission. Startup/readiness have a
separate eight-request pool; saturation returns a low-detail retryable `503`
without more dependency work. Liveness remains independent of that pool. URL,
body-size and encoding validation still applies. Other methods, escaped aliases
and unrelated paths retain ordinary application limits.

Diagnostics authorize before dependency work or cached data access. Tenant
admin and ordinary wildcard tenant keys are insufficient. Instance admins see
vetted failure text, startup/initialization/drain state, and `checked_at` /
`valid_until` freshness timestamps when a sample exists. Raw errors, credentials,
paths and tenant data remain excluded. These are operational observations,
not evidence-integrity verification or proof that every business path works.

On a shutdown signal the API marks its readiness service as draining before
starting listener shutdown. A permanent serving failure also marks draining
when observed. Draining makes startup/readiness unavailable immediately,
without dependency I/O; it does not cancel admitted requests before their
existing drain deadline. The listener then closes as part of normal shutdown,
so this does not promise that a new probe can connect during termination.

### Worker lifecycle probes

The worker has a separate loopback-only listener, default `127.0.0.1:8081`.
It starts after runtime initialization and migration completion, before the
worker loop can claim jobs. Runtime initialization has a 30-second deadline.
The listener serves `/v1/health`, `/v1/startup` and `/v1/ready`, with overall
status only and `meta.process: worker`. It uses the same bounded snapshot cache
and an eight-request startup/readiness pool; liveness does no dependency I/O.
The public API's OpenAPI/SDK catalog does not expose this internal listener.

| Command | Observation |
| --- | --- |
| `evydence-worker healthcheck` | Running worker readiness: database, schema, object store, outbox progress and configuration freshness. |
| `evydence-worker healthcheck --startup` | Initialized worker with current database/schema/configuration prerequisites. |
| `evydence-worker healthcheck --liveness` | Responsive worker probe handler, independent of serving dependencies. |

Commands query the configured local listener and exit zero only for a healthy
response identifying a worker. An absent worker, another process, a malformed
reply or a failed dependency check exits nonzero. `--healthcheck` remains an
alias for the command; startup/liveness flags are mutually exclusive. The client
has a five-second timeout, a 4096-byte response cap, no ambient proxy and no
redirect following. It prints no response body or dependency details.

Worker readiness does not suspend job processing. Liveness cannot diagnose a
failure isolated to business logic; stalled work is observed through outbox
progress checks. Workers do not require the API writer lease or an API signing
executor to report ready. Detailed instance diagnostics remain on the API's
authenticated `/v1/admin/readiness` surface; the worker listener has no detailed
diagnostic route.

The worker owns and joins its probe server and native work loop. A shutdown
signal, serving failure or loop exit marks draining before cancelling the work
root. Listener shutdown overlaps the existing job drain; admitted jobs retain
their native drain deadline. A noncooperative probe that outlives listener
shutdown forces a nonzero process exit and preserves the resource-ownership
boundary, as an unfinished job does. An occupied probe port fails before any
jobs are claimed. No worker probe port needs to be published outside its pod.

### Configuration freshness

The API and worker `configuration` startup/readiness checks compare their process
environment with a digest captured before runtime composition. It includes
`ENV`, `EVYDENCE_*`, `AWS_*`, `GOOGLE_*` and `AZURE_*`; it retains no raw secret
values and exposes neither the digest nor changed variable names. Reordering
variables or changing unrelated environment entries does not invalidate it.
Environment-based settings are fixed for the process lifetime; health checks
do not reload them.

For an external desired-state signal, set both revision variables in the
[configuration reference](configuration.md). Each daemon reopens the local revision
file on each dependency refresh. A changed, missing or malformed revision
blocks startup/readiness; restoring the loaded revision permits recovery after
cache expiry. The file and parent directory must be operator-controlled and
on a local filesystem; this mechanism is not a remote configuration reader.
Content reads are scoped to the configured parent directory with an owned
directory handle. Relative and absolute symlinks resolving inside that directory
remain supported, including Kubernetes' nested `..data` projection replacement.
Symlinks escaping the directory fail initialization or the next refreshed probe,
even when the outside file contains the expected revision. Keep projected targets
inside the configured directory when upgrading.

Helm hashes its non-secret ConfigMap data into the loaded revision, projects
that revision into both daemons as a read-only volume without `subPath`, and annotates API
and worker pod templates with a ConfigMap checksum to trigger replacement on
chart configuration changes. Detection in an existing pod depends on
Kubernetes propagating the projected volume update, then the health cache
refreshing. The five-second snapshot age bound starts after local projection,
not at the control-plane update. Normal chart changes also start a rollout.

Without a revision file, an already running process cannot observe changes to
its parent's environment, external ConfigMaps or Secrets. Separately managed
Secret updates and out-of-band configuration changes require an operator
rollout or an explicitly coordinated desired revision. The chart does not
watch the Kubernetes API or claim to detect those changes automatically.

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

The repository includes a local Prometheus 3.x scrape profile, alert rules and
a Grafana classic dashboard (schema version 39):

```text
deploy/observability/prometheus.yaml
deploy/observability/prometheus-rules.yaml
deploy/observability/grafana-dashboard.json
deploy/observability/metrics-contract.json
```

The metric contract is generated by `TestObservabilityMetricContract` from the
actual API/worker exporter with synthetic operational/resource fixtures, rather
than from documentation or a hand-written metric list. It contains sample
names/types, label names and finite code-owned label values, with no production
measurements. Histogram queries use actual `_bucket`, `_sum` or `_count` samples;
the classic histogram family name alone is not a sample.

### Scrape and import profile

The example assumes Prometheus and the two processes share a network namespace:
API `127.0.0.1:8080`, worker private metrics `127.0.0.1:9091`. Loopback inside a
separate container points to that container, not the host. Adapt target discovery
and TLS to the actual topology; use an authenticated TLS proxy when the worker's
HTTP metrics cross an untrusted network. The worker's lifecycle listener is a
different endpoint and port.

Mount the API's explicit `instance:admin` credential as
`/run/secrets/evydence_api_metrics_token` in Prometheus. Mount the worker's
distinct private metrics token as `/run/secrets/evydence_worker_metrics_token`.
The latter must match the token deliberately configured on the worker; see
[worker scraping](#worker-scraping) for enablement, permissions and rotation.
Prometheus must be able to read its credential files; do not commit their
contents or put tokens in target URLs, command arguments, dashboard variables
or metric labels. The example selects the Prometheus text scrape protocol, so
the API receives `Accept: text/plain` negotiation rather than its JSON format.
Tenant-only scrapes remain a separate API feature and cannot populate this
instance dashboard.

Keep `prometheus.yaml` and `prometheus-rules.yaml` together when mounting the
configuration. Retain the job names `evydence-api` and `evydence-worker`, or
update the rules and dashboard selectors to match. Assign a bounded,
operator-owned `deployment` label that identifies **one shared database**.
Different ledgers must have different values. Do not put tenant/customer data
in that label. Avoid overriding the exporter's `service` or other metric label
names with target labels; Prometheus can rename conflicting sample labels.

Import `grafana-dashboard.json` through Grafana's dashboard import and select
the intended Prometheus datasource when prompted by `DS_PROMETHEUS`. Restrict
access to the instance-wide datasource and dashboard. The repository check
validates JSON structure, datasource binding and queries; it does not establish
a successful import on every Grafana version or deploy a monitoring server.
Configure Alertmanager routing and replace repository-relative runbook URLs
with the corresponding absolute URL in the operator's documentation system.

### Aggregation and interpretation

- Apply `rate`/`increase` to each process counter **before** summing. Restarts
  reset process counters, and a new series needs enough scrapes to calculate
  a rate. Work before the first sample or between lost scrapes can be missed.
- Queue metrics are shared database projections repeated by API and workers.
  Use `max by (deployment, state)` for states and `max by (deployment)` for
  scalar queue gauges. Summing targets multiplies the same jobs. Scrapes occur
  at different instants; the maximum is a conservative observed value, not an
  atomic cluster snapshot. Compare freshness and target inventory as well.
- Retained succeeded/dead-letter counts and `evydence_queue_attempts` are
  gauges. Retention, replay and restore can reduce or change them. They are not
  lifetime completions or attempt counters; do not use `increase` on them.
- Pool connections and waits belong to each process and named pool. Keep
  `instance`, `job`, `service` and `pool` when diagnosing saturation. Neither
  active operations nor pool size establishes provider/database capacity.
- Histogram quantiles are estimates over the emitted buckets. Zero traffic
  can yield no series or undefined quantiles. A missing operation series does
  not prove success, and an empty queue does not prove a worker is alive.
- Nested object/provider operations are distinct observations, not unique
  failed business actions. A `succeeded` verification call may return a limited
  result; use durable receipts and the verification taxonomy for conclusions.
- The exporter bounds operation/outcome labels, route templates and detailed
  HTTP series. Overflow folds detail while retaining aggregate HTTP outcomes.
  `job`, `instance` and `deployment` are scrape metadata owned by the operator;
  control target churn and avoid customer labels in relabeling or recordings.

### Example alert thresholds

All examples start at `ticket` severity. These values are diagnostic defaults,
not SLOs, measured capacity, an availability promise or an escalation policy.
The [monitoring runbook](../runbooks/observability.md) provides the concrete
diagnostic action for every alert.

| Alert | Initial threshold and rationale |
| --- | --- |
| `EvydenceScrapeUnavailable` | `up == 0` for 2 minutes permits a short scrape interruption. Authentication, projection failure and network errors can all cause it; it does not alone establish API downtime. Missing configured targets need separate inventory review. |
| `EvydencePrivateMetricsMissing` | Successful scrape without the always-emitted private overflow counter for 2 minutes catches wrong authority or negotiation. An ordinary tenant key can return valid text without the private registry. |
| `EvydenceQueueOverdue` | Any work already 5 minutes past `run_after`, held for another 5 minutes, calls for worker/dependency diagnosis. Future retries alone do not fire it. |
| `EvydenceWorkerLeaseExpired` | Any running work with a missing/expired 5-minute lease for another 5 minutes calls for lifecycle review; it does not authorize editing leases. |
| `EvydenceQueueDeadLetters` | Any retained dead letter for 15 minutes asks for a recorded disposition. A reviewed historical dead letter can keep the gauge positive; use a scoped silence, not deletion to clear the graph. |
| `EvydenceWorkerProcessingFailures` | Positive increase in failed/uncertain processing over 15 minutes, held for 5 minutes, prompts durable job review. Empty polls and successful failure acknowledgements are separate phases. |
| `EvydenceDatabasePoolPressure` | Acquired/maximum above 90% with positive waited acquisitions for 10 minutes requires both utilization and observed waiting. Calibrate per process/pool before increasing connection budgets. |
| `EvydenceProviderFailures`, `EvydenceObjectStoreFailures` | At least 3 failed/uncertain observations in 15 minutes, held for 5 minutes, tolerates an isolated observed error. Nested calls can contribute separately. |
| `EvydenceHTTPServerFailures` | Positive 5-minute failed-outcome rate held for 5 minutes calls for bounded route/dependency diagnosis. This independent counter retains failures after detailed-series overflow. A sliding window can keep isolated errors visible; calibrate to traffic and routing needs. |
| `EvydenceTelemetryOverflow` | A positive 15-minute overflow increase held for 5 minutes calls for instrumentation/cardinality review rather than an automatic budget increase. |

Observe idle, normal-load, restart and dependency-failure behavior before
choosing production thresholds and severity. Record the reviewed deployment,
scrape interval, routing owner, expected job inventory and an expiry/review date
for silences. Alert hold time adds to scrape/evaluation delay and the metric's
own overdue threshold; it is not an end-to-end detection deadline.

Prometheus retention is operator-owned server configuration, not an Evydence
setting or part of this scrape YAML. Choose and record time/size limits, storage
access, backup policy and monitoring of the monitoring service. Keep enough
history for the longest example window (15 minutes), investigation and restart
comparison; actual capacity requirements depend on target/series churn and
scrape interval. Ledger job retention and Prometheus sample retention have
different meanings. Neither monitoring history nor a dashboard replaces the
append-only evidence ledger or its backup/restore policy.

### Repository validation

```sh
make observability-tools # once after checkout/lock changes; requires Node 22 and npm
make observability-check
```

The offline gate first compares real exporter snapshots with the committed
metric contract, then checks PromQL with the pinned official Prometheus editor
grammar and type linter (`@prometheus-io/codemirror-promql` and `lezer-promql`
`0.313.4`). These QA-only packages share the existing marketing npm workspace;
they are not application runtime dependencies. The checker rejects grammar
recovery nodes and supplements the linter with Go RE2/string, positive-duration
and disabled-feature checks. Recorded comparison controls cover every stable
function from the Go `v0.315.1` parser plus syntax/type and feature negatives;
this is not a claim of exhaustive language equivalence. It also checks
rule syntax/templates, metric and label references, finite label matches,
reset-aware aggregation, shared queue gauges, the narrow local scrape profile,
dashboard structure and local runbook sections. It opens no credential files,
contacts no targets and deploys nothing. The scrape-profile check deliberately
supports this example's fields; it is not a complete Prometheus configuration
validator. `make deploy-check` includes it.

After deliberately changing exporter metadata, review and regenerate the fixed
contract with:

```sh
go test ./internal/adapters/telemetry/metrics -run '^TestObservabilityMetricContract$' -count=1 -args -update-observability-contract
```

Re-run the gate and review the generated diff. New families still require
runtime tests and privacy/cardinality review; regeneration is not admission of
arbitrary metric labels.

## Limitations

- `/v1/metrics` remains tenant-scoped for ordinary admin actors. Explicit
  `instance:admin` adds the private process registry and bounded outbox gauges
  in text format; it does not expose tenant evidence or job details.
- Examples require operator topology, authentication, retention, routing,
  silence and escalation review. Offline validation does not prove deployed
  collection, notification delivery, a Grafana import or recovery effectiveness.
- Optional OpenTelemetry tracing and durable propagation remain separate
  EVY-1213 work; these examples do not claim an implemented tracing exporter.
