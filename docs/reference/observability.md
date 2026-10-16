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
