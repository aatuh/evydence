# Worker Outbox Contract

The worker claims PostgreSQL outbox jobs with row locking and retries only
transient failures with bounded exponential backoff plus deterministic jitter.
Each logical operation has a stable tenant-scoped deduplication key, so a
duplicate enqueue request does not create another worker job. Job handlers must
remain idempotent: retrying or reclaiming a job may verify existing durable
state, but must not duplicate evidence, signatures, reports, or audit-chain
entries.

Each claim receives a lease token. Completion and failure recording require the
current token, so a worker that continues after its five-minute lease expires
cannot overwrite a newer worker's outcome. An expired running job is reclaimed
when attempts remain; an expired final attempt becomes terminal.

PostgreSQL parser side effects use the same lease token. The worker locks the
still-running, unexpired claim, writes only that job's focused release-ledger
mutation, and renews the lease in one database transaction. A stale or
reclaimed worker therefore receives a conflict before it can replace a newer
parser report, decision, or audit entry. VEX decision audit-entry IDs are also
derived from the logical job operation, so retrying after a transient
completion failure does not create a second logical audit record.

## Failure and replay lifecycle

Worker failures use stable, payload-free classes and codes:

- `transient` failures retry while attempts remain, using a capped backoff.
- `permanent` failures enter `dead_letter` immediately.
- `poisoned` failures (for example a durable payload invariant mismatch) enter
  `dead_letter` immediately.

The database records claim, retry, terminal, completion, and replay outcomes in
an append-only attempt-history table. It stores stable failure codes rather than
raw object-store, provider, database, or payload errors. A `dead_letter` job is
never claimed again automatically.

An explicit instance administrator may replay one terminal job through
`POST /v1/admin/outbox/{id}/replay` with an `Idempotency-Key`. The replay resets
its attempt counter, preserves history, and appends an `outbox_job.replayed`
audit record. Tenant administrators and wildcard tenant API keys without the
explicit `instance:admin` scope cannot use this operation. `GET /v1/admin/outbox`
returns aggregate pending, running, terminal, and oldest-pending metrics without
tenant IDs, job payloads, or raw failure details.

Configured job kinds:

- `finalize_payload`
- `parse_sbom`
- `parse_vulnerability_scan`
- `parse_openapi_contract`
- `parse_vex`
- `sign_bundle`
- `verify_subject`
- `verify_attestation`

## Staged raw-payload lifecycle

For a managed raw upload, the API streams bytes into a deterministic,
tenant-prefixed staging key while calculating its SHA-256 digest and byte
count. The command transaction then records the domain data, a tenant-scoped
payload metadata row, and a `finalize_payload` job together. The metadata
contains the digest, size, media type, staging and final keys, timestamps, and
one of these states: `staged`, `finalized`, `failed`, or `orphaned`.

The finalizer verifies the staged bytes and copies them to the final key before
atomically marking metadata `finalized`. A worker retry is safe if the copy
completed just before a crash: it verifies the existing final object rather
than creating a second trusted payload. A transient finalization error leaves a
safe `failed` state and is retried through the normal outbox policy. If both
staging and final objects are missing, metadata is marked `orphaned` and the
job is terminal until an operator restores the correct object bytes or records
new evidence.

Readers for new parser and attestation jobs require the lifecycle metadata to
be `finalized`, to match the tenant, digest, and final key, and then verify the
object digest again. They do not trust staged, failed, or orphaned objects. The
same digest deduplicates within a tenant; a different tenant receives a
separate key namespace. If a database transaction fails after streaming, the
object remains only in the tenant staging namespace, where it can be identified
as uncommitted storage residue; it is never exposed at the final payload key.

Current behavior is intentionally conservative. The API still records normalized signing and verification results before enqueueing jobs for the implemented paths. Parser jobs independently replay tenant-prefixed payload objects when `payload_ref` is present, verify object metadata and byte digests when `payload_hash` is present, parse SBOM, vulnerability-scan, OpenAPI, OpenVEX, CycloneDX VEX, and DSSE attestation payloads, and check that replayed payload summaries match the expected durable state. When `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`, non-VEX parser-backed uploads store accepted records first and workers write parser-derived document fields after replay. Every VEX upload persists its verified normalized document, an `accepted` report, and a bounded `vex-decision-request.v1.0.0` request in the same transaction with `worker_create_decisions=true`. The `parse_vex` worker creates decisions idempotently after commit and updates the report to `parsed` with safe decision, supersession, and mapping-failure counts. When a replayable object exists, the worker reparses it and rejects a normalized request that does not match the raw payload; without an object, it consumes the versioned normalized request directly. A VEX job remains `accepted` and retries when a release-scoped vulnerability-scan projection is still pending, so claim order cannot permanently discard otherwise mappable decisions. Once the linked report is `parsed`, a reclaimed job is a no-op and cannot recompute or downgrade the committed result. Other VEX processing failures update the import report to `failed` with `failure_code` and `failure_detail` before the outbox job is retried or marked terminal by the persisted job status. Missing objects, wrong tenant prefixes, tenant mismatches, oversized payload objects, malformed replay payloads or normalized requests, durable-state mismatches, incomplete verification, missing signatures, hash mismatch, uninitialized storage, and unsupported job kinds fail the job safely.

If no active scan-parser dependency exists because it completed without the
required projection or became terminal, the VEX report becomes `failed` with
the stable `dependency_failed` code instead of retrying forever.

Parser and attestation jobs include a deterministic `parser_version` payload
field for new uploads. Workers reject unsupported parser versions and accept
older jobs with no parser version for upgrade compatibility.

Parser replay is worker-owned for CycloneDX SBOM, generic vulnerability-scan,
OpenAPI contract, and DSSE build-attestation metadata when
`EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`. OpenVEX and CycloneDX VEX
metadata is verified and stored by the API, while decision creation is always
worker-owned, including without object storage, and uses deterministic decision
and audit IDs to avoid duplicate side effects on retry.

The production PostgreSQL worker persists only the records changed by a parser
job (for example one SBOM projection, one attestation, or the VEX decisions,
report, and audit entries created by that replay). It does not write the full
state snapshot loaded before parsing, so an unrelated command committed during
the replay cannot be overwritten by stale worker state. The full-snapshot
`SaveState` path remains only as a compatibility fallback for local test stores
that do not implement focused release-ledger mutations; production wiring does
implement the focused mutation contract.

## PostgreSQL projection consistency

Worker-owned parser and decision records can commit after an API process has
loaded its in-memory compatibility read model. `WorkerProjectionStore` reloads
the tenant's SBOMs, vulnerability scans, OpenAPI contracts, VEX documents and
import reports, build attestations, vulnerability decisions, and audit chain.
Every PostgreSQL loader includes the tenant ID in its SQL predicate; records are
not loaded globally and filtered afterward. The compatibility merge validates
tenant identity, applicable referenced resource coordinates, and audit-chain
continuity before publishing the complete projection, and fails without
partially replacing the local view.

A standalone refresh opens one read-only, repeatable-read transaction and holds
a shared per-tenant PostgreSQL advisory fence through commit. A command unit of
work exposes `Repositories.WorkerProjection`, bound to that unit of work's
`pgx.Tx`, and takes the exclusive tenant fence before loading. Focused worker
projection mutations and audit appends take the same exclusive fence; audit
append takes it before the audit-chain sequencing lock. Consequently, a command
that reads a worker-owned projection inside its unit of work cannot commit a
dependent business record or audit entry after an intervening mutation changed
that tenant's projection. Locks are tenant-scoped, so unrelated tenants do not
share this serialization boundary.

This projection is a compatibility bridge for the deprecated Ledger read model.
It does not grant cross-context mutation authority and does not represent
completion of the EVY-904 decision, package, or verification service migration
or the EVY-905 database-backed query-service migration.

Successful parser replay also appends one reserved `parser_normalization`
evidence marker that binds the source evidence, parser version, payload digest,
normalized subject set, and audit entry. The API validates that provenance
before exposing a marker through get, list, search, or package projection paths;
malformed or forged markers fail closed. Generic evidence creation cannot use
the reserved type. Parser-normalization markers and the worker-owned `sbom`,
`vulnerability_scan`, `openapi_contract`, `vex`, and `build_attestation`
evidence types cannot be generically linked or superseded because changing
their projection coordinates independently would make durable state
inconsistent. Parser replay is create-or-return-existing only after the
PostgreSQL adapter validates the full existing marker, its source, and its audit
entry in the current tenant transaction.

Workers use the same object-store environment variables as the API. The default worker payload replay limit is 20 MiB and can be adjusted with `EVYDENCE_WORKER_MAX_PAYLOAD_BYTES`.

Safe logging rules:

- Log job ID, kind, subject type, and attempt count.
- Do not log raw payload bytes, object paths, bearer tokens, customer portal tokens, private keys, or full provider environment dumps.
- Worker logs use stable failure class and code rather than raw processing,
  database, object-store, or provider errors. Error messages should describe
  the failed invariant without echoing subject IDs or raw payload fields.
- VEX import report `failure_code` values are stable operator hints such as
  `payload_read_failed`, `payload_ref_invalid`, `payload_tenant_mismatch`,
  `payload_digest_mismatch`, `payload_too_large`, `payload_invalid`,
  `unsupported_parser_version`, `durable_state_mismatch`, and
  `dependency_failed`.

This contract supports operations evidence for asynchronous processing. It does not claim external scanner authority, complete parsing coverage, or cryptographic attestation trust unless the relevant trust roots and verification receipts are recorded.
