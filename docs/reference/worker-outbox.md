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

- `parse_sbom`
- `parse_vulnerability_scan`
- `parse_openapi_contract`
- `parse_vex`
- `sign_bundle`
- `verify_subject`
- `verify_attestation`

Current behavior is intentionally conservative. The API still records normalized signing and verification results before enqueueing jobs for the implemented paths. Parser jobs independently replay tenant-prefixed payload objects when `payload_ref` is present, verify object metadata and byte digests when `payload_hash` is present, parse SBOM, vulnerability-scan, OpenAPI, OpenVEX, CycloneDX VEX, and DSSE attestation payloads, and check that replayed payload summaries match the expected durable state. When `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`, parser-backed uploads store accepted records first and workers write parser-derived document fields after replay. The `parse_vex` worker also creates VEX-derived vulnerability decisions idempotently in that mode and updates the VEX import report from `accepted` to `parsed` with safe decision and mapping-failure counts. VEX parser failures update the import report to `failed` with `failure_code` and `failure_detail` before the outbox job is retried or marked terminal by the persisted job status. Missing objects, wrong tenant prefixes, tenant mismatches, oversized payload objects, malformed replay payloads, durable-state mismatches, incomplete verification, missing signatures, hash mismatch, uninitialized storage, and unsupported job kinds fail the job safely.

Parser and attestation jobs include a deterministic `parser_version` payload
field for new uploads. Workers reject unsupported parser versions and accept
older jobs with no parser version for upgrade compatibility.

Parser replay is worker-owned for CycloneDX SBOM, generic vulnerability-scan,
OpenAPI contract, DSSE build-attestation, OpenVEX document metadata, and
CycloneDX VEX document metadata when
`EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`. VEX-derived vulnerability
decision creation is also worker-owned in that mode and uses deterministic
decision IDs to avoid duplicate side effects on retry.

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
  `unsupported_parser_version`, and `durable_state_mismatch`.

This contract supports operations evidence for asynchronous processing. It does not claim external scanner authority, complete parsing coverage, or cryptographic attestation trust unless the relevant trust roots and verification receipts are recorded.
