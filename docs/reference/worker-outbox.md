# Worker Outbox Contract

The worker claims PostgreSQL outbox jobs with row locking and retries failed jobs with backoff. Job handlers must be idempotent: retrying a job may verify existing durable state, but must not duplicate evidence, signatures, reports, or audit-chain entries.

Configured job kinds:

- `parse_sbom`
- `parse_vulnerability_scan`
- `parse_openapi_contract`
- `parse_vex`
- `sign_bundle`
- `verify_subject`
- `verify_attestation`

Current behavior is intentionally conservative. The API still records normalized signing and verification results before enqueueing jobs for the implemented paths. Parser jobs independently replay tenant-prefixed payload objects when `payload_ref` is present, verify object metadata and byte digests when `payload_hash` is present, parse SBOM, vulnerability-scan, OpenAPI, OpenVEX, and DSSE attestation payloads, and check that replayed payload summaries match the expected durable state. When `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`, CycloneDX SBOM, generic vulnerability-scan, and OpenAPI contract uploads store accepted records first, and the `parse_sbom`, `parse_vulnerability_scan`, and `parse_openapi_contract` workers write parser-derived fields after replay. Missing objects, wrong tenant prefixes, tenant mismatches, oversized payload objects, malformed replay payloads, durable-state mismatches, incomplete verification, missing signatures, hash mismatch, uninitialized storage, and unsupported job kinds fail the job safely.

Parser and attestation jobs include a deterministic `parser_version` payload
field for new uploads. Workers reject unsupported parser versions and accept
older jobs with no parser version for upgrade compatibility.

Parser replay is worker-owned for CycloneDX SBOM, generic vulnerability-scan,
and OpenAPI contract normalized fields when
`EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`. OpenVEX and attestation
upload paths still create initial normalized records before worker replay
validates and backfills missing fields. Moving those remaining parser side
effects fully out of the request path remains production hardening work.

Workers use the same object-store environment variables as the API. The default worker payload replay limit is 20 MiB and can be adjusted with `EVYDENCE_WORKER_MAX_PAYLOAD_BYTES`.

Safe logging rules:

- Log job ID, kind, subject type, and attempt count.
- Do not log raw payload bytes, object paths, bearer tokens, customer portal tokens, private keys, or full provider environment dumps.
- Error messages should describe the failed invariant without echoing subject IDs or raw payload fields.

This contract supports operations evidence for asynchronous processing. It does not claim external scanner authority, complete parsing coverage, or cryptographic attestation trust unless the relevant trust roots and verification receipts are recorded.
