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

Current behavior is intentionally conservative. The API performs parsing, signing, and verification synchronously before enqueueing jobs. The worker then validates that the expected durable state exists and, when a `payload_hash` is present, that the hash matches the recorded state. Missing state, incomplete verification, missing signatures, hash mismatch, uninitialized storage, and unsupported job kinds fail the job safely.

Safe logging rules:

- Log job ID, kind, subject type, and attempt count.
- Do not log raw payload bytes, object paths, bearer tokens, customer portal tokens, private keys, or full provider environment dumps.
- Error messages should describe the failed invariant without echoing subject IDs or raw payload fields.

This contract supports operations evidence for asynchronous processing. It does not claim external scanner authority, complete parsing coverage, or cryptographic attestation trust unless the relevant trust roots and verification receipts are recorded.
