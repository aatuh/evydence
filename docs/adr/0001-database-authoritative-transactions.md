# ADR 0001: Database-Authoritative Command Transactions

Status: accepted for incremental implementation. This ADR defines the target
contract for EVY-202 through EVY-206; it does not claim that every existing
write family already satisfies it.

## Context

Evydence records tenant-scoped evidence, credential hashes, idempotency keys,
audit-chain entries, signatures, release decisions, package metadata, and
outbox jobs. These records must not become visible in process memory, an API
response, or an external report unless their durable database transaction has
committed. The current, generated [persistence decomposition inventory](../reference/persistence-decomposition.md)
lists every `persistLocked`, `persistCriticalLocked`, and
`persistReleaseLedgerLocked` call site and remains the migration work list.

Object storage cannot participate in a PostgreSQL transaction. Raw payload
bytes therefore require an explicit staged/finalized protocol rather than an
imaginary distributed transaction.

## Decision

Each production command has one PostgreSQL unit of work. It validates tenant
scope and immutable/append-only rules, performs domain inserts or state
transitions, inserts the matching audit entry and outbox job, then commits. The
application publishes a cached/read-model mutation and returns success only
after that commit. A failed command rolls back every database mutation and
publishes nothing.

Database constraints are authoritative for tenant ownership, uniqueness,
idempotency request binding, append-only relationships, and foreign-key links.
Retryable serialization, deadlock, or transient connectivity failures return a
safe failure without publishing state. A retry reuses the idempotency key only
when the canonical request content matches; otherwise it is rejected.

For object-backed commands, the process first writes a tenant-prefixed staged
object with size/type/digest validation. The database transaction records it as
pending and includes the command, audit, and outbox records. A worker verifies
the exact bytes, finalizes the object reference, and appends any lifecycle
record. Crashes before commit leave a staged object eligible for bounded
cleanup; crashes after commit leave a durable pending record for replay. No
metadata may claim trusted/finalized bytes before that verification.

The in-memory store is permitted only for explicit local, demo, and unit-test
use when no production PostgreSQL contract is configured. It must emulate
commit-or-rollback behavior for tests but is never a production authority.
Compatibility snapshots/import-export are explicit administrative workflows,
versioned and integrity-validated; they cannot bypass tenant checks or normal
command validation.

## Invariants

- A successful response has a committed domain row, audit row, idempotency
  record when supplied, and required outbox row.
- Credential and portal/session secrets are returned only after their hashes
  commit; raw bearer values are never persisted or logged.
- Evidence core fields, audit entries, links, approvals, exceptions, and
  lifecycle records remain immutable or append-only.
- Audit ordering is allocated and verified inside the transaction; failed or
  retried commands cannot expose a skipped committed sequence.
- A rollback, serialization failure, context cancellation, or process crash
  cannot update a process cache ahead of durable state.

## Consequences

EVY-202 removes silent clone/load failure. EVY-203 introduces transaction and
repository ports. EVY-204 through EVY-206 migrate the inventory families in
order and reduce the generated broad-call-site count to zero. Until then, the
inventory and the single-writer production limitation are the accurate scope;
this ADR is a technical decision, not a production-completeness claim.
