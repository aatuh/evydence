# Architecture Diagram

This explanation is a compact map of the current controlled self-hosted
production candidate architecture. It omits many resource families but shows the
trust boundaries operators need to understand first.

```mermaid
flowchart LR
  ci[CI collectors and CLI uploaders] --> api[Evydence API /v1]
  users[Operators and API clients] --> api
  portal[Customer portal token holder] --> api

  api --> auth[Scoped API key / SSO / portal auth]
  auth --> app[Application ledger and policy services]
  app --> pg[(PostgreSQL relational state)]
  app --> obj[(S3/MinIO or filesystem object store)]
  app --> outbox[(PostgreSQL outbox)]
  app --> signer[Signing executor or KMS/gateway]
  app --> provider[Optional provider validation gateway]
  app --> transparency[Optional transparency proof gateway]

  worker[Evydence worker replicas] --> outbox
  worker --> pg
  worker --> obj
  worker --> signer

  pg --> reports[Readiness, control, package, audit and backup reports]
  obj --> reports
```

## Boundaries

- API clients and collectors are untrusted until authenticated and authorized.
- Tenant IDs are enforced at application and persistence boundaries.
- Raw payload bytes live in object storage under tenant-prefixed keys.
- PostgreSQL is the production source of truth for the controlled profile.
- Workers re-read object payloads and verify digests before parser side effects.
- Signing providers receive payload hashes or signing requests, not raw evidence
  payload bytes from Evydence.
- Provider validation, public transparency, broad WORM/object-lock proof, and
  native HSM custody remain deployment/provider responsibilities unless a
  specific deployment closes those checks.
