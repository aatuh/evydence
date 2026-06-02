# Hardened Reference Deployment

This reference describes the supported controlled self-hosted deployment shape
for Evydence release candidates. Use it to review a deployment before pilot or
internal production use. It is not legal compliance proof, certification,
complete SBOM proof, authoritative scanner coverage, or a secure-release
guarantee.

The narrow supported topology is:

- one API writer replica;
- scalable worker replicas using PostgreSQL outbox locking;
- external PostgreSQL as the durable source of truth;
- external S3/MinIO-compatible object storage for raw payloads and generated
  packages;
- TLS terminated at a reverse proxy or Kubernetes ingress;
- deployment secrets supplied by an operator-controlled secret manager;
- external signing mode or an operator-controlled signing provider;
- paired database and object-store backups with restore rehearsal evidence;
- authenticated metrics, admin, audit, and package-access surfaces.

Use the [pilot deployment checklist](../how-to/pilot-deployment-checklist.md)
for the copy-paste go/no-go record and the
[external controls matrix](external-controls-matrix.md) to assign operator,
provider, repo, and review responsibilities.

## Reference Topology

| Layer | Required Shape | Operator Evidence To Keep |
| --- | --- | --- |
| API | One API writer replica with `ENV=production`, `EVYDENCE_API_WRITER_MODE=single`, and `EVYDENCE_API_WRITER_REPLICAS=1`. | Helm values or deployment manifest, startup log showing production mode, and `/v1/ready` result. |
| Worker | One or more worker replicas with the same database and object-store config as the API. | Worker rollout status, outbox backlog metrics, retry/failure counters, and parser/signing/report job evidence. |
| PostgreSQL | External PostgreSQL, not an application sidecar, with migrations applied before traffic. | Database version, migration version, backup schedule, restore rehearsal output, access policy, and encryption setting. |
| Object storage | External S3/MinIO-compatible object storage with tenant-prefixed keys. | Bucket policy, versioning or retention setting, encryption setting, lifecycle policy, object-lock receipt where required, and object/database backup pairing. |
| Ingress/TLS | TLS at the edge with body-size limits matched to expected uploads. | Ingress or reverse-proxy config, certificate owner, request body limit, timeout, redaction, and rate-limit evidence. |
| Secrets | Database URL, API-key pepper, object-store credentials, signing credentials, SSO secrets, and portal secrets from deployment secrets. | Secret-manager path or sealed-secret reference, rotation owner, and proof that secrets are not rendered into logs or manifests. |
| Signing | `EVYDENCE_SIGNING_KEY_MODE=external`, `aws-kms`, `gcp-kms`, `azure-key-vault`, or gateway-backed `pkcs11-hsm`. | Provider key ID, signing receipt, rotation plan, custody review, and limitations for the selected provider. |
| Monitoring | Authenticated metrics, readiness checks, safe logs, and alert routing. | Prometheus scrape config, dashboard link, alert route, and sanitized incident runbook. |

## Helm Values

For Kubernetes, start from `deploy/helm/evydence/values.yaml` and set an
explicit image tag or digest. The chart intentionally defaults
`api.replicas` to `1` and `api.writerMode` to `single`.
Use `.production.env.example` as the environment-variable checklist when
translating settings into Kubernetes Secrets or another secret manager; keep
the empty secret fields empty in git and fill them only in the deployment
system.

```sh
helm upgrade --install evydence ./deploy/helm/evydence \
  --set image.repository=ghcr.io/aatuh/evydence \
  --set image.tag='<verified-tag>@sha256:<verified-digest>' \
  --set api.replicas=1 \
  --set api.writerMode=single \
  --set worker.replicas=2 \
  --set env.objectStore=s3 \
  --set env.s3Endpoint=s3.example.com \
  --set env.s3Bucket=evydence \
  --set ingress.enabled=true \
  --set ingress.host=evydence.example.com \
  --set ingress.tlsSecretName=evydence-tls
```

Expected result:

- Helm renders both API and worker deployments.
- The API deployment uses one writer replica.
- Worker replicas can be scaled to match parser/signing/report load.
- Pods read sensitive values from `existingSecret`, not literal values in the
  chart.
- Startup fails closed if production mode uses unsafe defaults.

## Ingress, TLS, And Upload Limits

Put the public API behind a reverse proxy or Kubernetes ingress that terminates
TLS. Configure:

- request body limits for expected evidence, SBOM, VEX, scan, attestation,
  package, and bundle uploads;
- connection and response timeouts that account for upload size and object-store
  latency;
- edge rate limits for unauthenticated, token-heavy, and upload endpoints;
- header redaction for `Authorization`, cookies, database URLs, object-store
  credentials, provider tokens, and API-key material;
- no unauthenticated public access to `/v1/metrics`, `/v1/audit-log`, or
  `/v1/admin/instance`.

Evydence verifies uploaded payload digests and records object references, but
the ingress or reverse proxy remains responsible for TLS certificates,
client-facing rate limits, and raw request-size enforcement.

## Backup Pairing

Back up PostgreSQL and object storage from the same recovery point. A database
backup without matching object payloads cannot verify raw evidence hashes after
restore. Object payload backups without matching database rows cannot
reconstruct release, report, and package relationships.

Keep these records with every deployment backup:

- Evydence release tag, image digest or binary checksum, OpenAPI checksum, and
  migration checksum;
- database backup identifier and completion time;
- object-store backup, replication, or version marker from the same recovery
  window;
- signing-provider custody and recovery note;
- restore rehearsal output with audit-chain, release-bundle, package, and
  object-digest verification.

Use [Backup and restore](../runbooks/backup-restore.md) and
[Object store recovery](../runbooks/object-store-recovery.md) for the operator
runbooks.

## Validation Sequence

Before accepting pilot or internal production traffic:

```sh
make deploy-check
make release-acceptance
make production-check
```

Expected result:

- `make deploy-check` validates repository-owned deployment assets and the
  single-writer Helm defaults.
- `make release-acceptance` validates release metadata, legal/governance files,
  and release-evidence language.
- `make production-check` runs the strict live-PostgreSQL gate with coverage,
  migration compatibility, restore rehearsal, release signing smoke test, and
  production-check summary output.

Complete the [pilot deployment checklist](../how-to/pilot-deployment-checklist.md)
for the target environment. Record any skipped provider checks, missing object
lock, missing KMS/HSM proof, missing SSO provider evidence, or untested restore
procedure as deployment limitations.

## Boundaries

Repo-owned checks can verify Evydence code, schemas, release artifacts, Helm
defaults, local restore rehearsals, and generated evidence. They cannot verify
that an operator's cloud account, identity provider, object-store policy,
network, backup tooling, signing provider, or legal/review process is suitable.

Do not broaden this reference into a multi-writer API HA claim. The supported
self-hosted profile remains a single API writer replica with scalable worker
replicas until multi-writer API concurrency is implemented, tested, and
documented.
