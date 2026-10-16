# Kubernetes Deployment

This is a how-to guide for controlled self-hosted Kubernetes deployments.

The Helm chart lives at `deploy/helm/evydence`. It deploys the API, worker, service, optional ingress, lifecycle probes, and configuration for external PostgreSQL, S3/MinIO object storage, and external signing mode.

The API startup probe uses `/v1/startup` every five seconds with a five-second
timeout and 60 failures allowed (five minutes). After startup succeeds,
readiness uses `/v1/ready` every five seconds with a five-second timeout and
three consecutive failures; liveness uses `/v1/health` every ten seconds with
a two-second timeout and three failures. Startup/readiness timeouts exceed the
three-second dependency refresh budget. The startup allowance does not extend
the process's own initialization deadlines. See [probe semantics and
configuration freshness](reference/observability.md#endpoints).

Worker exec probes query the daemon's private loopback listener. Startup uses
`evydence-worker healthcheck --startup` every five seconds with 60 failures
allowed. Readiness uses `evydence-worker healthcheck` every five seconds with
three failures; both allow six seconds for command startup and the five-second
client timeout. Liveness uses `evydence-worker healthcheck --liveness` every ten
seconds with a two-second timeout and three failures. The command now checks
the running worker; starting a separate process alone cannot report health.

ConfigMap changes alter pod-template checksums for both daemons and trigger a
rollout. The API also receives a read-only projected desired configuration
revision, so a still-running pod can report stale configuration after the
projection updates. The existing single-writer `Recreate` rollout still incurs
planned downtime. Restart workloads after changing a separately managed Secret;
the chart does not automatically detect updates to that external object.

## Prerequisites

- An Evydence image with an explicit immutable tag or digest in a registry the
  cluster can pull from. Project-owned release-candidate images are published
  through the maintainer Container Image workflow as
  `ghcr.io/aatuh/evydence:<tag>` when that workflow has run for the tag.
  Operators should pin the digest and verify cosign evidence, or build, sign,
  and publish their own image through a controlled registry.
- External PostgreSQL and S3/MinIO-compatible object storage.
- Helm; the repository's render checks use the pinned CI tool described in
  [Release validation](reference/release-validation.md#build-toolchain).
- A pre-created object-store bucket.
- A Kubernetes secret containing at least `EVYDENCE_DATABASE_URL` and `EVYDENCE_API_KEY_PEPPER`.
- A signing setup compatible with `EVYDENCE_SIGNING_KEY_MODE=external`,
  `aws-kms`, `gcp-kms`, `azure-key-vault`, or the gateway-backed `pkcs11-hsm`
  profile documented in the configuration reference.

The chart does not create databases, buckets, KMS keys, or secrets.
It loads additional runtime variables, such as S3 credentials and API signing
gateway settings, from the selected Secret. Set `api.existingSecret` and
`worker.existingSecret` to separate Secrets when identities differ; each falls
back to `existingSecret`. Include the required database/pepper keys in each
selected Secret and grant only the permissions that daemon needs. For example,
a worker does not need the API's cloud signing credentials. Chart ConfigMap
settings take precedence over Secret variables; explicit database/pepper key
references retain their configured key names. Existing external Secret data
updates still require an operator rollout.
Use the [external controls matrix](reference/external-controls-matrix.md) to
track which of those production controls are repo-owned, operator-owned,
provider-owned, or legal/review-owned for the deployment.
Use [Hardened reference deployment](reference/hardened-reference-deployment.md)
for the full self-hosted topology, backup pairing, ingress/TLS, monitoring,
and signing review.

## Create Secrets

```sh
kubectl create secret generic evydence-secrets \
  --from-literal=EVYDENCE_DATABASE_URL='postgres://user:password@postgres.example.com:5432/evydence?sslmode=require' \
  --from-literal=EVYDENCE_API_KEY_PEPPER='replace-with-long-random-value'
```

Store real values in your secret manager or sealed-secret process. Do not commit rendered secrets.

## Install Or Upgrade

```sh
helm upgrade --install evydence ./deploy/helm/evydence \
  --set image.repository=ghcr.io/aatuh/evydence \
  --set image.tag='<verified-release-tag>@sha256:<verified-image-digest>' \
  --set env.s3Endpoint=s3.example.com \
  --set env.s3Bucket=evydence
```

Relevant chart values are defined in `deploy/helm/evydence/values.yaml`:

| Value | Purpose |
|-------|---------|
| `image.repository`, `image.tag` | API and worker image. |
| `api.replicas` | API writer replicas. Keep `1` for the current production profile. |
| `api.writerMode` | Runtime writer mode passed as `EVYDENCE_API_WRITER_MODE`. Keep `single` for production. |
| `api.*TimeoutSeconds`, `api.maxHeaderBytes`, `api.maxURLBytes`, `api.maxInFlightRequests`, `api.maxConcurrentUploads` | Validated API listener, request-target, and concurrency limits. Defaults match the canonical [Configuration](reference/configuration.md#http-ingress-limits-and-proxy-trust). |
| `api.rateLimitRequestsPerMinute`, `api.expensiveTenantRequestsPerMinute`, `api.rateLimitBucketCapacity`, `api.trustedProxyCIDRs` | Process-local edge and expensive-route limits. Set trusted CIDRs only for ingress proxies that sanitize `X-Forwarded-For`. |
| `worker.replicas` | Worker replicas. May be scaled with PostgreSQL outbox locking. |
| `worker.healthPort` | Private `127.0.0.1` probe port, integer `1..65535`, default `8081`. No Service or published container port is added. |
| `api.shutdownTimeoutSeconds`, `worker.shutdownTimeoutSeconds` | Request/job drain budgets, whole seconds `1..300`, default `30`. |
| `cleanupTimeoutSeconds` | Shared daemon resource-cleanup budget, whole seconds `1..60`, default `5`. |
| `api.terminationGracePeriodSeconds`, `worker.terminationGracePeriodSeconds` | Pod grace periods, default `40`; each must cover its drain budget plus cleanup plus a five-second margin. Invalid combinations fail rendering. |
| `api.resources`, `worker.resources` | Resource requests and limits. |
| `podSecurityContext`, `containerSecurityContext` | Non-root and least-privilege pod/container defaults. |
| `worker.probes.*` | Enable/override startup, readiness and liveness exec commands. Defaults query the running worker with their distinct modes. |
| `networkPolicy.enabled` | Optional starter NetworkPolicy for API ingress. |
| `existingSecret`, `api.existingSecret`, `worker.existingSecret` | Shared runtime Secret and optional daemon-specific overrides. Additional variables are loaded through `envFrom`; prefer separate scoped credentials. |
| `env.databaseURLSecretKey` | Secret key for `EVYDENCE_DATABASE_URL`. |
| `env.apiKeyPepperSecretKey` | Secret key for `EVYDENCE_API_KEY_PEPPER`. |
| `env.objectStore` | `s3` or `minio` for cluster deployments. |
| `env.s3Endpoint`, `env.s3Bucket`, `env.s3Region`, `env.s3UseSSL` | Object-store configuration. |
| `env.signingKeyMode` | Production signing mode. Use `external`, `aws-kms`, `gcp-kms`, `azure-key-vault`, or gateway-backed `pkcs11-hsm`. |
| `ingress.*` | Optional ingress host and TLS secret. |

## Shutdown And Upgrades

The API uses the `Recreate` deployment strategy: the old writer stops before
its replacement starts. This introduces planned API downtime during an upgrade.
A rolling update that waits for a ready replacement can stall because the old
API still holds the PostgreSQL writer lease. Worker replicas retain normal
rolling updates and outbox lease fencing.

The defaults allow 30 seconds for request/job drain and five seconds for resource
cleanup, with a five-second pod margin. For a longer drain, increase the matching
grace value in the same values file. For example, `api.shutdownTimeoutSeconds=90`
with `cleanupTimeoutSeconds=10` needs `api.terminationGracePeriodSeconds>=105`;
the worker then needs at least 45 seconds with its default 30-second drain.
Do not add a `preStop` delay without adding that delay to the grace period.
See [Configuration](reference/configuration.md#http-ingress-limits-and-proxy-trust)
for graceful and forced exit semantics and uncertain in-flight commits.

Before installation, run `make deploy-check` with the prerequisites above.
It renders the actual chart with valid and invalid lifecycle values and resolves
the production-like Compose configuration. It does not contact a Kubernetes
cluster or prove a live rollout, storage integration or backup readiness.

## Verify

```sh
kubectl rollout status deploy/evydence-evydence-api
kubectl rollout status deploy/evydence-evydence-worker
kubectl get pods -l app.kubernetes.io/name=evydence
kubectl port-forward svc/evydence-evydence 8080:8080
curl -sS http://localhost:8080/v1/ready
```

Expected result:

- API and worker deployments roll out.
- Pods stay ready.
- `/v1/ready` returns low-detail readiness JSON.
- Startup logs do not print bootstrap secrets when `ENV=production`.

## Rollback

Use Helm history and rollback commands:

```sh
helm history evydence
helm rollback evydence <revision>
```

Rollback does not roll back PostgreSQL data or object-store payloads. Keep database migrations, object-store backups, and release artifact versions paired with the Helm revision used for deployment.

## Production Notes

Production deployments should use external PostgreSQL, S3/MinIO-compatible object storage, TLS ingress, backup automation, network access controls, and external signing. Current production guidance uses a single API writer replica; the chart passes `EVYDENCE_API_WRITER_MODE=single` and `EVYDENCE_API_WRITER_REPLICAS=1`, production API startup rejects unsupported writer modes or replica counts above one, then enforces the stance with a PostgreSQL advisory writer lease. Worker replicas can scale independently through PostgreSQL outbox row locking. See [HA strategy](reference/ha-strategy.md), [Hardened reference deployment](reference/hardened-reference-deployment.md), [Production hardening review](production-hardening.md), [Production readiness](reference/production-readiness.md), and [Configuration](reference/configuration.md).
