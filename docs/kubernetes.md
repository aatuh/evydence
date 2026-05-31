# Kubernetes Deployment

This is a how-to guide for controlled self-hosted Kubernetes deployments.

The Helm chart lives at `deploy/helm/evydence`. It deploys the API, worker, service, optional ingress, readiness and liveness probes, and configuration for external PostgreSQL, S3/MinIO object storage, and external signing mode.

## Prerequisites

- An Evydence image with an explicit immutable tag or digest in a registry the
  cluster can pull from. Project-owned release-candidate images are published
  through the maintainer Container Image workflow as
  `ghcr.io/aatuh/evydence:<tag>` when that workflow has run for the tag.
  Operators should pin the digest and verify cosign evidence, or build, sign,
  and publish their own image through a controlled registry.
- External PostgreSQL and S3/MinIO-compatible object storage.
- A pre-created object-store bucket.
- A Kubernetes secret containing at least `EVYDENCE_DATABASE_URL` and `EVYDENCE_API_KEY_PEPPER`.
- A signing setup compatible with `EVYDENCE_SIGNING_KEY_MODE=external`,
  `aws-kms`, `gcp-kms`, `azure-key-vault`, or the gateway-backed `pkcs11-hsm`
  profile documented in the configuration reference.

The chart does not create databases, buckets, KMS keys, or secrets.

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
  --set image.tag=v0.1.0-rc.4@sha256:de5627ec300cb603c3f1dc21029bffc096d43399114888cd5c194e00f1285603 \
  --set env.s3Endpoint=s3.example.com \
  --set env.s3Bucket=evydence
```

Relevant chart values are defined in `deploy/helm/evydence/values.yaml`:

| Value | Purpose |
|-------|---------|
| `image.repository`, `image.tag` | API and worker image. |
| `api.replicas` | API writer replicas. Keep `1` for the current production profile. |
| `api.writerMode` | Runtime writer mode passed as `EVYDENCE_API_WRITER_MODE`. Keep `single` for production. |
| `worker.replicas` | Worker replicas. May be scaled with PostgreSQL outbox locking. |
| `api.resources`, `worker.resources` | Resource requests and limits. |
| `podSecurityContext`, `containerSecurityContext` | Non-root and least-privilege pod/container defaults. |
| `worker.probes.*` | Worker exec probes using `evydence-worker healthcheck`. |
| `networkPolicy.enabled` | Optional starter NetworkPolicy for API ingress. |
| `existingSecret` | Secret containing runtime sensitive variables. |
| `env.databaseURLSecretKey` | Secret key for `EVYDENCE_DATABASE_URL`. |
| `env.apiKeyPepperSecretKey` | Secret key for `EVYDENCE_API_KEY_PEPPER`. |
| `env.objectStore` | `s3` or `minio` for cluster deployments. |
| `env.s3Endpoint`, `env.s3Bucket`, `env.s3Region`, `env.s3UseSSL` | Object-store configuration. |
| `env.signingKeyMode` | Production signing mode. Use `external`, `aws-kms`, `gcp-kms`, `azure-key-vault`, or gateway-backed `pkcs11-hsm`. |
| `ingress.*` | Optional ingress host and TLS secret. |

## Verify

```sh
kubectl rollout status deploy/evydence-api
kubectl rollout status deploy/evydence-worker
kubectl get pods -l app.kubernetes.io/name=evydence
kubectl port-forward svc/evydence 8080:8080
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

Production deployments should use external PostgreSQL, S3/MinIO-compatible object storage, TLS ingress, backup automation, network access controls, and external signing. Current production guidance uses a single API writer replica; the chart passes `EVYDENCE_API_WRITER_MODE=single` and `EVYDENCE_API_WRITER_REPLICAS=1`, production API startup rejects unsupported writer modes or replica counts above one, then enforces the stance with a PostgreSQL advisory writer lease. Worker replicas can scale independently through PostgreSQL outbox row locking. See [Production hardening review](production-hardening.md), [Production readiness](reference/production-readiness.md), and [Configuration](reference/configuration.md).
