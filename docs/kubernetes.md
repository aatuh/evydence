# Kubernetes Deployment

This is a how-to guide for self-hosted Kubernetes deployments.

The Helm chart lives at `deploy/helm/evydence`. It deploys the API, worker, service, optional ingress, readiness and liveness probes, and configuration for external PostgreSQL, S3/MinIO object storage, and external signing mode.

Create a secret with at least:

```sh
kubectl create secret generic evydence-secrets \
  --from-literal=EVYDENCE_DATABASE_URL='postgres://user:password@postgres.example.com:5432/evydence?sslmode=require' \
  --from-literal=EVYDENCE_API_KEY_PEPPER='replace-with-long-random-value'
```

Install:

```sh
helm upgrade --install evydence ./deploy/helm/evydence \
  --set image.repository=registry.example.com/evydence \
  --set image.tag=v0.1.0 \
  --set env.s3Endpoint=s3.example.com \
  --set env.s3Bucket=evydence
```

Production deployments should use external PostgreSQL, S3/MinIO-compatible object storage, TLS ingress, backup automation, and `EVYDENCE_SIGNING_KEY_MODE=external`. The chart does not create databases, buckets, KMS keys, or secrets.
