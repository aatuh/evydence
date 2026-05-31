# Configuration Reference

This is the canonical reference for current environment files and runtime variables.

## Environment Files

| File | Used By | Purpose | Commit Real Values? |
|------|---------|---------|---------------------|
| `.env.example` | `docker-compose.yml` | Local PostgreSQL and MinIO container credentials. | No |
| `.api.env.example` | API, worker, migration command | Local API runtime settings, durable database URL, object storage mode, bootstrap tenant, and local secret printing. | No |
| `.test.env.example` | Make targets for live PostgreSQL tests | `EVYDENCE_TEST_DATABASE_URL` and test-only API key pepper. | No |

Copy examples to local untracked files when needed:

```sh
cp .api.env.example .api.env
cp .test.env.example .test.env
```

The example secrets are placeholders. Replace them before using shared or production-like infrastructure.

## Runtime Variables

| Variable | Required | Default / Example | Notes |
|----------|----------|-------------------|-------|
| `ENV` | Production only | unset locally | Set `ENV=production` to enable production-safety checks. |
| `EVYDENCE_ADDR` | No | `:8080` | API bind address. |
| `EVYDENCE_API_KEY_PEPPER` | Production yes | `change-me-long-random-pepper` | HMAC pepper for API key, session, and portal-token hashes. Use a long random value. |
| `EVYDENCE_DATABASE_URL` | Production yes | `postgres://evydence:change-me@localhost:5432/evydence?sslmode=disable` | Enables PostgreSQL durable state, projections, migrations, and persisted outbox jobs. If unset, the API uses in-process state. |
| `EVYDENCE_POSTGRES_LOAD_MODE` | No | `snapshot_preferred` locally, `relational_only` when `ENV=production` | PostgreSQL state load mode. Supported values are `snapshot_preferred`, `relational_preferred`, and `relational_only`. Production defaults to relational-only startup reads, refuses snapshot fallback modes, and disables compatibility snapshot writes; snapshots remain available for local compatibility and non-production migration checks. |
| `EVYDENCE_API_WRITER_MODE` | No | `single` | API writer concurrency mode. Production supports only `single` or `single-writer` until multi-writer concurrency controls are implemented. |
| `EVYDENCE_API_WRITER_REPLICAS` | No | unset, chart sets `1` | Optional self-declared API writer replica count used by startup safety checks. Production rejects values other than `1`. |
| `EVYDENCE_OBJECT_STORE` | No | `filesystem` | Supported values are `filesystem`, `s3`, and `minio`. |
| `EVYDENCE_OBJECT_DIR` | Filesystem object store | `./tmp/objects` | Local raw payload storage root. |
| `EVYDENCE_S3_ENDPOINT` | S3/MinIO object store | `localhost:9000` | Endpoint for S3-compatible object storage. |
| `EVYDENCE_S3_BUCKET` | S3/MinIO object store | `evydence` | Bucket must already exist. |
| `EVYDENCE_S3_ACCESS_KEY_ID` | S3/MinIO object store | local example value | Store outside source control. |
| `EVYDENCE_S3_SECRET_ACCESS_KEY` | S3/MinIO object store | local example value | Store outside source control and logs. |
| `EVYDENCE_S3_REGION` | No | empty | Optional S3 region. |
| `EVYDENCE_S3_USE_SSL` | No | `false` locally, `true` in chart values | Use TLS for remote object storage. |
| `EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE` | No | `0` disabled | Optional in-process per-client request limit using the TCP remote address. Use reverse-proxy or ingress rate limiting for production edge controls. |
| `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS` | No | `false` | Optional hardening mode for parser-backed uploads. When set to `true`, the API stores accepted records and the outbox worker populates parser-derived fields from tenant-prefixed raw payloads after digest verification, including OpenVEX-derived vulnerability decisions. |
| `EVYDENCE_SKIP_MIGRATIONS` | No | unset | Set to `true` only when migrations are applied by a separate release process. API and worker startup still verify that no committed migrations are pending and fail closed if the database is behind. |
| `EVYDENCE_MIGRATIONS_DIR` | No | `migrations` | Migration directory for API startup and `cmd/evydence-migrate`. |
| `EVYDENCE_BOOTSTRAP_TENANT` | No | `Local Tenant` | Tenant name used when bootstrapping an empty store. |
| `EVYDENCE_BOOTSTRAP_DISABLED` | No | unset | Set to `true` to prevent startup bootstrap on an empty store. |
| `EVYDENCE_PRINT_BOOTSTRAP_SECRET` | Local only | `true` in `.api.env.example` | Prints the one-time bootstrap secret. Rejected when `ENV=production`. |
| `EVYDENCE_WORKER_POLL_INTERVAL` | No | `1s` | Worker outbox polling interval. |
| `EVYDENCE_WORKER_BATCH_SIZE` | No | `10` | Maximum outbox jobs claimed per polling cycle. |
| `EVYDENCE_WORKER_MAX_PAYLOAD_BYTES` | No | `20971520` | Maximum raw object payload size replayed by a worker job. |
| `EVYDENCE_OIDC_USERINFO_TIMEOUT_SECONDS` | No | `10` | Timeout for optional live OIDC UserInfo validation when `POST /v1/provider-verifications` includes `access_token`. |
| `EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST` | Local only | `false` | Allows HTTP OIDC issuer/UserInfo endpoints only for localhost tests. Do not use for production. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL` | No | unset | Optional HTTPS operator-controlled provider validation gateway. When set, provider verification uses this gateway instead of direct OIDC UserInfo calls. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN` | Gateway | unset | Optional bearer token for the provider validation gateway. Store outside source control and logs. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TIMEOUT_SECONDS` | No | `10` | Timeout for provider validation gateway requests. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST` | Local only | `false` | Allows an HTTP localhost gateway for tests. Do not use for production. |
| `EVYDENCE_SIGNING_KEY_MODE` | Production yes | `external`, `aws-kms`, `gcp-kms`, `azure-key-vault`, or `pkcs11-hsm` for production | Production rejects local plaintext signing-key mode. `aws-kms`, `gcp-kms`, and `azure-key-vault` can use built-in provider executors. `pkcs11-hsm` remains an HTTPS signing-gateway profile. |
| `EVYDENCE_SIGNING_EXECUTOR_URL` | No | unset | Optional HTTPS signing gateway used by `POST /v1/signing-operations` when `external_signature` is omitted. The API sends subject metadata and `payload_hash`, not raw payload bytes. |
| `EVYDENCE_SIGNING_EXECUTOR_TOKEN` | Signing gateway | unset | Optional bearer token for the signing gateway. Store outside source control and logs. |
| `EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS` | No | `10` | Timeout for signing gateway requests. |
| `EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST` | Local only | `false` | Allows `http://localhost` or loopback signing gateway endpoints for local development and tests. Do not use for production. |
| `EVYDENCE_AWS_KMS_KEY_ID` | AWS KMS mode | unset | AWS KMS asymmetric signing key id, alias, or ARN. Store IAM credentials outside Evydence config and logs. |
| `EVYDENCE_AWS_REGION` / `AWS_REGION` | AWS KMS mode | unset | Region used by the AWS KMS executor. `EVYDENCE_AWS_REGION` takes precedence. |
| `EVYDENCE_AWS_KMS_ENDPOINT` | No | unset | Optional AWS KMS-compatible endpoint for tests or controlled private endpoints. |
| `EVYDENCE_AWS_KMS_SIGNING_ALGORITHM` | No | `ECDSA_SHA_256` | Supported values are `ECDSA_SHA_256`, `RSASSA_PSS_SHA_256`, and `RSASSA_PKCS1_V1_5_SHA_256` because Evydence signs stored SHA-256 payload hashes. |
| `EVYDENCE_AWS_KMS_TIMEOUT_SECONDS` | No | `10` | Timeout for AWS KMS signing requests. |
| `EVYDENCE_GCP_KMS_ACCESS_TOKEN` | GCP KMS mode | unset | Bearer token used by the direct GCP Cloud KMS executor. Store outside source control and logs. If unset, `gcp-kms` requires `EVYDENCE_SIGNING_EXECUTOR_URL`. |
| `EVYDENCE_GCP_KMS_KEY_NAME` | GCP KMS mode | unset | Default GCP Cloud KMS key version resource name. A signing provider `key_ref` can override it. |
| `EVYDENCE_GCP_KMS_ENDPOINT` | No | `https://cloudkms.googleapis.com` | Optional GCP KMS endpoint for tests or controlled private endpoints. |
| `EVYDENCE_GCP_KMS_TIMEOUT_SECONDS` | No | `10` | Timeout for GCP KMS signing requests. |
| `EVYDENCE_AZURE_KEY_VAULT_URL` | Azure Key Vault mode | unset | HTTPS Key Vault URL used by the direct Azure Key Vault executor. |
| `EVYDENCE_AZURE_KEY_VAULT_ACCESS_TOKEN` | Azure Key Vault mode | unset | Bearer token used by the direct Azure Key Vault executor. Store outside source control and logs. If unset, `azure-key-vault` requires `EVYDENCE_SIGNING_EXECUTOR_URL`. |
| `EVYDENCE_AZURE_KEY_VAULT_KEY_NAME` | Azure Key Vault mode | unset | Default Key Vault key name. A signing provider `key_ref` URL can override it. |
| `EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION` | Azure Key Vault mode | unset | Default Key Vault key version. A signing provider `key_ref` URL can override it. |
| `EVYDENCE_AZURE_KEY_VAULT_ALGORITHM` | No | `ES256` | Azure Key Vault signing algorithm used for the SHA-256 digest. |
| `EVYDENCE_AZURE_KEY_VAULT_API_VERSION` | No | `7.4` | Azure Key Vault API version. |
| `EVYDENCE_AZURE_KEY_VAULT_TIMEOUT_SECONDS` | No | `10` | Timeout for Azure Key Vault signing requests. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL` | No | unset | Optional HTTPS operator-controlled gateway for transparency inclusion proof fetch/verification material. When unset, Evydence fetches from the configured public log endpoint. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN` | Gateway | unset | Optional bearer token for the transparency proof gateway. Store outside source control and logs. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TIMEOUT_SECONDS` | No | `10` | Timeout for transparency proof gateway requests. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST` | Local only | `false` | Allows an HTTP localhost transparency proof gateway for tests. Do not use for production. |
| `EVYDENCE_TEST_DATABASE_URL` | Live tests | `.test.env.example` value | Used by `make live-postgres-check`, `make postgres-integration-test`, and `make release-check`. |

## Production Rejection Checks

When `ENV=production`, the API refuses to start unless:

- `EVYDENCE_DATABASE_URL` is set.
- `EVYDENCE_API_KEY_PEPPER` is non-empty and not the local default.
- `EVYDENCE_SIGNING_KEY_MODE` is `external`, `aws-kms`, `gcp-kms`,
  `azure-key-vault`, or `pkcs11-hsm`. `pkcs11-hsm` requires
  `EVYDENCE_SIGNING_EXECUTOR_URL`; `gcp-kms` and `azure-key-vault` require
  either their direct provider credentials or `EVYDENCE_SIGNING_EXECUTOR_URL`.
- `EVYDENCE_PRINT_BOOTSTRAP_SECRET` is not `true`.
- `EVYDENCE_POSTGRES_LOAD_MODE`, when set, is `relational_only`.
- `EVYDENCE_API_WRITER_MODE`, when set, is `single` or `single-writer`.
- `EVYDENCE_API_WRITER_REPLICAS`, when set, is `1`.

These checks reduce unsafe runtime defaults. They do not replace secret management, network controls, backup validation, or external signing operations.

When `ENV=production` and `EVYDENCE_POSTGRES_LOAD_MODE` is unset, API and worker
processes load only from tenant-scoped relational rows and do not write new
compatibility snapshots. Production refuses snapshot fallback modes. Local
development keeps `snapshot_preferred` and snapshot writes by default to
preserve existing workflows. Use `relational_preferred` only for controlled
non-production migration or recovery checks that intentionally fall back to the
snapshot.

In production, API startup rejects non-single writer mode, rejects a declared
API writer replica count above one, takes a PostgreSQL advisory writer lease,
and fails if another API writer already holds it. Worker replicas are not
constrained by that lease because outbox jobs use row locking.

When PostgreSQL is configured, critical runtime mutations use focused
transaction-backed writes for tenants, API-key hashes, SSO-session hashes,
customer-portal token hashes, idempotency records, audit-chain entries,
signing keys, signatures, release bundles, verification results, provider
verification receipts, vulnerability decisions, and outbox jobs. Remaining
resource families still depend on the broader ledger persistence path until
later repository decomposition work.

## S3/MinIO Object-Retention Verification

When `EVYDENCE_OBJECT_STORE=s3` or `minio`, object-retention policy verification
uses the same S3/MinIO client to check bucket versioning and default
object-lock settings. When the policy names a tenant-prefixed sample object,
the verifier also checks object-level retention; when `require_legal_hold` is
true, it checks that legal hold is enabled for that sample object. The resulting
policy record includes verification checks and limitations. These checks cover
the configured bucket and sample object only: operators still need to review
bucket creation mode, IAM policy, lifecycle rules, backups, and any
deployment-specific WORM requirements.

## Signing Executors

When `EVYDENCE_SIGNING_EXECUTOR_URL` is set, signing operations can omit
`external_signature`. Evydence sends a JSON request containing tenant id,
provider id/type, key reference, subject type/id, and `payload_hash`. The
gateway returns a signature, optional provider key id, and optional algorithm.
Evydence records the signature receipt and verification checks; it does not
store production private key material or send raw evidence payload bytes.

`EVYDENCE_SIGNING_KEY_MODE=gcp-kms` and `azure-key-vault` can use direct
provider executors when their access-token and key configuration variables are
set. If direct credentials are absent, they fall back to requiring the HTTPS
signing gateway. `pkcs11-hsm` always uses the HTTPS signing gateway because
native HSM modules and slots are deployment-specific. Operators remain
responsible for provider credentials, IAM, key lifecycle, gateway operation
where used, and custody review.

Tenant signing-provider records also accept `native_pkcs11_hsm` for deployments
that operate local PKCS#11 modules or slots outside Evydence. The provider
`key_ref` must be a `pkcs11:` URI and must not embed PIN values, PIN sources,
passwords, or secrets. This profile records custody evidence for review through
`GET /v1/reports/custody-review`; it does not load native HSM modules or prove
hardware custody by itself.

When `EVYDENCE_SIGNING_KEY_MODE=aws-kms`, Evydence uses the AWS KMS `Sign`
operation against `EVYDENCE_AWS_KMS_KEY_ID`. The executor signs the decoded
SHA-256 digest with KMS `MessageType=DIGEST`; it does not send raw evidence
payload bytes to AWS KMS. Operators remain responsible for AWS IAM policy,
key lifecycle, CloudTrail review, regional availability, and external review
of whether the selected key custody profile satisfies their deployment needs.

When `EVYDENCE_SIGNING_KEY_MODE=gcp-kms`, Evydence can call GCP Cloud KMS
`asymmetricSign` with a configured bearer token and key-version resource name.
The executor sends a SHA-256 digest, not raw evidence payload bytes. Operators
remain responsible for GCP IAM, token issuance, audit logs, key lifecycle, and
regional availability.

When `EVYDENCE_SIGNING_KEY_MODE=azure-key-vault`, Evydence can call Azure Key
Vault `sign` with a configured bearer token, key name, key version, and
algorithm. The executor sends a SHA-256 digest encoded for Key Vault, not raw
evidence payload bytes. Operators remain responsible for Azure identity, Key
Vault access policy/RBAC, audit logs, key lifecycle, and regional availability.

## Provider Validation Gateway

When `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL` is set, provider identity
verification can call an operator-controlled HTTPS gateway with tenant id,
provider id/type, issuer, subject, group-claim name, and whether the caller
supplied an access token. Evydence does not forward that access token to the
gateway. The gateway returns non-secret checks, groups, and limitations.
Evydence stores the checks and normalized groups, not the supplied token or raw
provider response.

This gateway is an integration point for GitHub, GitLab, IdP, directory, or
other provider-specific validation logic that depends on deployment-owned
credentials and policies. It does not make external group synchronization
automatic, does not create permanent role bindings, and does not prove provider
truth beyond the gateway response and recorded limitations.

## Transparency Proof Gateway

When `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL` is set, public transparency
proof fetches call an operator-controlled HTTPS gateway instead of constructing
`/entries/{external_id}/inclusion-proof` requests directly against the log
endpoint. Evydence sends tenant id, log id, entry id, configured endpoint,
external entry id, and the expected Evydence entry hash. The gateway returns
RFC6962-style proof material plus optional non-secret checks and limitations.

Evydence still verifies the returned proof material locally against the
published entry hash. The gateway records provider-specific proof retrieval or
timestamp semantics as evidence only; operators remain responsible for public
log trust, gateway operation, and provider availability.

## Related Commands

- Local operation: [Install and operate](../how-to/install-and-operate.md)
- Release validation: [Release validation](release-validation.md)
- Kubernetes secret wiring: [Kubernetes deployment](../kubernetes.md)
