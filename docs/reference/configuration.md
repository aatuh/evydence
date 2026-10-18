# Configuration Reference

This is the canonical reference for current environment files and runtime variables.

## Environment Files

| File | Used By | Purpose | Commit Real Values? |
|------|---------|---------|---------------------|
| `.env.example` | `docker-compose.yml` | Local PostgreSQL and MinIO container credentials. | No |
| `.api.env.example` | API, worker, migration command | Local API runtime settings, durable database URL, object storage mode, bootstrap tenant, and local secret printing. | No |
| `.test.env.example` | Make targets for live PostgreSQL and MinIO tests | `EVYDENCE_TEST_DATABASE_URL`, loopback MinIO test credentials, and test-only API key pepper. | No |
| `.production.env.example` | Operators translating config into deployment secrets | Production-mode variable checklist with empty secret fields, external object storage, single-writer API settings, rate limiting, signing profiles, and telemetry/diagnostic notes. | No |

Copy examples to local untracked files when needed:

```sh
cp .api.env.example .api.env
cp .test.env.example .test.env
```

The example secrets are placeholders. Replace them before using shared or production-like infrastructure.

For production planning, read `.production.env.example` as a checklist. It is
not intended to be committed after filling values, and the empty required
secret fields are deliberate so production startup fails until an operator
supplies real values through a secret manager, Kubernetes Secret, sealed-secret
process, or equivalent deployment control.

## Maintaining Generated Configuration

The runtime schema in `internal/platform/config/` owns the generated settings in
this reference, `.production.env.example` and the [Kubernetes guide](../kubernetes.md).
Production example selections are explicitly labelled; they do not replace
runtime defaults. Native PostgreSQL and cloud SDK variables retain their stated
resolution owners.

After changing schema metadata, run from the repository root:

```sh
make config-generate
make config-check
```

`config-check` is read-only and also runs through `make docs-check`. It fails on
drift or invalid section markers and compares exposed Helm integer bounds and
secret-file option roles with the runtime schema. Generation requires explicit `--write` through
`config-generate`; it replaces only marked sections and retains surrounding
operator explanations and existing file permission bits. The command reads no
runtime configuration, resolves no credentials and prints no document contents
or diffs. Secret example values remain empty.

The tool accepts only the three fixed repository paths, requires existing
regular files of at most 4 MiB and rejects symlink targets and ancestors. It
validates all documents before staging replacements. Each changed file is
replaced by rename; the three-file update is not a transaction. Avoid concurrent
edits while generating, and rerun the check after an interrupted update.

## Runtime Variables

API startup captures its environment once and validates shared settings and
active project-secret files, then prepares native PostgreSQL configuration,
before constructing providers, opening storage or listening. HTTP limits,
session lifetimes, bootstrap input and provider settings use that captured
configuration. Invalid settings return fixed diagnostics without supplied values
or underlying causes. Configuration freshness observes source/revision drift;
it does not reload running settings. Legacy environment parsers in shared
logging, health, object-store wiring and cleanup wiring have been removed;
programmatic adapter construction retains defensive validation.


Explicit malformed booleans, numbers and durations fail startup instead of using
silent fallbacks. API writer mode accepts only `single` or `single-writer` in all
profiles; the old unimplemented local experimental mode is rejected. Direct cloud
signing modes require their configured key references before credential loading.

The Azure adapter disables the native SDK's raw diagnostic listener during
process initialization and disables SDK telemetry for credentials it constructs.
`AZURE_SDK_GO_LOGGING=all` is rejected in production and does not enable raw SDK
diagnostics in other profiles. Injected credentials and external credential tools
retain their own telemetry policy; their internals are not configured by these
owned-client options. Structured application events remain the diagnostic path.

Online CLI commands (`github-actions upload-build`, `ci preflight`,
`import-bundle upload`, `upload manifest`, and `release upload-evidence`) capture
once and apply shared configuration before reading payloads or making requests.
Explicit flags override inline environment defaults; an explicit `--api-key`,
including an empty one, conflicts with `EVYDENCE_API_KEY_FILE` instead of silently
replacing that credential source. Active key files use the same bounded private
file checks as other project secrets. Build timestamps and GitHub metadata apply
only to the build command; resource-selection defaults apply to CI preflight.
Offline hashing/verification, local manifest/key generation and manifest
validation do not acquire online dependencies. Help retains its existing usage
and exit-code behavior without applying configuration or resolving credentials.

Malformed client URLs (including user info, queries and fragments), credentials
with internal whitespace/control characters, and explicit zero/malformed build
timestamps fail with fixed diagnostics. `GITHUB_RUN_ATTEMPT` is a strict positive
integer at most 2147483647, matching the persisted PostgreSQL integer; absence
uses 1. Valid numeric spelling remains part of the existing build idempotency key
(for example, `02` stays `02`), while the payload uses numeric 2. An absent build
start time uses the command clock. Finish timestamps retain their supplied offset
and fractional precision. CI preflight retains its documented exit-code classes.
Online commands, including release upload dry runs, validate their applicable
configuration and write structured lifecycle diagnostics to stderr; command
results remain on stdout. Dry runs make no network requests.

Worker `healthcheck` and `--healthcheck` commands capture and validate `ENV`,
`EVYDENCE_LOG_LEVEL`, `EVYDENCE_LOG_FORMAT` and `EVYDENCE_WORKER_HEALTH_ADDR`
before querying the loopback worker. Readiness is the default; `--startup` and
`--liveness` select those probes. This client does not require or resolve database,
runtime-profile, object-storage, provider or metrics settings from the daemon's
environment. In production, unknown `EVYDENCE_` option names still fail closed.
HTTP proxies and redirects are disabled for these local requests.

Worker `parser-replay` and `reconcile` commands require the PostgreSQL runtime
profile and database settings. They share storage, migration, load-mode, logging
and cleanup configuration with the daemon, including active database and S3
secret-file alternatives. Each validates its own operation timeout; daemon
listeners, metrics credentials, polling and the other command's timeout do not
apply. Invalid explicit timeouts now fail before runtime startup rather than
silently using the default. Cleanup failures make the command fail.

The daemon's `EVYDENCE_WORKER_MAX_PAYLOAD_BYTES` is captured once and applies
through both object retrieval and structured SBOM, scanner and VEX replay parsing.
Changing the environment does not change a running processor. This setting does
not raise the HTTP request-body limits below. Operator `parser-replay` instead
uses the existing fixed `EvidenceDocumentLimit` from `internal/app/payload_limits.go`;
it requires bounded object reads and rejects oversized adapter results before
appending a derived record. An unbounded storage fallback is not accepted.

Worker modes that open PostgreSQL and the migration command resolve pgx native
settings into an owned, private pool configuration before opening connections.
Native `PG*` inputs, service/password/TLS files and OS defaults retain the pinned
driver's resolution policy. Pool construction uses copies of that resolved
configuration. These native files are separate from project `_FILE` secrets;
the project's private-file permissions, containment and byte limits do not apply
to arbitrary native driver files. Resolution failures use a fixed diagnostic
without the connection string, file path or underlying cause.

<!-- BEGIN EVYDENCE GENERATED CONFIGURATION -->
| Variable | Processes | Type | Default | Constraints | Notes |
| --- | --- | --- | --- | --- | --- |
| `CI` | online CLI | boolean | `false` | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `upload commands`, `github-actions upload-build`, `ci preflight`. |
| `ENV` | API, worker, migration, online CLI, worker probe, parser replay, reconciliation | choice | unset | choices: unset, `development`, `staging`, `production`, `test`, `local` | Production-safety selector. Unset retains the non-production development profile. Production example: `production`. |
| `EVYDENCE_ADDR` | API | text | `:8080` | schema validation | API bind address. |
| `EVYDENCE_API_KEY` | online CLI | text (secret) | unset | schema validation | Online CLI bearer credential. Never include the value in diagnostics or generated examples. CLI flag: `--api-key`. CLI commands: `upload commands`, `github-actions upload-build`, `ci preflight`. |
| `EVYDENCE_API_KEY_FILE` | online CLI | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_API_KEY`; unset the inline value. Runtime resolution retains the documented file checks. CLI commands: `upload commands`, `github-actions upload-build`, `ci preflight`. |
| `EVYDENCE_API_KEY_PEPPER` | API | text (secret) | unset | schema validation | HMAC pepper for API key, session, and portal-token hashes. Use a long random value. Required in production: API. |
| `EVYDENCE_API_KEY_PEPPER_FILE` | API | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_API_KEY_PEPPER`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_API_URL` | online CLI | url | unset | endpoint policy: api-client | Online CLI API endpoint; offline/help/version commands do not require it. CLI flag: `--url`. CLI commands: `upload commands`, `github-actions upload-build`, `ci preflight`. |
| `EVYDENCE_API_WRITER_MODE` | API | choice | `single` | choices: `single`, `single-writer` | API writer concurrency mode. Production supports only `single` or `single-writer` until multi-writer concurrency controls are implemented. |
| `EVYDENCE_API_WRITER_REPLICAS` | API | integer | `1` | 1..9223372036854775807 | Optional self-declared API writer replica count used by startup safety checks. Production rejects values other than `1`. |
| `EVYDENCE_ARTIFACT_ID` | online CLI | text | unset | schema validation | Optional online CLI resource selection; normal server-side scope authorization still applies. CLI flag: `--artifact-id`. CLI commands: `ci preflight`. |
| `EVYDENCE_AUTH_FAILURES_PER_MINUTE` | API | integer | `20` | 1..60000 | Per-client failure budget for each of credential authentication, public SSO, and portal access. Values must be 1 through 60000; zero cannot disable it. In-flight verification reserves budget until completion. See [failure limits](#authentication-and-portal-failure-limits-unreleased). |
| `EVYDENCE_AWS_KMS_ENDPOINT` | API | url | unset | endpoint policy: tls-base | Optional AWS KMS-compatible endpoint for tests or controlled private endpoints. |
| `EVYDENCE_AWS_KMS_KEY_ID` | API | text | unset | schema validation | AWS KMS asymmetric signing key id, alias, or ARN. Store IAM credentials outside Evydence config and logs. |
| `EVYDENCE_AWS_KMS_SIGNING_ALGORITHM` | API | choice | `ECDSA_SHA_256` | choices: `ECDSA_SHA_256`, `RSASSA_PSS_SHA_256`, `RSASSA_PKCS1_V1_5_SHA_256` | Supported values are `ECDSA_SHA_256`, `RSASSA_PSS_SHA_256`, and `RSASSA_PKCS1_V1_5_SHA_256` because Evydence signs stored SHA-256 payload hashes. |
| `EVYDENCE_AWS_KMS_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for AWS KMS signing requests. |
| `EVYDENCE_AWS_REGION` | API | text | unset | schema validation | AWS signing region; the existing AWS_REGION fallback is an alias, not a second independent option. Aliases: AWS_REGION. |
| `EVYDENCE_AZURE_KEY_VAULT_ALGORITHM` | API | choice | `ES256` | choices: `ES256` | Azure Key Vault signing algorithm used for the SHA-256 digest. |
| `EVYDENCE_AZURE_KEY_VAULT_API_VERSION` | API | text | `7.4` | schema validation | Azure Key Vault API version. |
| `EVYDENCE_AZURE_KEY_VAULT_KEY_NAME` | API | text | unset | schema validation | Default Key Vault key name required for metadata readiness. A signing provider `key_ref` URL can override it for actual signing. |
| `EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION` | API | text | unset | schema validation | Default Key Vault key version required for metadata readiness. A signing provider `key_ref` URL can override it for actual signing. |
| `EVYDENCE_AZURE_KEY_VAULT_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for Azure Key Vault signing requests. |
| `EVYDENCE_AZURE_KEY_VAULT_URL` | API | url | unset | endpoint policy: tls-base | HTTPS Key Vault URL used by the direct Azure Key Vault executor. |
| `EVYDENCE_BOOTSTRAP_DISABLED` | API | boolean | `false` | schema validation | Set to `true` to prevent startup bootstrap on an empty store. Production example: `true`. |
| `EVYDENCE_BOOTSTRAP_TENANT` | API | text | `Local Tenant` | input bytes <= 65536 | Tenant name used when bootstrapping an empty store; raw value must be valid UTF-8 without NUL bytes, at most 65,536 bytes, and nonblank after trimming. |
| `EVYDENCE_BUILD_FINISHED_AT` | online CLI | timestamp | unset | schema validation | Optional CLI build finish timestamp. CLI flag: `--finished-at`. CLI commands: `github-actions upload-build`. |
| `EVYDENCE_BUILD_STARTED_AT` | online CLI | timestamp | unset; current UTC command time when unset | schema validation | CLI build start timestamp; absence uses the command clock, not a frozen generated timestamp. CLI flag: `--started-at`. CLI commands: `github-actions upload-build`. |
| `EVYDENCE_BUILD_STATUS` | online CLI | text | `passed` | schema validation | CLI build-evidence status; defaults to passed. CLI flag: `--status`. CLI commands: `github-actions upload-build`. |
| `EVYDENCE_CONFIGURATION_REVISION` | API, worker | text | unset | schema validation | API/worker configuration revision: exactly 64 lowercase hexadecimal characters. Must match the projected revision file at startup and on subsequent cached health refreshes. This is an operator revision identifier, not evidence or a secret digest. |
| `EVYDENCE_CONFIGURATION_REVISION_FILE` | API, worker | path | unset | input bytes <= 4096 | Absolute path to an operator-owned local regular file containing the desired revision (at most 256 bytes, surrounding whitespace allowed). Symlinked projections must resolve inside the configured parent directory. Missing, invalid or changed content fails startup/readiness; no hot reload. See [configuration freshness](observability.md#configuration-freshness). |
| `EVYDENCE_DATABASE_URL` | API, worker, migration, parser replay, reconciliation | postgres-dsn (secret) | unset | schema validation | PostgreSQL durable state, projections, migrations, and persisted outbox jobs. Connection settings alone do not select the runtime profile. Required for: API, worker, migration, parser replay, reconciliation. |
| `EVYDENCE_DATABASE_URL_FILE` | API, worker, migration, parser replay, reconciliation | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_DATABASE_URL`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE` | API | integer | `30` | 0..60000 | Per-tenant, per-route limit for document ingestion, bundle/import/export, report/package generation, diffs, and policy evaluation. Set `0` only for controlled local evaluation. |
| `EVYDENCE_GCP_KMS_ENDPOINT` | API | url | `https://cloudkms.googleapis.com` | endpoint policy: tls-base | Optional GCP KMS endpoint for tests or controlled private endpoints. |
| `EVYDENCE_GCP_KMS_KEY_NAME` | API | text | unset | schema validation | Default GCP Cloud KMS key version resource name. Required for the process's metadata readiness probe; a signing provider `key_ref` can still override it for actual signing. |
| `EVYDENCE_GCP_KMS_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for GCP KMS signing requests. |
| `EVYDENCE_GITHUB_OIDC_SUBJECT` | online CLI | text | unset | schema validation | Captured GitHub OIDC subject used by the CLI evidence command, not independently verified source identity. CLI flag: `--oidc-subject`. CLI commands: `github-actions upload-build`. |
| `EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS` | API | seconds | `120` | 1..3600 seconds | Idle keep-alive timeout. Values must be whole seconds from 1 through 3600. |
| `EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS` | API | integer | `8` | 1..10000 | Simultaneous native SBOM, VEX, scan, and OpenAPI-document upload cap. Saturation returns a retryable `429` Problem Details response. |
| `EVYDENCE_HTTP_MAX_HEADER_BYTES` | API | integer | `16384` | 1024..1048576 | Listener header-size cap in bytes. Values must be 1024 through 1048576. |
| `EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS` | API | integer | `256` | 1..100000 | Simultaneous ordinary application request cap. Saturation returns a retryable `429` Problem Details response. Canonical lifecycle probes use separate admission; see [observability](observability.md#endpoints). |
| `EVYDENCE_HTTP_MAX_URL_BYTES` | API | integer | `8192` | 1024..65536 | Raw request-target cap in bytes, including its query string. Values must be 1024 through 65536. |
| `EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS` | API | seconds | `5` | 1..60 seconds | Maximum time to receive HTTP request headers. Values must be whole seconds from 1 through 60. |
| `EVYDENCE_HTTP_READ_TIMEOUT_SECONDS` | API | seconds | `30` | 1..900 seconds | Maximum total request-read time. Values must be whole seconds from 1 through 900. |
| `EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS` | API | seconds | `30` | 1..300 seconds | Request drain budget after `SIGINT`, `SIGTERM`, or a permanent listener failure. Values must be whole seconds from 1 through 300. |
| `EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS` | API | seconds | `60` | 1..900 seconds | Maximum response-write time. Values must be whole seconds from 1 through 900. |
| `EVYDENCE_LOG_FORMAT` | API, worker, migration, online CLI, worker probe, parser replay, reconciliation | choice | `json` | choices: `json`, `text` | `json` or `text` (case-insensitive); both retain the same structured fields. Logs go to stderr; command results and explicitly requested local bootstrap credentials retain their separate stdout contract. |
| `EVYDENCE_LOG_LEVEL` | API, worker, migration, online CLI, worker probe, parser replay, reconciliation | choice | `info` | choices: `debug`, `info`, `warn`, `error` | API, worker and migration diagnostics: `debug`, `info`, `warn`, `error` (case-insensitive). Invalid values fail before dependency startup. |
| `EVYDENCE_MIGRATIONS_DIR` | API, worker, migration, parser replay, reconciliation | path | `migrations` | input bytes <= 4096 | Migration directory for API startup and `cmd/evydence-migrate`. |
| `EVYDENCE_OBJECT_DIR` | API, worker, parser replay, reconciliation | path | `tmp/objects` | input bytes <= 4096 | Local raw payload storage root. |
| `EVYDENCE_OBJECT_STORE` | API, worker, parser replay, reconciliation | choice | `filesystem` | choices: `file`, `filesystem`, `s3`, `minio` | Supported values are `filesystem`, `s3`, and `minio`. Production example: `s3`. |
| `EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST` | API | boolean | `false` | production-forbidden override | Allow HTTP loopback OIDC discovery only outside production. |
| `EVYDENCE_OIDC_DISCOVERY_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | OIDC discovery timeout in whole seconds. |
| `EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST` | API | boolean | `false` | production-forbidden override | Allows an HTTP loopback OIDC issuer/UserInfo endpoint only outside production. `ENV=production` rejects this setting when `true`. Discovery and UserInfo must remain the same origin, so a bearer token is never sent to a discovered different origin. |
| `EVYDENCE_OIDC_USERINFO_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for optional live OIDC UserInfo validation when `POST /v1/provider-verifications` includes `access_token`. |
| `EVYDENCE_PARSER_REPLAY_TIMEOUT` | parser replay | duration | `2m` | 1..9223372036854775807 nanoseconds | Positive parser-replay command timeout; malformed explicit values fail before runtime opens. |
| `EVYDENCE_POSTGRES_LOAD_MODE` | API, worker, parser replay, reconciliation | choice | unset; production: `relational_only`; non-production: `snapshot_preferred`; relational_only in production; snapshot_preferred outside production | choices: unset, `snapshot`, `snapshot_preferred`, `snapshot-preferred`, `relational`, `relational_preferred`, `relational-preferred`, `relational_only`, `relational-only`; production choices: unset, `relational_only`, `relational-only` | PostgreSQL state load mode. Supported values are `snapshot_preferred`, `relational_preferred`, and `relational_only`. Production defaults to relational-only startup reads, refuses snapshot fallback modes, and disables compatibility snapshot writes; snapshots remain available for local compatibility and non-production migration checks. |
| `EVYDENCE_PRINT_BOOTSTRAP_SECRET` | API | boolean | `false` | production-forbidden override | Prints the one-time bootstrap secret. Rejected when `ENV=production`. |
| `EVYDENCE_PRODUCT_ID` | online CLI | text | unset | schema validation | Optional online CLI resource selection; normal server-side scope authorization still applies. CLI flag: `--product-id`. CLI commands: `ci preflight`. |
| `EVYDENCE_PROJECT_ID` | online CLI | text | unset | schema validation | Optional online CLI resource selection; normal server-side scope authorization still applies. CLI flag: `--project-id`. CLI commands: `ci preflight`. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST` | API | boolean | `false` | production-forbidden override | Allows an HTTP loopback gateway only outside production. `ENV=production` rejects this setting when `true`. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for provider validation gateway requests. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN` | API | text (secret) | unset | schema validation | Optional bearer token for the provider validation gateway. Store outside source control and logs. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN_FILE` | API | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL` | API | url | unset | endpoint policy: gateway | Optional HTTPS operator-controlled provider validation gateway. When set, provider verification uses this gateway instead of direct OIDC UserInfo calls. |
| `EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY` | API | integer | `10000` | 1..1000000 | Maximum tracked buckets per in-process limiter. Values must be 1 through 1000000. General client/tenant quotas evict least-recent buckets; failure quotas deny new keys while capacity is full, preserving active failure history. |
| `EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE` | API | integer | `120` | 0..60000 | In-process per-client request limit. Set `0` only for controlled local evaluation; retain a reverse-proxy or ingress limit as the primary edge control. Canonical lifecycle probes are excluded; see [observability](observability.md#endpoints). |
| `EVYDENCE_RECONCILIATION_TIMEOUT` | reconciliation | duration | `10m` | 1..9223372036854775807 nanoseconds | Positive object-reconciliation command timeout; malformed explicit values fail before runtime opens. |
| `EVYDENCE_RELEASE_ID` | online CLI | text | unset | schema validation | Optional online CLI resource selection; normal server-side scope authorization still applies. CLI flag: `--release-id`. CLI commands: `ci preflight`. |
| `EVYDENCE_RUNTIME_PROFILE` | API, worker, parser replay, reconciliation | choice | unset | choices: `postgres` | The only supported runtime profile, including local evaluation. Retired `local_memory` input fails before opening resources and explains the PostgreSQL migration. Required for: API, worker, parser replay, reconciliation. Production example: `postgres`. |
| `EVYDENCE_S3_ACCESS_KEY_ID` | API, worker, parser replay, reconciliation | text (secret) | unset | schema validation | Store outside source control. |
| `EVYDENCE_S3_ACCESS_KEY_ID_FILE` | API, worker, parser replay, reconciliation | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_S3_ACCESS_KEY_ID`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_S3_BUCKET` | API, worker, parser replay, reconciliation | s3-bucket-name | unset | schema validation | Bucket must already exist. Names use the pinned MinIO SDK's basic S3 bucket grammar after trimming, including its 3 through 63 byte bound. |
| `EVYDENCE_S3_ENDPOINT` | API, worker, parser replay, reconciliation | url | unset | schema validation | Endpoint for S3-compatible object storage. |
| `EVYDENCE_S3_REGION` | API, worker, parser replay, reconciliation | text | unset | schema validation | Optional S3 region. |
| `EVYDENCE_S3_SECRET_ACCESS_KEY` | API, worker, parser replay, reconciliation | text (secret) | unset | schema validation | Store outside source control and logs. |
| `EVYDENCE_S3_SECRET_ACCESS_KEY_FILE` | API, worker, parser replay, reconciliation | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_S3_SECRET_ACCESS_KEY`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_S3_USE_SSL` | API, worker, parser replay, reconciliation | boolean | `false` | schema validation | Use TLS for remote object storage. Production example: `true`. |
| `EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS` | API, worker, migration, parser replay, reconciliation | seconds | `5` | 1..60 seconds | API/worker resource-cleanup budget after draining or operator-command execution; whole seconds from 1 through 60. Invalid values fail before storage opens. |
| `EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST` | API | boolean | `false` | production-forbidden override | Allows an HTTP loopback signing gateway only outside production. `ENV=production` rejects this setting when `true`. |
| `EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64` | API | base64 | unset | decoded bytes <= 32 | Required base64-encoded Ed25519 public key. Evydence verifies the gateway signature over the canonical signing-request hash before persisting a receipt. This is public trust material, never a private key. |
| `EVYDENCE_SIGNING_EXECUTOR_READINESS_URL` | API | url | unset | endpoint policy: gateway-readiness | Explicit non-mutating GET endpoint on the signing URL's origin (same scheme, host and effective port), with no user information, query or fragment. Must return `200` with exactly `{"status":"ok"}` when required signing dependencies are available; responses are capped at 4096 bytes. Missing configuration keeps production readiness unavailable. Uses the signing bearer token and rejects redirects. |
| `EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for signing gateway requests. |
| `EVYDENCE_SIGNING_EXECUTOR_TOKEN` | API | text (secret) | unset | schema validation | Optional bearer token for the signing gateway. Store outside source control and logs. |
| `EVYDENCE_SIGNING_EXECUTOR_TOKEN_FILE` | API | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_SIGNING_EXECUTOR_TOKEN`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_SIGNING_EXECUTOR_URL` | API | url | unset | endpoint policy: gateway | HTTPS signing gateway used by `POST /v1/signing-operations`. The API sends a canonical request that binds subject metadata and `payload_hash`, never raw payload bytes. |
| `EVYDENCE_SIGNING_KEY_MODE` | API | choice | unset | choices: unset, `local`, `external`, `aws-kms`, `aws_kms`, `gcp-kms`, `gcp_kms`, `azure-key-vault`, `azure_key_vault`, `pkcs11-hsm`, `pkcs11_hsm`; production choices: `external`, `aws-kms`, `aws_kms`, `gcp-kms`, `gcp_kms`, `azure-key-vault`, `azure_key_vault`, `pkcs11-hsm`, `pkcs11_hsm` | Production rejects local plaintext signing-key mode. `aws-kms`, `gcp-kms`, and `azure-key-vault` can use built-in provider executors. `pkcs11-hsm` remains an HTTPS signing-gateway profile. Production example: `external`. |
| `EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64` | API | base64 | unset | decoded bytes <= 1048576 | Base64-encoded operator-managed PEM public key, bounded to 1 MiB after decoding. It can be configured with or instead of the trusted root. |
| `EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64` | API | base64 | unset | decoded bytes <= 1048576 | Base64-encoded operator-managed Sigstore trusted-root JSON, bounded to 1 MiB after decoding. Do not put private keys here. |
| `EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION` | API | text | unset | input bytes <= 256 | Non-secret operator version label recorded in the verification receipt. Missing, malformed, or oversized trust configuration prevents startup. |
| `EVYDENCE_SKIP_MIGRATIONS` | API, worker, parser replay, reconciliation | boolean | `false` | schema validation | Set to `true` only when migrations are applied by a separate release process. API and worker startup still verify that no committed migrations are pending and fail closed if the database is behind. |
| `EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS` | API | seconds | `1800` | 60..43200 seconds | Integer `60..43200`, at most the configured maximum lifetime. Cannot be disabled. Captured on new sessions. |
| `EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS` | API | seconds | `43200` | 60..43200 seconds | Integer `60..43200`; maximum absolute lifetime for newly issued SSO sessions. Explicit expiry beyond the configured limit is rejected. |
| `EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST` | API | boolean | `false` | production-forbidden override | Allow HTTP loopback transparency fetch only outside production. |
| `EVYDENCE_TRANSPARENCY_FETCH_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Direct transparency HTTP fetch timeout in whole seconds. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST` | API | boolean | `false` | production-forbidden override | Allows an HTTP loopback transparency gateway only outside production. `ENV=production` rejects this setting when `true`. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TIMEOUT_SECONDS` | API | seconds | `10` | 1..9223372036 seconds | Timeout for transparency proof gateway requests. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN` | API | text (secret) | unset | schema validation | Optional bearer token for the transparency proof gateway. Store outside source control and logs. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN_FILE` | API | path (secret) | unset | schema validation | Private-file alternative for `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN`; unset the inline value. Runtime resolution retains the documented file checks. |
| `EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL` | API | url | unset | endpoint policy: gateway | Optional HTTPS operator-controlled gateway for transparency inclusion proof fetch/verification material. When unset, Evydence fetches from the configured public log endpoint. |
| `EVYDENCE_TRUSTED_PROXY_CIDRS` | API | cidrs | unset | items <= 256 | Comma-separated proxy source CIDRs. Evydence uses `X-Forwarded-For` only when the direct TCP peer is in this list; otherwise it rate-limits the direct remote address. |
| `EVYDENCE_WORKER_BATCH_SIZE` | worker | integer | `10` | 1..9223372036854775807 | Maximum outbox jobs claimed per polling cycle. |
| `EVYDENCE_WORKER_HEALTH_ADDR` | worker, worker probe | text | `127.0.0.1:8081` | schema validation | Worker lifecycle listener and healthcheck client address. Must be a literal IPv4/IPv6 loopback address with a nonzero port; remote addresses, hostnames and wildcard binds are rejected before storage opens. Set distinct ports for multiple workers in one network namespace. Helm sets the port through `worker.healthPort`. |
| `EVYDENCE_WORKER_MAX_PAYLOAD_BYTES` | worker | integer | `20971520` | 1..9223372036854775806 | Immutable worker-job byte budget shared by bounded object reads, structured replay parsing and normalized VEX decision inputs; leaves room for the bounded reader's extra sentinel byte. |
| `EVYDENCE_WORKER_METRICS_ADDR` | worker | text | unset; loopback default only when metrics token file is configured; when `EVYDENCE_WORKER_METRICS_TOKEN_FILE`: `127.0.0.1:9091` | input bytes <= 128 | Optional separate `GET/HEAD /metrics` listener. Requires a literal loopback or private IPv4/IPv6 address, nonzero port, no zone and a port/address distinct from the lifecycle listener. Hostnames, public and wildcard binds are rejected before runtime opens. Both metrics variables unset disables the listener. See [worker scraping](observability.md#worker-scraping). |
| `EVYDENCE_WORKER_METRICS_TOKEN_FILE` | worker | path | unset | input bytes <= 4096 | Absolute path to an operator-owned POSIX regular secret file: exactly `evymetrics_` plus 64 lowercase hexadecimal characters, with one optional final LF. Use mode `0600`, `0640` or `0440`; group write and all other-user permissions are rejected. Relative symlink projections must stay inside the configured parent directory. Only the credential hash is retained; rotation/revocation requires replacing the file and restarting/stopping the worker. API/SSO/tenant credentials are not accepted. |
| `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS` | API | boolean | `false` | schema validation | Optional hardening mode for non-VEX parser-backed uploads. When set to `true`, the API stores accepted records and the outbox worker populates parser-derived fields from tenant-prefixed raw payloads after digest verification. VEX documents are normalized during upload and their decisions are always created post-commit by the worker from a versioned normalized request; a stored raw payload adds independent replay verification. Production example: `true`. |
| `EVYDENCE_WORKER_POLL_INTERVAL` | worker | duration | `1s` | 1..9223372036854775807 nanoseconds | Worker outbox polling interval. |
| `EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS` | worker | seconds | `30` | 1..300 seconds | Active-job drain and acknowledgement budget after `SIGINT` or `SIGTERM`; whole seconds from 1 through 300. Invalid values reject daemon startup before storage opens. |
| `GITHUB_ACTOR` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_JOB` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_REF` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_REPOSITORY` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_RUN_ATTEMPT` | online CLI | integer | `1` | 1..2147483647 | Positive GitHub run attempt, bounded by the persisted PostgreSQL integer. Malformed explicit values are rejected; absence defaults to 1. Capturing it does not verify provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_RUN_ID` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_SHA` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |
| `GITHUB_WORKFLOW_REF` | online CLI | text | unset | schema validation | Existing CI/CLI process input; capture does not verify the claimed provider identity. CLI commands: `github-actions upload-build`. |

Native inputs retain SDK/platform default, file and credential ownership; declarations do not resolve them.

| Variable | Processes | Type | Default | Constraints | Notes |
| --- | --- | --- | --- | --- | --- |
| `APPDATA` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Windows Google application-default credential directory. Resolution owner: host; pinned source: `golang.org/x/oauth2@v0.37.0/google/default.go:wellKnownFile`. Native parameter: `windows_application_data`. Control characters are rejected. |
| `AWS_ACCESS_KEY_ID` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native AWS access-key identity; supports the legacy AWS_ACCESS_KEY fallback. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Fallbacks: AWS_ACCESS_KEY. Native parameter: `access_key_id`. |
| `AWS_ACCOUNT_ID` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Account identity attached to native environment credentials. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `account_id`. |
| `AWS_ACCOUNT_ID_ENDPOINT_MODE` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `preferred`, `required`, `disabled` | Native account endpoint selection: preferred, required or disabled (case-sensitive). Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Choices are case-sensitive. Native parameter: `account_id_endpoint_mode`. |
| `AWS_AUTH_SCHEME_PREFERENCE` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; items <= 256 | Ordered comma-separated native authentication scheme preference. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `auth_scheme_preference`. Syntax: `auth-schemes`. Control characters are rejected. Item bytes <= 4096. |
| `AWS_CA_BUNDLE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native custom TLS trust-bundle file reference. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `ca_bundle`. Control characters are rejected. |
| `AWS_CONFIG_FILE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native shared AWS configuration file reference. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `config_file`. Control characters are rejected. |
| `AWS_CONTAINER_AUTHORIZATION_TOKEN` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Credential-endpoint authorization header value. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `container_authorization_token`. Control characters are rejected. |
| `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native AWS credential/default resolver input; resolution follows validation. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/resolve_credentials.go:resolveHTTPCredProvider`. Native parameter: `container_authorization_token_file`. Control characters are rejected. |
| `AWS_CONTAINER_CREDENTIALS_FULL_URI` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-identity | Explicit native container credential endpoint. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `container_credentials_full_uri`. Control characters are rejected. Allowed HTTP prefix: `127.0.0.0/8`. Allowed HTTP prefix: `::1/128`. Allowed HTTP prefix: `169.254.170.2/32`. Allowed HTTP prefix: `169.254.170.23/32`. Allowed HTTP prefix: `fd00:ec2::23/128`. |
| `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Relative native container credential path. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `container_credentials_relative_uri`. Syntax: `relative-credential-uri`. |
| `AWS_DEFAULTS_MODE` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `legacy`, `standard`, `in-region`, `cross-region`, `mobile`, `auto` | Native SDK default-setting profile. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `defaults_mode`. |
| `AWS_DISABLE_REQUEST_COMPRESSION` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native request-compression switch. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `disable_request_compression`. |
| `AWS_EC2_METADATA_DISABLED` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native EC2 metadata credential-discovery switch. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `ec2_metadata_disabled`. |
| `AWS_EC2_METADATA_SERVICE_ENDPOINT` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-identity | Native EC2 metadata endpoint override. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `ec2_metadata_service_endpoint`. Control characters are rejected. |
| `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `IPv4`, `IPv6` | Native EC2 metadata address family: IPv4 or IPv6. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `ec2_metadata_service_endpoint_mode`. |
| `AWS_EC2_METADATA_V1_DISABLED` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native IMDSv1 fallback switch. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `ec2_metadata_v1_disabled`. |
| `AWS_ENABLE_ENDPOINT_DISCOVERY` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `true`, `false`, `auto` | Native endpoint discovery: true, false or auto. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `enable_endpoint_discovery`. |
| `AWS_ENDPOINT_URL` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Native global service endpoint override. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `endpoint_url`. Control characters are rejected. |
| `AWS_ENDPOINT_URL_KMS` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Service-specific endpoint name computed by the native config loader from ServiceID; includes credential-chain services. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/service/kms@v1.52.2/api_client.go:ServiceID`. Native parameter: `endpoint_url_kms`. Control characters are rejected. |
| `AWS_ENDPOINT_URL_SIGNIN` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Service-specific endpoint name computed by the native config loader from ServiceID; includes credential-chain services. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/service/signin@v1.1.1/api_client.go:ServiceID`. Native parameter: `endpoint_url_signin`. Control characters are rejected. |
| `AWS_ENDPOINT_URL_SSO` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Service-specific endpoint name computed by the native config loader from ServiceID; includes credential-chain services. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/service/sso@v1.30.19/api_client.go:ServiceID`. Native parameter: `endpoint_url_sso`. Control characters are rejected. |
| `AWS_ENDPOINT_URL_SSO_OIDC` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Service-specific endpoint name computed by the native config loader from ServiceID; includes credential-chain services. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/service/ssooidc@v1.36.2/api_client.go:ServiceID`. Native parameter: `endpoint_url_ssooidc`. Control characters are rejected. |
| `AWS_ENDPOINT_URL_STS` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Service-specific endpoint name computed by the native config loader from ServiceID; includes credential-chain services. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/service/sts@v1.42.3/api_client.go:ServiceID`. Native parameter: `endpoint_url_sts`. Control characters are rejected. |
| `AWS_EXECUTION_ENV` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native AWS credential/default resolver input; resolution follows validation. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/defaultsmode.go:resolveDefaultsModeRuntimeEnvironment`. Native parameter: `execution_env`. |
| `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Ignore native endpoint overrides from environment and shared configuration. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `ignore_configured_endpoint_urls`. |
| `AWS_LOGIN_CACHE_DIRECTORY` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native AWS credential/default resolver input; resolution follows validation. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/resolve_credentials.go:resolveLoginCredentials`. Native parameter: `login_cache_directory`. Control characters are rejected. |
| `AWS_MAX_ATTEMPTS` | API | integer | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | 0..2147483647; input bytes <= 8388608 | Native retry count; zero retains the SDK's default selection. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `max_attempts`. |
| `AWS_PROFILE` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native shared configuration profile; AWS_DEFAULT_PROFILE is its fallback. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Fallbacks: AWS_DEFAULT_PROFILE. Native parameter: `profile`. |
| `AWS_REGION` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native region; AWS_DEFAULT_REGION is its fallback, beneath the explicit signing region. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Fallbacks: AWS_DEFAULT_REGION. Native parameter: `region`. |
| `AWS_REQUEST_CHECKSUM_CALCULATION` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `when_supported`, `when_required` | Native request checksum policy. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `request_checksum_calculation`. |
| `AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES` | API | integer | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | 0..10485760; input bytes <= 8388608 | Native compression threshold, bounded to 10 MiB by the pinned SDK. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `request_min_compression_size_bytes`. |
| `AWS_RESPONSE_CHECKSUM_VALIDATION` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `when_supported`, `when_required` | Native response checksum validation policy. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `response_checksum_validation`. |
| `AWS_RESTRICT_FILE_PERMISSIONS` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `user_read_write`, `unrestricted` | Native credential-cache file permission policy. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `restrict_file_permissions`. |
| `AWS_RETRY_MODE` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `standard`, `adaptive` | Native standard or adaptive retry policy. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `retry_mode`. |
| `AWS_ROLE_ARN` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native assumed-role identity. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `role_arn`. |
| `AWS_ROLE_SESSION_NAME` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native assumed-role session label. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `role_session_name`. |
| `AWS_S3_DISABLE_EXPRESS_SESSION_AUTH` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | S3 Express authentication setting read by the shared AWS config loader. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `s3_disable_express_session_auth`. |
| `AWS_S3_DISABLE_MULTIREGION_ACCESS_POINTS` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | S3 setting read even when constructing the native KMS configuration. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `s3_disable_multiregion_access_points`. |
| `AWS_S3_USE_ARN_REGION` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | S3 ARN-region setting read by the shared AWS config loader. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `s3_use_arn_region`. |
| `AWS_SDK_UA_APP_ID` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native SDK user-agent application label. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `sdk_ua_app_id`. |
| `AWS_SECRET_ACCESS_KEY` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native AWS secret access key; supports the legacy AWS_SECRET_KEY fallback. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Fallbacks: AWS_SECRET_KEY. Native parameter: `secret_access_key`. |
| `AWS_SESSION_TOKEN` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native AWS temporary-session credential. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `session_token`. Control characters are rejected. |
| `AWS_SHARED_CREDENTIALS_FILE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native shared credential file reference. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `shared_credentials_file`. Control characters are rejected. |
| `AWS_USE_DUALSTACK_ENDPOINT` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native dual-stack service endpoint switch. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `use_dualstack_endpoint`. |
| `AWS_USE_FIPS_ENDPOINT` | API | boolean | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native FIPS service endpoint switch. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `use_fips_endpoint`. |
| `AWS_WEB_IDENTITY_TOKEN_FILE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native web-identity token file reference. Resolution owner: aws; pinned source: `github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig`. Native parameter: `web_identity_token_file`. Control characters are rejected. |
| `AZURE_ADDITIONALLY_ALLOWED_TENANTS` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; items <= 256 | Semicolon-separated additional tenants accepted by the native credential. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `additionally_allowed_tenants`. Syntax: `tenants`. Control characters are rejected. Item bytes <= 4096. |
| `AZURE_AUTHORITY_HOST` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: tls-base | Native Azure identity authority URL. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `authority_host`. Control characters are rejected. |
| `AZURE_CLIENT_CERTIFICATE_PASSWORD` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native client certificate password. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `client_certificate_password`. |
| `AZURE_CLIENT_CERTIFICATE_PATH` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native client certificate/private-key file reference. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `client_certificate_path`. Control characters are rejected. |
| `AZURE_CLIENT_ID` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native client or managed-identity client identifier. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `client_id`. |
| `AZURE_CLIENT_SECRET` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native confidential-client credential. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `client_secret`. |
| `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `0`, `1`, `true`, `false` | Native certificate-chain switch: 1/true enables it; legacy other values disable it. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/environment_credential.go:NewEnvironmentCredential`. Native parameter: `client_send_certificate_chain`. |
| `AZURE_FEDERATED_TOKEN_FILE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Native workload-identity token file reference. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `federated_token_file`. Control characters are rejected. |
| `AZURE_PASSWORD` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native username/password credential password. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `password`. |
| `AZURE_REGIONAL_AUTHORITY_NAME` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native regional identity authority selection. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `regional_authority_name`. |
| `AZURE_SDK_GO_LOGGING` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `off`, `all`; production choices: unset, `off` | Native Azure SDK raw stderr logging switch. The Azure adapter clears the global listener during process initialization in all profiles; production rejects an explicit all request. Application diagnostics use structured events. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/internal@v1.12.0/log/log.go:initLogging`. Choices are case-sensitive. Native parameter: `sdk_logging`. |
| `AZURE_TENANT_ID` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native Azure credential tenant identifier. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `tenant_id`. |
| `AZURE_TOKEN_CREDENTIALS` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `dev`, `prod`, `EnvironmentCredential`, `WorkloadIdentityCredential`, `ManagedIdentityCredential`, `AzureCLICredential`, `AzureDeveloperCLICredential`, `AzurePowerShellCredential` | Native credential selection: dev/prod are case-sensitive; credential type names are case-insensitive; present empty input is invalid. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/default_azure_credential.go:NewDefaultAzureCredential`. Native parameter: `token_credentials`. Exact-case choices: `dev`, `prod`. Present empty input is rejected. |
| `AZURE_USERNAME` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native username/password credential identity. Resolution owner: azure; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go`. Native parameter: `username`. |
| `DEFAULT_IDENTITY_CLIENT_ID` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native Azure ML managed-identity client identifier. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/azure_ml.go:createAzureMLAuthRequest`. Native parameter: `default_identity_client_id`. |
| `GCE_METADATA_HOST` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Google metadata host:port override; also affects native metadata discovery. Resolution owner: google; pinned source: `cloud.google.com/go/compute/metadata@v0.9.0/metadata.go:OnGCE`. Native parameter: `metadata_host`. Syntax: `metadata-host`. |
| `GOOGLE_APPLICATION_CREDENTIALS` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Explicit Google application-default credential file reference. Resolution owner: google; pinned source: `golang.org/x/oauth2@v0.37.0/google/default.go:FindDefaultCredentialsWithParams`. Native parameter: `credentials_file`. Control characters are rejected. |
| `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES` | API | choice | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; choices: `0`, `1` | Native external-account executable opt-in: only 1 enables execution; capture never executes it. Resolution owner: google; pinned source: `golang.org/x/oauth2@v0.37.0/google/externalaccount/executablecredsource.go:getTokenFromExecutableCommand`. Native parameter: `allow_executables`. |
| `HOME` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Unix home input used by native AWS/Google credential-file defaults. Resolution owner: host; pinned source: `go@1.26.9/src/os/file.go:UserHomeDir`. Native parameter: `unix_home`. Control characters are rejected. |
| `HTTPS_PROXY` | API, worker, online CLI, parser replay, reconciliation | url (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-proxy | Go HTTP transport setting; first nonempty uppercase value takes precedence over its lowercase fallback. Resolution owner: host; pinned source: `go@1.26.9/src/vendor/golang.org/x/net/http/httpproxy/proxy.go:FromEnvironment`. Fallbacks: https_proxy. Native parameter: `HTTPS_PROXY`. Control characters are rejected. |
| `HTTP_PROXY` | API, worker, online CLI, parser replay, reconciliation | url (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-proxy | Go HTTP transport setting; first nonempty uppercase value takes precedence over its lowercase fallback. Resolution owner: host; pinned source: `go@1.26.9/src/vendor/golang.org/x/net/http/httpproxy/proxy.go:FromEnvironment`. Fallbacks: http_proxy. Native parameter: `HTTP_PROXY`. Control characters are rejected. |
| `IDENTITY_ENDPOINT` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-identity | Native Azure managed-identity endpoint selected by MSAL. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource`. Native parameter: `identity_endpoint`. Control characters are rejected. |
| `IDENTITY_HEADER` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native managed-identity authorization header value. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource`. Native parameter: `identity_header`. Control characters are rejected. |
| `IDENTITY_SERVER_THUMBPRINT` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native managed-identity server certificate thumbprint. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource`. Native parameter: `identity_server_thumbprint`. |
| `IMDS_ENDPOINT` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-identity | Native Azure Arc metadata endpoint selection. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource`. Native parameter: `imds_endpoint`. Control characters are rejected. |
| `MSI_ENDPOINT` | API | url | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; endpoint policy: native-identity | Native legacy managed-identity endpoint. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource`. Native parameter: `msi_endpoint`. Control characters are rejected. |
| `MSI_SECRET` | API | text (secret) | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Native legacy managed-identity authorization secret. Resolution owner: azure; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource`. Native parameter: `msi_secret`. Control characters are rejected. |
| `NO_PROXY` | API, worker, online CLI, parser replay, reconciliation | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; items <= 256 | Go HTTP transport setting; first nonempty uppercase value takes precedence over its lowercase fallback. Resolution owner: host; pinned source: `go@1.26.9/src/vendor/golang.org/x/net/http/httpproxy/proxy.go:FromEnvironment`. Fallbacks: no_proxy. Native parameter: `NO_PROXY`. Syntax: `no-proxy`. Control characters are rejected. Item bytes <= 4096. |
| `NoDefaultCurrentDirectoryInExePath` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | Windows executable lookup skips the current directory when this input is present, including when its value is empty; consumers must check Present rather than HasValue. Resolution owner: host; pinned source: `go@1.26.9/src/os/exec/lp_windows.go:lookPathExts`. Native parameter: `windows_skip_current_directory`. |
| `OS` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 256 | Windows operating-system label read by Azure SDK telemetry initialization; capture does not retroactively freeze SDK initialization. The Azure adapter disables SDK telemetry for default credentials it constructs; injected credentials and external tools retain their own policies. Resolution owner: host; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.21.1/runtime/policy_telemetry.go:platformInfo`. Native parameter: `windows_sdk_operating_system`. Control characters are rejected. |
| `PATH` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; items <= 256 | Native external credential helper search path; capture never executes a helper. Resolution owner: host; pinned source: `go@1.26.9/src/os/exec/lp_unix.go:lookPath`. Native parameter: `executable_search_path`. Syntax: `path-list`. Control characters are rejected. Item bytes <= 4096. |
| `PATHEXT` | API | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; items <= 256 | Semicolon-separated Windows executable suffixes; normalize case and optional leading dots, skip empty items, and apply no native defaults during input parsing. Resolution owner: host; pinned source: `go@1.26.9/src/os/exec/lp_windows.go:lookPathExts`. Native parameter: `windows_executable_extensions`. Syntax: `windows-executable-extensions`. Control characters are rejected. Item bytes <= 4096. |
| `PGAPPNAME` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native PostgreSQL application name. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `application_name`. |
| `PGCONNECT_TIMEOUT` | API, worker, migration, parser replay, reconciliation | seconds | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | 0..9223372036 seconds; input bytes <= 8388608 | Native connection timeout in seconds. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `connect_timeout`. |
| `PGDATABASE` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native database name. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `database`. |
| `PGHOST` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; items <= 16 | Native comma-separated PostgreSQL hosts or Unix socket directories. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `host`. Syntax: `postgres-hosts`. Control characters are rejected. Item bytes <= 4096. |
| `PGMAXPROTOCOLVERSION` | API, worker, migration, parser replay, reconciliation | choice | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; choices: unset, `3.0`, `3.2`, `latest` | Native maximum PostgreSQL protocol version. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Choices are case-sensitive. Native parameter: `max_protocol_version`. |
| `PGMINPROTOCOLVERSION` | API, worker, migration, parser replay, reconciliation | choice | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; choices: unset, `3.0`, `3.2`, `latest` | Native minimum PostgreSQL protocol version. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Choices are case-sensitive. Native parameter: `min_protocol_version`. |
| `PGOPTIONS` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native PostgreSQL startup options. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `options`. |
| `PGPASSFILE` | API, worker, migration, parser replay, reconciliation | path | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 4096 | Native password-file reference; capture never opens it. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `passfile`. Control characters are rejected. |
| `PGPASSWORD` | API, worker, migration, parser replay, reconciliation | text (secret) | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native database password; never diagnostic output. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `password`. |
| `PGPORT` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; items <= 16 | Native comma-separated PostgreSQL ports. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `port`. Syntax: `postgres-ports`. Item bytes <= 4096. |
| `PGSERVICE` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native service-file section name; resolution is a separate boundary. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `service`. |
| `PGSERVICEFILE` | API, worker, migration, parser replay, reconciliation | path | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 4096 | Native service-file reference; capture never opens it. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `servicefile`. Control characters are rejected. |
| `PGSSLCERT` | API, worker, migration, parser replay, reconciliation | path | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 4096 | Native client certificate file reference; capture never opens it. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `sslcert`. Control characters are rejected. |
| `PGSSLKEY` | API, worker, migration, parser replay, reconciliation | path | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 4096 | Native client private-key file reference; capture never opens it. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `sslkey`. Control characters are rejected. |
| `PGSSLMODE` | API, worker, migration, parser replay, reconciliation | choice | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; choices: unset, `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full` | Native PostgreSQL TLS mode; values are case-sensitive. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Choices are case-sensitive. Native parameter: `sslmode`. |
| `PGSSLNEGOTIATION` | API, worker, migration, parser replay, reconciliation | choice | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; choices: unset, `postgres`, `direct` | Native PostgreSQL TLS negotiation mode. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Choices are case-sensitive. Native parameter: `sslnegotiation`. |
| `PGSSLPASSWORD` | API, worker, migration, parser replay, reconciliation | text (secret) | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native client-key password; never diagnostic output. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `sslpassword`. |
| `PGSSLROOTCERT` | API, worker, migration, parser replay, reconciliation | path | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 4096 | Native TLS trust-root file reference; capture never opens it. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `sslrootcert`. Control characters are rejected. |
| `PGSSLSNI` | API, worker, migration, parser replay, reconciliation | choice | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; choices: unset, `0`, `1` | Native TLS server-name-indication control, 0 or 1. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Choices are case-sensitive. Native parameter: `sslsni`. |
| `PGTARGETSESSIONATTRS` | API, worker, migration, parser replay, reconciliation | choice | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608; choices: `any`, `read-write`, `read-only`, `primary`, `standby`, `prefer-standby` | Native target-session selection policy. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Choices are case-sensitive. Native parameter: `target_session_attrs`. |
| `PGTZ` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native PostgreSQL timezone setting. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `timezone`. |
| `PGUSER` | API, worker, migration, parser replay, reconciliation | text | unset; Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate. | input bytes <= 8388608 | Native database user. Resolution owner: postgres; pinned source: `github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings`. Native parameter: `user`. |
| `ProgramData` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Windows Azure Arc managed-identity filesystem base. Resolution owner: host; pinned source: `github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:getAzureArcPlatformPath`. Native parameter: `windows_program_data`. Control characters are rejected. |
| `REQUEST_METHOD` | API, worker, online CLI, parser replay, reconciliation | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608 | A nonempty value enables the Go transport's CGI proxy restrictions. Resolution owner: host; pinned source: `go@1.26.9/src/vendor/golang.org/x/net/http/httpproxy/proxy.go:FromEnvironment`. Native parameter: `cgi`. |
| `SSL_CERT_DIR` | API, worker, migration, online CLI, parser replay, reconciliation | text | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 8388608; items <= 256 | Colon-separated Unix system TLS trust-directory override. Resolution owner: host; pinned source: `go@1.26.9/src/crypto/x509/root_unix.go:loadSystemRoots`. Native parameter: `system_certificate_directories`. Syntax: `certificate-directories`. Control characters are rejected. Item bytes <= 4096. |
| `SSL_CERT_FILE` | API, worker, migration, online CLI, parser replay, reconciliation | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Unix system TLS trust-file override; resolution has a separate file owner. Resolution owner: host; pinned source: `go@1.26.9/src/crypto/x509/root_unix.go:loadSystemRoots`. Native parameter: `system_certificate_file`. Control characters are rejected. |
| `SYSTEMROOT` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Windows system directory used by native developer credentials. Resolution owner: host; pinned source: `github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/developer_credential_util_windows.go:buildCmd`. Native parameter: `windows_system_root`. Control characters are rejected. |
| `USERPROFILE` | API | path | unset; Optional native input; native defaults, fallback precedence and external resolution are separately owned. | input bytes <= 4096 | Windows home input used by native AWS credential-file defaults. Resolution owner: host; pinned source: `go@1.26.9/src/os/file.go:UserHomeDir`. Native parameter: `windows_home`. Control characters are rejected. |
<!-- END EVYDENCE GENERATED CONFIGURATION -->

`EVYDENCE_AWS_REGION` takes precedence over its native `AWS_REGION` fallback.
Parser depth, string and item limits remain separately enforced when the worker
object-byte budget is changed.

## Private Secret Files

The generated rows name each supported project `_FILE` alternative. Set a clean
absolute path and leave its inline variable and aliases unset or empty. A
nonempty inline value, including whitespace, conflicts with a selected file.
An empty file variable remains unset. Applicable inactive references still
receive path and conflict validation, but only the configured feature's active
files are opened.

Use nonempty regular files with private POSIX permissions, such as `0600`,
`0640` or `0440`: execute, group-write and all other-user bits are rejected.
The configured parent directory is operator-owned. Symlink projections must
resolve inside that parent. Each file has the schema field's byte bound, and
materialized files share an 8 MiB budget. These private-file checks fail closed
on platforms without the supported POSIX policy.

The captured configuration is completely validated after active files are
materialized and before providers, storage or listeners start. Object-store
credential files apply only to S3/MinIO; gateway token files apply only to active
gateway features. Native database and cloud credential files keep their SDK's
resolution and permissions policy, as identified in the native table above.
Evydence does not add a network secret fetcher. Use your deployment's secret
manager to project files or supply inline values, then restart to rotate them.

## Live-Test Settings

These variables belong to test infrastructure rather than process startup. Use
`.test.env.example` and the [release validation reference](release-validation.md)
for disposable service setup. They are intentionally outside the runtime schema.

| Variable | Required | Default / Example | Notes |
| --- | --- | --- | --- |
| `EVYDENCE_TEST_DATABASE_URL` | Live tests | `.test.env.example` value | Used by `make live-postgres-check`, `make postgres-integration-test`, `make fault-injection-check`, `make integration-check`, and `make release-check`. `make integration-check` rejects `ENV=production` and a value equal to `EVYDENCE_DATABASE_URL`. |
| `EVYDENCE_TEST_S3_ENDPOINT` | Live MinIO tests | `127.0.0.1:9000` | Required by `make integration-check` and therefore `make production-check`. The integration gate permits only a loopback MinIO endpoint and rejects a value equal to `EVYDENCE_S3_ENDPOINT`. |
| `EVYDENCE_TEST_S3_ACCESS_KEY_ID` | Live MinIO tests | `.test.env.example` value | Test-only credential for the disposable MinIO service. Never point it at a production or shared object-store account. |
| `EVYDENCE_TEST_S3_SECRET_ACCESS_KEY` | Live MinIO tests | `.test.env.example` value | Test-only secret for the disposable MinIO service. The integration summary redacts credentials. Never commit a real value. |
| `EVYDENCE_TEST_S3_USE_SSL` | Live MinIO tests | `false` | Boolean transport setting for the loopback test service. |

## SSO Session Lifecycle (Unreleased)

SSO credentials use 32 bytes from `crypto/rand`, encoded as unpadded URL-safe
base64 after `evysso_` (50 characters total). Lookup prefixes are 12 characters;
only the lowercase 64-character HMAC-SHA-256 hash, keyed by
`EVYDENCE_API_KEY_PEPPER`, is persisted. Issuance returns the secret only after
the session/audit transaction succeeds. Completed creation replay returns the
original public metadata without a secret.

The API validates the two policy variables before opening runtime adapters.
Each new `sso-session.v1.1.0` record captures its maximum lifetime and idle
timeout. Explicit expiry must be future and within the configured maximum.
Exchange without explicit expiry uses eight hours, shortened to the configured
maximum when necessary. Activity cannot extend absolute expiry or rotate a
secret. A policy change affects future issuance; revoke existing sessions when
an incident or policy change requires their immediate invalidation.

Cookie and Bearer admission apply the same exclusive expiry and idle deadlines.
They require an active user and provider, unchanged credential coordinates,
and current identity/grants. The transaction locks the selected session and
identity/grant rows, checks time after acquiring those locks, and advances
`last_used_at` monotonically. Failed admission checks roll back activity.
Issuance and admission also check lifecycle after commit before returning a
secret or actor. If a delayed commit crosses a deadline, the result is withheld;
committed history remains, and the now-inactive credential is not renewed.
Revocation and admission serialize on the session row; an admission
committed before revocation may finish its request, while later admissions fail.

Migration `20261012000100_sso_session_lifecycle` adds activity and bounded-policy
columns without replacing hashes, owners, groups, expiry or creation timestamps.
Older rows retain their schema labels and use the bounded defaults. Missing
activity means creation time, so an upgrade does not revive an idle session;
older idle or over-lifetime sessions require fresh authentication. Older safe
replay receipts may omit the new policy/activity fields. Stop old API writers
during rollout: an older binary does not enforce these new admission rules.
Plan for the migration's DDL lock. Its downgrade refuses to discard recorded
activity or tightened policy; retain the columns and use a forward fix instead.

There is no sliding absolute expiry or refresh-token endpoint. Use fresh
configured SSO exchange or authorized administrative issuance and revoke the
prior session as described in [Key rotation](../runbooks/key-rotation.md).
OIDC exchange now requires server-owned state/nonce binding and durable
single-use consumption; use the [login contract](../api.md#sso-credential-exchange)
and [rollout notes](upgrade-compatibility-policy.md#oidc-login-binding-rollout).
Its five-minute lifetime and 64 retained requests per provider are fixed
application bounds, not environment knobs. SAML recipient/NameID settings are
tenant-owned provider bindings configured through the [SAML login API](../api.md#saml-binding-and-login-requests-unreleased), rather than environment variables.
SAML uses its own bounded requests, signed assertion profile and state cookie.
Standalone SAML receipts require API-delivered request context and consume
proof without session issuance. The full local EVY-1010 production gate passed
on 2026-10-15. Authentication and portal failure limits are described below.

## First-Tenant Bootstrap

With `EVYDENCE_RUNTIME_PROFILE=postgres`, API startup composes focused Identity
and Verification bootstrap commands without loading the Ledger aggregate. A
single startup transaction locks the `tenants` table in
`SHARE ROW EXCLUSIVE` mode and checks existence with `SELECT EXISTS`; it does
not select tenant names, credential inventories, or signing keys. If any tenant
exists, bootstrap returns no identity or secret and creates nothing. The table
lock covers an empty installation and conflicts with ordinary tenant inserts,
so concurrent first-start attempts cannot each create an administrator. The
API bounds this transaction, including lock wait, to 30 seconds or the earlier
shutdown deadline. The lock can briefly delay unrelated tenant mutations; this
does not change the supported single-API-writer deployment profile.

On an empty installation, tenant, initial wildcard API-key hash, the
`tenant.created` system audit entry, and the initial local Ed25519 signing key
commit together. Write, cancellation, and commit failures return no bootstrap
identity or secret. The initial signing key retains the existing local storage
format; its creation is not external signing-provider custody or a new
encryption-at-rest guarantee. Generated transient private-key byte buffers are
cleared after use. Go credential strings are not guaranteed to be erased from
process memory.

Set `EVYDENCE_BOOTSTRAP_DISABLED=true` to bypass startup bootstrap. Local and
production runtime bootstrap both use the database transaction. Bootstrap names are bounded
at 65,536 raw bytes; scopes at 1024 entries of at most 128 bytes each. Text must
be valid UTF-8 without NUL bytes. These checks reject malformed operator inputs
before credential generation.

Neither bootstrap path logs secrets or stored hashes. Only the explicit,
non-production `EVYDENCE_PRINT_BOOTSTRAP_SECRET=true` option writes the existing
`tenant_id`, `api_key`, and `secret` JSON response. Durable bootstrap emits that
response immediately after commit, before later native server startup work;
restarts never reissue it. Output failure is reported with a safe error but
cannot undo an already committed bootstrap. Retain the one-time local output
securely; otherwise operator credential provisioning/recovery is required.
The PostgreSQL API binds `NewNativeServerWithOptionsContext`, which requires
the complete command/query/authentication surface, streamed and historical
durable replay capabilities, and a stable pagination secret of at least 16
bytes. Missing or typed-nil dependencies fail startup instead of enabling a
local fallback. API startup no longer constructs or accepts Ledger and does not
use `app.Config`. Legacy library/test utilities still await physical deletion
under EVY-906; they are not runtime backend options.
Ledger-accepting HTTP constructors and their aggregate replay binders are no
longer compiled into production transport. The remaining local HTTP setup is
explicitly test-only; legacy handler and aggregate deletion remain unfinished.
API routes and response schemas are unchanged. This is an API composition
boundary, not proof that EVY-905's full validation gates are complete. The worker
daemon uses a closed native processor as described in the
[worker outbox contract](worker-outbox.md); local-memory mode is not a worker
profile.

## Retired Local-Memory Profile (Unreleased)

Current source no longer runs the non-durable `local_memory` API. This is an
unreleased runtime-configuration change, not a claim that older published
release binaries changed. Configure `EVYDENCE_RUNTIME_PROFILE=postgres` and
`EVYDENCE_DATABASE_URL`; `.api.env.example` already supplies that shape.
Start the local database with `docker compose up -d postgres` or provide your
own PostgreSQL service, then follow [Install and operate](../how-to/install-and-operate.md).

Previously in-process metadata has no automatic migration because it was lost
on exit. Existing filesystem payload bytes are not deleted or automatically
imported by this change. Do not treat orphaned payload files as trusted evidence.
Fast unit tests can continue using in-memory fakes. The local CI simulation now
requires `EVYDENCE_TEST_DATABASE_URL` and creates and removes only its own fresh
schema; it does not reset the supplied database.
Supply a `postgres://` or `postgresql://` URI without an `options` query
parameter: the simulation owns its connection search path and rejects startup
options that could override schema isolation before issuing database commands.

## Request-Body Limits

The application constants in `internal/app/payload_limits.go` are the single
source of truth for request-body limits. HTTP handlers import those constants;
do not create separate proxy-specific limits in application configuration.

| Request class | Effective application limit | Current API behavior |
|---|---:|---|
| Small JSON commands, credentials, and administrative requests | 65,536 bytes | Buffered only within this small bound. This includes JSON evidence envelopes. |
| Native SBOM, OpenVEX, OpenAPI, and vulnerability-scan documents | 20 MiB (20,971,520 bytes) | Native streaming paths hash and spool the request to a private temporary file before validation and object-store staging. `POST /v1/vulnerability-scans` streams `application/json`; `POST /v1/sboms`, `POST /v1/vex`, and `POST /v1/openapi-contracts` also accept their documented native media types with required `X-Evydence-*` metadata headers. |
| Evidence archive transport budget | 128 MiB (134,217,728 bytes) | Reserved for archive transport. Current evidence-bundle import is a small JSON manifest rather than a raw archive-upload endpoint. |
| Report-template creation | 1 MiB (1,048,576 bytes) | Enforced both by the HTTP handler and application service. |

Configure a reverse proxy, ingress, or WAF with route-specific limits at least
as large as the corresponding application limit. In particular, the native
document routes must allow 20 MiB plus ordinary HTTP framing, while credential
and administrative routes should remain at the 64 KiB small-JSON limit. A
proxy limit lower than the table will reject a valid request before Evydence
can return its RFC 9457 problem response; a higher proxy limit does not weaken
the application limit. Keep any proxy configuration derived from this table
and review it when `payload_limits.go` changes.

## HTTP Ingress Limits And Proxy Trust

The API listener applies bounded header, request-target, request-read,
response-write, idle, and graceful-shutdown limits from the variables above.
The process rejects an invalid bound or proxy CIDR during startup rather than
silently falling back to an unbounded setting.

On `SIGINT` or `SIGTERM`, the API closes its listener and idle keep-alive
connections, then lets admitted requests finish within the shutdown budget.
Their request contexts survive the signal so a normal response and its durable
work can complete. A permanent accept failure uses the same drain path before
returning an error; it cannot trigger immediate runtime cleanup beneath an
otherwise successful active request. `http.ErrServerClosed` is normal.

At the drain deadline the API closes active connections and cancels their
request contexts, then returns an error. Handlers and storage/provider calls
must honor those contexts; a database commit already in flight may have
succeeded even if the client loses its response. Normal signal shutdown exits
zero; a serve error, unexpected root deadline, or forced drain failure exits
nonzero. Fixed lifecycle log messages report drain start, completion, or
failure without raw request or provider error details. Resource cleanup and
deployment termination grace must also be accounted for; the HTTP budget only
covers request draining.

Daemon resource cleanup has a separate configurable budget, defaulting to five
seconds. It waits for command and package-read borrowers, closes process-owned
provider clients and S3/MinIO transports, releases the API writer lease, then
closes the PostgreSQL pools. All stages, including nested provider cleanup, share
one deadline. A cleanup failure stops later stages, reports failure and requires
process exit. A database wait timeout therefore retains the lease until exit;
it cannot admit another writer beneath unfinished database work. Startup failure
uses a live cleanup context even if startup was canceled. Forced request/job
drain skips resource cleanup and exits with its resources still owned.

Supplied provider/object ports, custom HTTP transports, token sources and
credentials remain borrowed unless the process explicitly transfers cleanup.
Standard HTTP transports are cloned and the clone is owned. AWS signing created
by the process owns its SDK HTTP transport; an injected SDK client stays borrowed.
SDK-managed shared credential transports are not closed by Evydence. There is no
separate telemetry exporter resource in the current runtime. The API factory
registers its own clients before runtime startup, so partial startup cleans those
clients once. Operator commands retain the default five-second cleanup budget.

Evydence does not accept compressed or multipart request bodies. Only an absent
or `identity` `Content-Encoding` is accepted, so the ingress limit and the
route parser count the same bytes. Multipart is rejected because no public
route accepts multipart parts; native documents use their documented raw media
types and metadata headers. The ingress ceiling is the 20 MiB native-document
limit in `internal/app/payload_limits.go`; individual routes keep their tighter
small-JSON or report-template limits.

Set `EVYDENCE_TRUSTED_PROXY_CIDRS` only for addresses controlled by the
deployment. A trusted proxy must append and sanitize `X-Forwarded-For` before
forwarding requests. Evydence walks the rightmost trusted proxy hops to the
first untrusted address, and ignores `X-Forwarded-For` entirely when the direct
peer is not trusted. It does not treat `Forwarded` or `X-Real-IP` as a client
identity source. This process-local limiter remains a safety boundary, not a
substitute for TLS termination, edge DDoS controls, or a shared distributed
rate limiter when multiple API processes are introduced.

## Authentication And Portal Failure Limits (Unreleased)

`EVYDENCE_AUTH_FAILURES_PER_MINUTE` limits failed work separately for credential
authentication, public OIDC/SAML initiation and exchange, and token-based portal
JSON/form access and downloads. These limits remain active when the general
request limit is zero. Helm exposes `api.authenticationFailuresPerMinute`;
production-like Compose passes the same environment variable.

Each trusted client and class has a budget in a fixed UTC calendar minute.
Admission reserves a slot before verification or protected effects. Successful
completion releases that slot without erasing earlier failures. Every failed
SSO/portal handler response consumes a slot, including malformed input and
server errors. Credential failures include invalid/missing/ambiguous credentials
and unsafe cookie origins; downstream authorization and expensive-tenant quota
denials after successful authentication do not consume credential failures.
Concurrent work counts toward the budget, so a burst can receive `429` while
earlier requests are still running. Size the configured budget for expected
concurrency; do not rely on credential switching to select a fresh bucket.

Keys use a random process-private HMAC over the class and the existing trusted
client identity. Credentials, account names, provider subjects, raw client IPs,
and tenant identifiers are not retained in limiter keys or added to logs.
Clients sharing an address share an allowance. Untrusted forwarding headers
cannot select another client; the trusted-proxy rules above remain authoritative.
Failure-state capacity is shared across client/class keys. At capacity, new
keys receive `429` until a new minute releases capacity, including a new class
for a client already tracked in another class. Active histories are never evicted
to admit another key.

Limit responses use generic Problem Details, `Retry-After`, and `no-store`,
without setting credentials or exposing account existence.
SSO exchange identity/proof/permission denials use generic `401`; administrative
verification receipts keep their separate contract. Public system
metadata and the portal review form remain available. These counters are
bounded process-local state: restart clears them, and they do not claim a shared
multi-process quota. Keep the supported single API writer and external ingress
controls. The full local EVY-1011 production gate passed on 2026-10-15; this
does not establish a distributed quota or external identity-provider verification.

## Production Rejection Checks

When `ENV=production`, the API refuses to start unless:

- `EVYDENCE_RUNTIME_PROFILE=postgres` is set.
- `EVYDENCE_DATABASE_URL` is set.
- `EVYDENCE_API_KEY_PEPPER` is non-empty and not the local default.
- `EVYDENCE_SIGNING_KEY_MODE` is `external`, `aws-kms`, `gcp-kms`,
  `azure-key-vault`, or `pkcs11-hsm`. `external` and `pkcs11-hsm` require
  `EVYDENCE_SIGNING_EXECUTOR_URL`; `gcp-kms` uses Google Application Default
  Credentials and `azure-key-vault` uses Azure DefaultAzureCredential.
- `EVYDENCE_PRINT_BOOTSTRAP_SECRET` is not `true`.
- `EVYDENCE_POSTGRES_LOAD_MODE`, when set, is `relational_only`.
- `EVYDENCE_API_WRITER_MODE`, when set, is `single` or `single-writer`.
- `EVYDENCE_API_WRITER_REPLICAS`, when set, is `1`.
- Any `EVYDENCE_*_ALLOW_INSECURE_LOCALHOST` outbound-provider override is not
  `true`. This includes OIDC discovery/UserInfo, provider-validation,
  signing-executor, and transparency gateway/fetch settings.

## Outbound Provider Destination Policy

The OIDC discovery/UserInfo, provider-validation gateway, signing gateway, and
transparency HTTP adapters use one outbound policy. By default they require an
HTTPS destination whose resolved address is public; loopback, private,
link-local (including metadata-service), multicast, unspecified, carrier-grade
NAT, and documentation/reserved IPv4 addresses are rejected. The client
resolves and validates each dial target and dials that checked address, so a
later DNS answer cannot silently redirect the connection.

Ambient `HTTP_PROXY`/`HTTPS_PROXY` configuration is not used for these adapter
calls. Redirects are denied rather than followed, so a gateway bearer token
cannot cross an origin. Gateway profiles allow only their configured endpoint
host. OIDC discovery and UserInfo are pinned to the configured issuer origin;
a discovered different-host or different-scheme endpoint fails closed. Each
adapter has a finite timeout and response-body budget.

The `*_ALLOW_INSECURE_LOCALHOST` variables are narrowly for local development
and test loopback endpoints. They do not allow arbitrary private hosts, are
rejected when `ENV=production`, and are not a production proxy or egress-policy
mechanism. Operators who require a corporate proxy or a private provider cannot
use this direct-adapter profile unchanged; they need a separately reviewed
deployment/code change with explicit egress and IAM controls. This runtime
deliberately does not silently inherit an ambient proxy.

## Build Identity

`make build-api` injects API identity through linker flags. CI and release
packaging may set `BUILD_VERSION`, `BUILD_COMMIT`, `BUILD_TIME`, `BUILD_DIRTY`,
`BUILD_GO_VERSION`, and `BUILD_RELEASE_MANIFEST_DIGEST`; none may contain
secrets. Docker accepts corresponding `EVYDENCE_BUILD_*` build arguments.

The release-candidate package script writes a deterministic pre-build release
input manifest from the tag, commit, OpenAPI file, and migrations, injects its
SHA-256 digest into `evydence-api`, and includes that manifest in the final
signed release set. The field is intentionally not the digest of the final
manifest, because a final manifest that covers the binary cannot recursively be
embedded in that same binary.

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

## Sigstore/Cosign Offline Verification

The Cosign route is enabled only when operator configuration supplies a
versioned Sigstore trusted root or public key. It verifies self-contained,
stored bundles offline and requires an embedded Rekor inclusion proof. The
configuration is read only at process startup; it does not fetch trust roots or
Rekor material over the network. A request that requires online verification
does not fall back to this profile. Verification receipts record the configured
version and library version, never trust-root bytes, certificates, bundle bytes,
or private keys.

For keyless bundles, callers must supply exact expected identity and issuer
values. For key bundles, callers select `mode: "key"` and the configured public
key supplies the trust boundary. Operators remain responsible for trust-root
rotation, revocation policy, and deciding whether the offline profile fits
their deployment requirements.

## Signing Executors

Signing operations always use a configured executor; the public API rejects
caller-supplied signatures. Evydence sends a canonical JSON request containing
tenant id, provider id/type, key reference, subject type/id, `payload_hash`,
request id, nonce, and canonical-request hash. The gateway returns a signature
and safe provider receipt identifiers. Evydence does not store production
private key material or send raw evidence payload bytes.

`EVYDENCE_SIGNING_KEY_MODE=gcp-kms` uses the Google Application Default
Credentials chain and `azure-key-vault` uses Azure DefaultAzureCredential. If
direct credentials are unavailable, select
`EVYDENCE_SIGNING_KEY_MODE=external` and configure the HTTPS signing gateway.
Native cloud modes do not silently fall back to a gateway when credentials
are missing, even if `EVYDENCE_SIGNING_EXECUTOR_URL` is also configured.
`pkcs11-hsm` always uses the HTTPS signing gateway because native HSM modules
and slots are deployment-specific. Operators remain responsible for provider
credentials, IAM, key lifecycle, gateway operation where used, and custody
review.

Tenant signing-provider records also accept `native_pkcs11_hsm` for deployments
that operate local PKCS#11 modules or slots outside Evydence. The provider
`key_ref` must be a `pkcs11:` URI and must not embed PIN values, PIN sources,
passwords, or secrets. This profile records custody evidence for review through
`GET /v1/reports/custody-review`; it does not load native HSM modules or prove
hardware custody by itself.

When `EVYDENCE_SIGNING_KEY_MODE=aws-kms`, Evydence uses AWS KMS `Sign` and
`Verify` against `EVYDENCE_AWS_KMS_KEY_ID`. The executor signs and verifies
the decoded SHA-256 canonical-request digest with KMS `MessageType=DIGEST`; it
does not send raw evidence payload bytes to AWS KMS. Operators remain
responsible for AWS IAM policy, key lifecycle, CloudTrail review, regional
availability, and external review of whether the selected key custody profile
satisfies their deployment needs.

When `EVYDENCE_SIGNING_KEY_MODE=gcp-kms`, Evydence calls GCP Cloud KMS
`asymmetricSign` with an Application Default Credentials access token and a
key-version resource name. It fetches the provider public key and verifies the
returned signature over the SHA-256 canonical-request digest. The executor
does not send raw evidence payload bytes. Operators remain responsible for GCP
IAM, audit logs, key lifecycle, and regional availability.

When `EVYDENCE_SIGNING_KEY_MODE=azure-key-vault`, Evydence calls Azure Key
Vault `sign` using DefaultAzureCredential, a key name/version, and `ES256`. It
fetches the provider public key and verifies the returned signature over the
SHA-256 canonical-request digest. The executor does not send raw evidence
payload bytes. Operators remain responsible for Azure identity, Key Vault
access policy/RBAC, audit logs, key lifecycle, and regional availability.

If a signing provider is temporarily unavailable, Evydence returns a retryable
service-unavailable response and releases the request's idempotency reservation
without persisting a signing operation or signature. Retrying the same
idempotency key can then create at most one persisted signing receipt after a
successful provider response. Providers that do not expose a request-level
idempotency primitive can still produce an unobserved external signature after
a network timeout; use the HTTPS gateway where provider-side deduplication is
required.

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
