package config

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// projectInput owns all mutable data and supplies no defaults. The schema
// evaluator is the single owner of input requirements, bounds and defaults.
func projectInput(input parsedInput) Configuration {
	return Configuration{
		role: input.role, production: input.production,
		runtime:   projectRuntime(input),
		api:       projectAPI(input),
		worker:    projectWorker(input),
		storage:   projectStorage(input),
		providers: projectProvider(input),
		cli:       projectCLI(input),
		native:    projectNative(input.native),
		database:  cloneDatabaseInput(input.database),
	}
}

func cloneDatabaseInput(input databaseInput) databaseInput {
	return databaseInput{
		native:       databaseSettings{values: maps.Clone(input.native.values)},
		explicit:     databaseSettings{values: maps.Clone(input.explicit.values)},
		candidate:    databaseSettings{values: maps.Clone(input.candidate.values)},
		needsService: input.needsService,
	}
}

func projectRuntime(input parsedInput) RuntimeSettings {
	v := input.values
	return RuntimeSettings{
		Environment:               v["ENV"].text,
		ConfigurationRevision:     strings.TrimSpace(v["EVYDENCE_CONFIGURATION_REVISION"].text),
		ConfigurationRevisionFile: v["EVYDENCE_CONFIGURATION_REVISION_FILE"].text,
		DatabaseURL:               Secret{value: strings.TrimSpace(v["EVYDENCE_DATABASE_URL"].text)},
		LogFormat:                 v["EVYDENCE_LOG_FORMAT"].text,
		LogLevel:                  v["EVYDENCE_LOG_LEVEL"].text,
		MigrationsDir:             strings.TrimSpace(v["EVYDENCE_MIGRATIONS_DIR"].text),
		PostgresLoadMode:          v["EVYDENCE_POSTGRES_LOAD_MODE"].text,
		Profile:                   v["EVYDENCE_RUNTIME_PROFILE"].text,
		ShutdownCleanupTimeout:    v["EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS"].duration,
		SkipMigrations:            v["EVYDENCE_SKIP_MIGRATIONS"].boolean,
	}
}

func projectAPI(input parsedInput) APISettings {
	v := input.values
	return APISettings{
		Address:                          strings.TrimSpace(v["EVYDENCE_ADDR"].text),
		KeyPepper:                        Secret{value: strings.TrimSpace(v["EVYDENCE_API_KEY_PEPPER"].text)},
		WriterMode:                       v["EVYDENCE_API_WRITER_MODE"].text,
		WriterReplicas:                   v["EVYDENCE_API_WRITER_REPLICAS"].integer,
		AuthFailuresPerMinute:            v["EVYDENCE_AUTH_FAILURES_PER_MINUTE"].integer,
		BootstrapDisabled:                v["EVYDENCE_BOOTSTRAP_DISABLED"].boolean,
		BootstrapTenant:                  v["EVYDENCE_BOOTSTRAP_TENANT"].text,
		ExpensiveTenantRequestsPerMinute: v["EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE"].integer,
		HTTPIdleTimeout:                  v["EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS"].duration,
		HTTPMaxConcurrentUploads:         v["EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS"].integer,
		HTTPMaxHeaderBytes:               v["EVYDENCE_HTTP_MAX_HEADER_BYTES"].integer,
		HTTPMaxInFlightRequests:          v["EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS"].integer,
		HTTPMaxURLBytes:                  v["EVYDENCE_HTTP_MAX_URL_BYTES"].integer,
		HTTPReadHeaderTimeout:            v["EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS"].duration,
		HTTPReadTimeout:                  v["EVYDENCE_HTTP_READ_TIMEOUT_SECONDS"].duration,
		HTTPShutdownTimeout:              v["EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS"].duration,
		HTTPWriteTimeout:                 v["EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS"].duration,
		PrintBootstrapSecret:             v["EVYDENCE_PRINT_BOOTSTRAP_SECRET"].boolean,
		RateLimitBucketCapacity:          v["EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY"].integer,
		RateLimitRequestsPerMinute:       v["EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE"].integer,
		SSOSessionIdleTimeout:            v["EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS"].duration,
		SSOSessionMaxLifetime:            v["EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS"].duration,
		trustedProxyCIDRs:                slices.Clone(v["EVYDENCE_TRUSTED_PROXY_CIDRS"].prefixes),
		WorkerOwnedParserSideEffects:     v["EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS"].boolean,
	}
}

func projectWorker(input parsedInput) WorkerSettings {
	v := input.values
	return WorkerSettings{
		ParserReplayTimeout:   v["EVYDENCE_PARSER_REPLAY_TIMEOUT"].duration,
		ReconciliationTimeout: v["EVYDENCE_RECONCILIATION_TIMEOUT"].duration,
		BatchSize:             v["EVYDENCE_WORKER_BATCH_SIZE"].integer,
		HealthAddress:         optionalAddress(v["EVYDENCE_WORKER_HEALTH_ADDR"].text),
		MaxPayloadBytes:       v["EVYDENCE_WORKER_MAX_PAYLOAD_BYTES"].integer,
		MetricsAddress:        optionalAddress(v["EVYDENCE_WORKER_METRICS_ADDR"].text),
		MetricsTokenFile:      strings.TrimSpace(v["EVYDENCE_WORKER_METRICS_TOKEN_FILE"].text),
		PollInterval:          v["EVYDENCE_WORKER_POLL_INTERVAL"].duration,
		ShutdownTimeout:       v["EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS"].duration,
	}
}

func projectStorage(input parsedInput) StorageSettings {
	v := input.values
	return StorageSettings{
		Directory:         strings.TrimSpace(v["EVYDENCE_OBJECT_DIR"].text),
		Kind:              v["EVYDENCE_OBJECT_STORE"].text,
		S3AccessKeyID:     Secret{value: v["EVYDENCE_S3_ACCESS_KEY_ID"].text},
		S3Bucket:          strings.TrimSpace(v["EVYDENCE_S3_BUCKET"].text),
		S3Endpoint:        strings.TrimSpace(v["EVYDENCE_S3_ENDPOINT"].text),
		S3Region:          strings.TrimSpace(v["EVYDENCE_S3_REGION"].text),
		S3SecretAccessKey: Secret{value: v["EVYDENCE_S3_SECRET_ACCESS_KEY"].text},
		S3UseSSL:          v["EVYDENCE_S3_USE_SSL"].boolean,
	}
}

func projectProvider(input parsedInput) ProviderSettings {
	v := input.values
	return ProviderSettings{
		AWSKMSEndpoint:                      strings.TrimSpace(v["EVYDENCE_AWS_KMS_ENDPOINT"].text),
		AWSKMSKeyID:                         strings.TrimSpace(v["EVYDENCE_AWS_KMS_KEY_ID"].text),
		AWSKMSSigningAlgorithm:              v["EVYDENCE_AWS_KMS_SIGNING_ALGORITHM"].text,
		AWSKMSTimeout:                       v["EVYDENCE_AWS_KMS_TIMEOUT_SECONDS"].duration,
		AWSRegion:                           strings.TrimSpace(v["EVYDENCE_AWS_REGION"].text),
		AzureKeyVaultAlgorithm:              strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_ALGORITHM"].text),
		AzureKeyVaultAPIVersion:             strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_API_VERSION"].text),
		AzureKeyVaultKeyName:                strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_KEY_NAME"].text),
		AzureKeyVaultKeyVersion:             strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION"].text),
		AzureKeyVaultTimeout:                v["EVYDENCE_AZURE_KEY_VAULT_TIMEOUT_SECONDS"].duration,
		AzureKeyVaultURL:                    strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_URL"].text),
		GCPKMSEndpoint:                      strings.TrimSpace(v["EVYDENCE_GCP_KMS_ENDPOINT"].text),
		GCPKMSKeyName:                       strings.TrimSpace(v["EVYDENCE_GCP_KMS_KEY_NAME"].text),
		GCPKMSTimeout:                       v["EVYDENCE_GCP_KMS_TIMEOUT_SECONDS"].duration,
		OIDCDiscoveryAllowInsecureLocalhost: v["EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST"].boolean,
		OIDCDiscoveryTimeout:                v["EVYDENCE_OIDC_DISCOVERY_TIMEOUT_SECONDS"].duration,
		OIDCUserInfoAllowInsecureLocalhost:  v["EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST"].boolean,
		OIDCUserInfoTimeout:                 v["EVYDENCE_OIDC_USERINFO_TIMEOUT_SECONDS"].duration,
		ProviderValidationGatewayAllowInsecureLocalhost: v["EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST"].boolean,
		ProviderValidationGatewayTimeout:                v["EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TIMEOUT_SECONDS"].duration,
		ProviderValidationGatewayToken:                  Secret{value: strings.TrimSpace(v["EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN"].text)},
		ProviderValidationGatewayURL:                    strings.TrimSpace(v["EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL"].text),
		SigningExecutorAllowInsecureLocalhost:           v["EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST"].boolean,
		signingExecutorPublicKey:                        slices.Clone(v["EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64"].bytes),
		SigningExecutorReadinessURL:                     strings.TrimSpace(v["EVYDENCE_SIGNING_EXECUTOR_READINESS_URL"].text),
		SigningExecutorTimeout:                          v["EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS"].duration,
		SigningExecutorToken:                            Secret{value: strings.TrimSpace(v["EVYDENCE_SIGNING_EXECUTOR_TOKEN"].text)},
		SigningExecutorURL:                              strings.TrimSpace(v["EVYDENCE_SIGNING_EXECUTOR_URL"].text),
		SigningKeyMode:                                  v["EVYDENCE_SIGNING_KEY_MODE"].text,
		sigstoreTrustedPublicKeyPEM:                     slices.Clone(v["EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64"].bytes),
		sigstoreTrustRootJSON:                           slices.Clone(v["EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64"].bytes),
		SigstoreTrustRootVersion:                        strings.TrimSpace(v["EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION"].text),
		TransparencyFetchAllowInsecureLocalhost:         v["EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST"].boolean,
		TransparencyFetchTimeout:                        v["EVYDENCE_TRANSPARENCY_FETCH_TIMEOUT_SECONDS"].duration,
		TransparencyProofGatewayAllowInsecureLocalhost:  v["EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST"].boolean,
		TransparencyProofGatewayTimeout:                 v["EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TIMEOUT_SECONDS"].duration,
		TransparencyProofGatewayToken:                   Secret{value: strings.TrimSpace(v["EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN"].text)},
		TransparencyProofGatewayURL:                     strings.TrimSpace(v["EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL"].text),
	}
}

func projectCLI(input parsedInput) CLISettings {
	v := input.values
	return CLISettings{
		CI:                v["CI"].boolean,
		APIKey:            Secret{value: strings.TrimSpace(v["EVYDENCE_API_KEY"].text)},
		APIURL:            strings.TrimSpace(v["EVYDENCE_API_URL"].text),
		ArtifactID:        strings.TrimSpace(v["EVYDENCE_ARTIFACT_ID"].text),
		BuildFinishedAt:   v["EVYDENCE_BUILD_FINISHED_AT"].timestamp,
		BuildStartedAt:    v["EVYDENCE_BUILD_STARTED_AT"].timestamp,
		BuildStatus:       strings.TrimSpace(v["EVYDENCE_BUILD_STATUS"].text),
		GitHubOIDCSubject: strings.TrimSpace(v["EVYDENCE_GITHUB_OIDC_SUBJECT"].text),
		ProductID:         strings.TrimSpace(v["EVYDENCE_PRODUCT_ID"].text),
		ProjectID:         strings.TrimSpace(v["EVYDENCE_PROJECT_ID"].text),
		ReleaseID:         strings.TrimSpace(v["EVYDENCE_RELEASE_ID"].text),
		GitHubActor:       strings.TrimSpace(v["GITHUB_ACTOR"].text),
		GitHubJob:         strings.TrimSpace(v["GITHUB_JOB"].text),
		GitHubRef:         strings.TrimSpace(v["GITHUB_REF"].text),
		GitHubRepository:  strings.TrimSpace(v["GITHUB_REPOSITORY"].text),
		GitHubRunAttempt:  strings.TrimSpace(v["GITHUB_RUN_ATTEMPT"].text),
		GitHubRunID:       strings.TrimSpace(v["GITHUB_RUN_ID"].text),
		GitHubSHA:         strings.TrimSpace(v["GITHUB_SHA"].text),
		GitHubWorkflowRef: strings.TrimSpace(v["GITHUB_WORKFLOW_REF"].text),
	}
}

// Address syntax has already been checked before projection. Absent settings
// from other roles intentionally produce the zero address.
func optionalAddress(raw string) netip.AddrPort {
	address, _ := netip.ParseAddrPort(strings.TrimSpace(raw))
	return address
}
