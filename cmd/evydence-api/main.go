package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/identity/httpvalidator"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcdiscovery"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcuserinfo"
	"github.com/aatuh/evydence/internal/adapters/signing/awskms"
	"github.com/aatuh/evydence/internal/adapters/signing/azurekeyvault"
	"github.com/aatuh/evydence/internal/adapters/signing/gcpkms"
	signinggateway "github.com/aatuh/evydence/internal/adapters/signing/httpgateway"
	"github.com/aatuh/evydence/internal/adapters/transparency/httpfetcher"
	transparencygateway "github.com/aatuh/evydence/internal/adapters/transparency/httpgateway"
	cosignverification "github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
	"github.com/aatuh/evydence/internal/platform/wiring"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

const runtimeReadinessTimeout = 5 * time.Second

const maxSigstoreTrustConfigBytes = 1 << 20

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runWithContext(ctx); err != nil {
		log.Fatal(redaction.Error(err))
	}
}

func runWithContext(ctx context.Context) error {
	identity := runtimeinfo.Current()
	log.Printf("evydence api build identity %s", identity.String())
	production := strings.EqualFold(os.Getenv("ENV"), "production")
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	pepper := strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY_PEPPER"))
	profile, err := wiring.ResolveRuntimeProfile(os.Getenv("EVYDENCE_RUNTIME_PROFILE"), production, databaseURL, wiring.API)
	if err != nil {
		return err
	}
	if err := validateRuntimeConfig(
		production,
		databaseURL,
		pepper,
		strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_KEY_MODE")),
		strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_EXECUTOR_URL")),
		strings.EqualFold(os.Getenv("EVYDENCE_PRINT_BOOTSTRAP_SECRET"), "true"),
	); err != nil {
		return err
	}
	if err := validateAPIWriterMode(production, os.Getenv("EVYDENCE_API_WRITER_MODE"), os.Getenv("EVYDENCE_API_WRITER_REPLICAS")); err != nil {
		return err
	}
	if err := validateOutboundHTTPConfig(production); err != nil {
		return err
	}
	httpConfig, err := httpRuntimeConfigFromEnv()
	if err != nil {
		return err
	}
	cfg := app.Config{APIKeyPepper: pepper}
	cfg.WorkerOwnedParserSideEffects = boolEnv("EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS")
	cfg.OIDC = oidcdiscovery.New(oidcdiscovery.Config{
		AllowInsecureForLocalhost: outboundLocalhostAllowed("EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_OIDC_DISCOVERY_TIMEOUT_SECONDS", 10)) * time.Second,
	})
	providerValidator, err := openProviderIdentityValidator()
	if err != nil {
		return err
	}
	cfg.ProviderAPI = providerValidator
	transparencyFetcher, err := openTransparencyProofFetcher()
	if err != nil {
		return err
	}
	cfg.Transparency = transparencyFetcher
	cosignVerifier, err := openCosignVerifier()
	if err != nil {
		return err
	}
	cfg.Cosign = cosignVerifier
	if signer, err := openSigningExecutor(ctx); err != nil {
		return err
	} else {
		cfg.Signer = signer
	}
	startupCtx, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()
	migrationsDir := envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")
	runtime, err := wiring.OpenRuntime(startupCtx, wiring.RuntimeConfig{
		Process:        wiring.API,
		Profile:        profile,
		Production:     production,
		DatabaseURL:    databaseURL,
		LoadMode:       os.Getenv("EVYDENCE_POSTGRES_LOAD_MODE"),
		MigrationsDir:  migrationsDir,
		SkipMigrations: strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true"),
		ObjectStore:    wiring.ObjectStoreConfigFromEnv(),
	})
	if err != nil {
		return err
	}
	defer runtime.Close()
	if profile == wiring.PostgreSQL {
		pgStore := runtime.Postgres
		objectStore := runtime.Objects
		cfg.Store = pgStore
		cfg.UnitOfWork = pgStore
		cfg.Outbox = pgStore
		cfg.OutboxAdmin = pgStore
		cfg.ReconciliationMetrics = pgStore
		cfg.ObjectStore = objectStore
		cfg.ReadinessChecks = append(cfg.ReadinessChecks,
			app.ReadinessCheck{Name: "postgres", Timeout: runtimeReadinessTimeout, FailureDetail: "database connectivity is unavailable", Check: pgStore.CheckReadiness},
			app.ReadinessCheck{Name: "migrations", Timeout: runtimeReadinessTimeout, FailureDetail: "database migration state is unavailable", Check: func(checkCtx context.Context) error {
				return pgStore.CheckMigrationState(checkCtx, migrationsDir)
			}},
		)
		if production {
			cfg.ReadinessChecks = append(cfg.ReadinessChecks, app.ReadinessCheck{Name: "writer_lease", Timeout: runtimeReadinessTimeout, FailureDetail: "API writer lease is unavailable", Check: pgStore.CheckAPIWriterLease})
		}
		objectReadiness, ok := objectStore.(interface{ CheckReadiness(context.Context) error })
		if !ok {
			return errors.New("configured object store does not provide readiness checks")
		}
		cfg.ReadinessChecks = append(cfg.ReadinessChecks, app.ReadinessCheck{Name: "object_store", Timeout: runtimeReadinessTimeout, FailureDetail: "object store access is unavailable", Check: objectReadiness.CheckReadiness})
		log.Print("evydence api using postgres state store and configured object store")
	} else {
		cfg.ObjectStore = runtime.Objects
		for _, limitation := range profile.Limitations() {
			log.Print(redaction.RedactString(limitation)) // #nosec G706 -- Limitations returns compiled literals; redaction removes line breaks.
		}
	}
	if production {
		cfg.ReadinessChecks = append(cfg.ReadinessChecks, app.ReadinessCheck{Name: "signing_config", Timeout: runtimeReadinessTimeout, FailureDetail: "required signing configuration is unavailable", Check: signingConfigurationReadiness(cfg.Signer)})
	}
	ledgerContext, cancelLedgerLoad := context.WithTimeout(ctx, 30*time.Second)
	defer cancelLedgerLoad()
	ledger, err := app.NewLedgerWithContext(ledgerContext, cfg)
	if err != nil {
		return fmt.Errorf("create ledger: %w", err)
	}
	if !ledger.HasTenants(ctx) && !strings.EqualFold(os.Getenv("EVYDENCE_BOOTSTRAP_DISABLED"), "true") {
		tenant, key, secret, err := ledger.BootstrapTenant(ctx, envDefault("EVYDENCE_BOOTSTRAP_TENANT", "Local Tenant"), "local-admin", []string{"*"})
		if err != nil {
			return fmt.Errorf("bootstrap tenant: %w", err)
		}
		if strings.EqualFold(os.Getenv("EVYDENCE_PRINT_BOOTSTRAP_SECRET"), "true") {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"tenant_id": tenant.ID,
				"api_key":   key,
				"secret":    secret,
			})
		} else {
			log.Printf("bootstrapped tenant %s and key %s; set EVYDENCE_PRINT_BOOTSTRAP_SECRET=true for local-only secret output", tenant.ID, key.ID)
		}
	}
	var productQuery httpapi.ProductQuery
	var catalogPointQuery httpapi.CatalogPointQuery
	var buildPointQuery httpapi.BuildPointQuery
	var releaseCandidateQuery httpapi.ReleaseCandidateQuery
	var deploymentPointQuery httpapi.DeploymentPointQuery
	var deploymentListQuery httpapi.DeploymentListQuery
	var evidencePointQuery httpapi.EvidencePointQuery
	var sourceRepositoryQuery httpapi.SourceRepositoryQuery
	var collectorQuery httpapi.CollectorQuery
	var auditLogQuery httpapi.AuditLogQuery
	var apiKeyQuery httpapi.APIKeyQuery
	var roleBindingQuery httpapi.RoleBindingQuery
	var authenticator httpapi.Authenticator
	if runtime.Postgres != nil {
		authenticator, err = wiring.BuildAuthenticator(runtime.Postgres, runtime.Postgres, pepper, production)
		if err != nil {
			return fmt.Errorf("create authenticator: %w", err)
		}
		productQuery, err = wiring.BuildProductQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create product query: %w", err)
		}
		catalogPointQuery, err = wiring.BuildCatalogPointQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create catalog point query: %w", err)
		}
		buildPointQuery, err = wiring.BuildBuildPointQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create build point query: %w", err)
		}
		releaseCandidateQuery, err = wiring.BuildReleaseCandidateQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create release candidate query: %w", err)
		}
		deploymentPointQuery, err = wiring.BuildDeploymentPointQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create deployment point query: %w", err)
		}
		deploymentListQuery, err = wiring.BuildDeploymentListQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create deployment list query: %w", err)
		}
		evidencePointQuery, err = wiring.BuildEvidencePointQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create evidence point query: %w", err)
		}
		sourceRepositoryQuery, err = wiring.BuildSourceRepositoryQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create source repository query: %w", err)
		}
		collectorQuery, err = wiring.BuildCollectorQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create collector query: %w", err)
		}
		auditLogQuery, err = wiring.BuildAuditLogQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create audit log query: %w", err)
		}
		apiKeyQuery, err = wiring.BuildAPIKeyQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create API-key query: %w", err)
		}
		roleBindingQuery, err = wiring.BuildRoleBindingQuery(runtime.Postgres)
		if err != nil {
			return fmt.Errorf("create role-binding query: %w", err)
		}
	}
	server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, httpapi.ServerOptions{
		Authenticator:                    authenticator,
		RateLimitRequestsPerMinute:       httpConfig.RateLimitRequestsPerMinute,
		ExpensiveTenantRequestsPerMinute: httpConfig.ExpensiveTenantRequestsPerMinute,
		RateLimitBucketCapacity:          httpConfig.RateLimitBucketCapacity,
		TrustedProxyCIDRs:                httpConfig.TrustedProxyCIDRs,
		MaxURLBytes:                      httpConfig.MaxURLBytes,
		MaxInboundRequestBytes:           httpConfig.MaxInboundRequestBytes,
		MaxInFlightRequests:              httpConfig.MaxInFlightRequests,
		MaxConcurrentUploads:             httpConfig.MaxConcurrentUploads,
		BuildIdentity:                    identity,
		PaginationSecret:                 []byte(pepper),
		ProductQuery:                     productQuery,
		CatalogPointQuery:                catalogPointQuery,
		BuildPointQuery:                  buildPointQuery,
		ReleaseCandidateQuery:            releaseCandidateQuery,
		DeploymentPointQuery:             deploymentPointQuery,
		DeploymentListQuery:              deploymentListQuery,
		EvidencePointQuery:               evidencePointQuery,
		SourceRepositoryQuery:            sourceRepositoryQuery,
		CollectorQuery:                   collectorQuery,
		AuditLogQuery:                    auditLogQuery,
		APIKeyQuery:                      apiKeyQuery,
		RoleBindingQuery:                 roleBindingQuery,
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	addr := envDefault("EVYDENCE_ADDR", ":8080")
	httpServer := newHTTPServer(addr, server.Handler(), httpConfig)
	log.Printf("evydence api listening on %s", addr)
	return serveHTTP(ctx, httpServer, httpConfig.ShutdownTimeout)
}

func openSigningExecutor(ctx context.Context) (app.SigningExecutor, error) {
	mode := normalizeSigningKeyMode(os.Getenv("EVYDENCE_SIGNING_KEY_MODE"))
	if mode == "aws_kms" {
		region := strings.TrimSpace(os.Getenv("EVYDENCE_AWS_REGION"))
		if region == "" {
			region = strings.TrimSpace(os.Getenv("AWS_REGION"))
		}
		executor, err := awskms.New(ctx, awskms.Config{
			Region:           region,
			KeyID:            os.Getenv("EVYDENCE_AWS_KMS_KEY_ID"),
			Endpoint:         os.Getenv("EVYDENCE_AWS_KMS_ENDPOINT"),
			SigningAlgorithm: os.Getenv("EVYDENCE_AWS_KMS_SIGNING_ALGORITHM"),
			Timeout:          time.Duration(intEnv("EVYDENCE_AWS_KMS_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure AWS KMS signing executor: %w", err)
		}
		return executor, nil
	}
	if mode == "gcp_kms" {
		executor, err := gcpkms.New(ctx, gcpkms.Config{
			Endpoint: os.Getenv("EVYDENCE_GCP_KMS_ENDPOINT"),
			KeyName:  os.Getenv("EVYDENCE_GCP_KMS_KEY_NAME"),
			Timeout:  time.Duration(intEnv("EVYDENCE_GCP_KMS_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure GCP KMS signing executor: %w", err)
		}
		return executor, nil
	}
	if mode == "azure_key_vault" {
		executor, err := azurekeyvault.New(azurekeyvault.Config{
			VaultURL:   os.Getenv("EVYDENCE_AZURE_KEY_VAULT_URL"),
			KeyName:    os.Getenv("EVYDENCE_AZURE_KEY_VAULT_KEY_NAME"),
			KeyVersion: os.Getenv("EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION"),
			Algorithm:  os.Getenv("EVYDENCE_AZURE_KEY_VAULT_ALGORITHM"),
			APIVersion: os.Getenv("EVYDENCE_AZURE_KEY_VAULT_API_VERSION"),
			Timeout:    time.Duration(intEnv("EVYDENCE_AZURE_KEY_VAULT_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure Azure Key Vault signing executor: %w", err)
		}
		return executor, nil
	}
	endpoint := strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_EXECUTOR_URL"))
	if endpoint == "" && signingModeRequiresGateway(mode) {
		return nil, fmt.Errorf("EVYDENCE_SIGNING_KEY_MODE=%s requires direct provider credentials or EVYDENCE_SIGNING_EXECUTOR_URL", mode)
	}
	if endpoint == "" {
		return nil, nil
	}
	executor, err := signinggateway.New(signinggateway.Config{
		Endpoint:                  endpoint,
		BearerToken:               os.Getenv("EVYDENCE_SIGNING_EXECUTOR_TOKEN"),
		VerificationPublicKey:     os.Getenv("EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64"),
		AllowInsecureForLocalhost: outboundLocalhostAllowed("EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS", 10)) * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("configure signing executor: %w", err)
	}
	return executor, nil
}

func openTransparencyProofFetcher() (app.TransparencyProofFetcher, error) {
	endpoint := strings.TrimSpace(os.Getenv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL"))
	if endpoint != "" {
		fetcher, err := transparencygateway.New(transparencygateway.Config{
			Endpoint:                  endpoint,
			BearerToken:               os.Getenv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN"),
			AllowInsecureForLocalhost: outboundLocalhostAllowed("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST"),
			Timeout:                   time.Duration(intEnv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure transparency proof gateway: %w", err)
		}
		return fetcher, nil
	}
	return httpfetcher.New(httpfetcher.Config{
		AllowInsecureForLocalhost: outboundLocalhostAllowed("EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_TRANSPARENCY_FETCH_TIMEOUT_SECONDS", 10)) * time.Second,
	}), nil
}

// openCosignVerifier decodes public, operator-managed trust material from
// bounded base64 environment variables. It deliberately has no network path:
// the verification endpoint supports explicit offline bundles only.
func openCosignVerifier() (app.CosignPolicyVerifier, error) {
	rootValue := strings.TrimSpace(os.Getenv("EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64"))
	keyValue := strings.TrimSpace(os.Getenv("EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64"))
	if rootValue == "" && keyValue == "" {
		return nil, nil
	}
	version := strings.TrimSpace(os.Getenv("EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION"))
	if version == "" {
		return nil, errors.New("sigstore trust material requires EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION")
	}
	rootJSON, err := decodeBoundedBase64Config(rootValue)
	if err != nil {
		return nil, errors.New("EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64 is invalid")
	}
	publicKey, err := decodeBoundedBase64Config(keyValue)
	if err != nil {
		return nil, errors.New("EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64 is invalid")
	}
	verifier, err := cosignverification.New(cosignverification.Config{
		TrustedRootJSON:     rootJSON,
		TrustRootVersion:    version,
		TrustedPublicKeyPEM: publicKey,
	})
	if err != nil {
		return nil, errors.New("configured Sigstore trust material is invalid")
	}
	return verifier, nil
}

func decodeBoundedBase64Config(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > base64.StdEncoding.EncodedLen(maxSigstoreTrustConfigBytes) {
		return nil, errors.New("configuration is too large")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maxSigstoreTrustConfigBytes {
		return nil, errors.New("invalid base64 configuration")
	}
	return decoded, nil
}

func openProviderIdentityValidator() (app.ProviderIdentityValidator, error) {
	endpoint := strings.TrimSpace(os.Getenv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL"))
	if endpoint != "" {
		validator, err := httpvalidator.New(httpvalidator.Config{
			Endpoint:                  endpoint,
			BearerToken:               os.Getenv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN"),
			AllowInsecureForLocalhost: outboundLocalhostAllowed("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST"),
			Timeout:                   time.Duration(intEnv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure provider validation gateway: %w", err)
		}
		return validator, nil
	}
	return oidcuserinfo.New(oidcuserinfo.Config{
		AllowInsecureForLocalhost: outboundLocalhostAllowed("EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_OIDC_USERINFO_TIMEOUT_SECONDS", 10)) * time.Second,
	}), nil
}

func validateRuntimeConfig(production bool, databaseURL, pepper, signingKeyMode, signingExecutorURL string, printBootstrapSecret bool) error {
	if !production {
		return nil
	}
	if strings.TrimSpace(databaseURL) == "" {
		return errors.New("production requires EVYDENCE_DATABASE_URL")
	}
	if strings.TrimSpace(pepper) == "" || strings.TrimSpace(pepper) == identityapp.LocalDevelopmentPepper {
		return errors.New("production requires a non-default EVYDENCE_API_KEY_PEPPER")
	}
	normalizedMode := normalizeSigningKeyMode(signingKeyMode)
	if !productionSigningKeyMode(normalizedMode) {
		return errors.New("production requires EVYDENCE_SIGNING_KEY_MODE=external, aws-kms, gcp-kms, azure-key-vault, or pkcs11-hsm; plaintext local signing keys are dev-only")
	}
	if (normalizedMode == "pkcs11_hsm" || normalizedMode == "external") && strings.TrimSpace(signingExecutorURL) == "" {
		return fmt.Errorf("production EVYDENCE_SIGNING_KEY_MODE=%s requires EVYDENCE_SIGNING_EXECUTOR_URL", normalizedMode)
	}
	if printBootstrapSecret {
		return errors.New("production refuses EVYDENCE_PRINT_BOOTSTRAP_SECRET=true")
	}
	return nil
}

var outboundLocalhostOverrideNames = []string{
	"EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST",
	"EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST",
	"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST",
	"EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST",
	"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST",
	"EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST",
}

func validateOutboundHTTPConfig(production bool) error {
	if !production {
		return nil
	}
	for _, name := range outboundLocalhostOverrideNames {
		if boolEnv(name) {
			return fmt.Errorf("production refuses %s=true", name)
		}
	}
	return nil
}

func outboundLocalhostAllowed(name string) bool {
	return !strings.EqualFold(os.Getenv("ENV"), "production") && boolEnv(name)
}

func signingConfigurationReadiness(signer app.SigningExecutor) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if signer == nil {
			return errors.New("signing executor is not configured")
		}
		return nil
	}
}

func normalizeSigningKeyMode(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return normalized
}

func productionSigningKeyMode(normalizedMode string) bool {
	switch normalizedMode {
	case "external", "aws_kms", "gcp_kms", "azure_key_vault", "pkcs11_hsm":
		return true
	default:
		return false
	}
}

func signingModeRequiresGateway(normalizedMode string) bool {
	switch normalizedMode {
	case "external", "gcp_kms", "azure_key_vault", "pkcs11_hsm":
		return true
	default:
		return false
	}
}

func validateAPIWriterMode(production bool, mode, replicas string) error {
	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	if normalizedMode == "" {
		normalizedMode = "single"
	}
	switch normalizedMode {
	case "single", "single-writer":
	default:
		if production {
			return fmt.Errorf("production supports only EVYDENCE_API_WRITER_MODE=single until multi-writer concurrency controls are implemented")
		}
	}

	replicaValue := strings.TrimSpace(replicas)
	if replicaValue == "" {
		return nil
	}
	replicaCount, err := strconv.Atoi(replicaValue)
	if err != nil || replicaCount < 1 {
		return fmt.Errorf("EVYDENCE_API_WRITER_REPLICAS must be a positive integer")
	}
	if production && replicaCount != 1 {
		return fmt.Errorf("production supports only one API writer replica until multi-writer concurrency controls are implemented")
	}
	return nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

type httpRuntimeConfig struct {
	ReadHeaderTimeout                time.Duration
	ReadTimeout                      time.Duration
	WriteTimeout                     time.Duration
	IdleTimeout                      time.Duration
	ShutdownTimeout                  time.Duration
	MaxHeaderBytes                   int
	MaxURLBytes                      int
	MaxInboundRequestBytes           int64
	MaxInFlightRequests              int
	MaxConcurrentUploads             int
	RateLimitRequestsPerMinute       int
	ExpensiveTenantRequestsPerMinute int
	RateLimitBucketCapacity          int
	TrustedProxyCIDRs                []string
}

// httpRuntimeConfigFromEnv validates ingress controls before a listener is
// opened. Bounds deliberately make accidental zero/infinite timeouts and
// memory-expanding headers impossible in the API process configuration.
func httpRuntimeConfigFromEnv() (httpRuntimeConfig, error) {
	readHeaderTimeout, err := boundedDurationSecondsEnv("EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS", 5, 1, 60)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	readTimeout, err := boundedDurationSecondsEnv("EVYDENCE_HTTP_READ_TIMEOUT_SECONDS", 30, 1, 900)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	writeTimeout, err := boundedDurationSecondsEnv("EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS", 60, 1, 900)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	idleTimeout, err := boundedDurationSecondsEnv("EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS", 120, 1, 3600)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	shutdownTimeout, err := boundedDurationSecondsEnv("EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS", 30, 1, 300)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	maxHeaderBytes, err := boundedIntEnv("EVYDENCE_HTTP_MAX_HEADER_BYTES", 16<<10, 1<<10, 1<<20)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	maxURLBytes, err := boundedIntEnv("EVYDENCE_HTTP_MAX_URL_BYTES", 8<<10, 1<<10, 64<<10)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	maxInFlight, err := boundedIntEnv("EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS", 256, 1, 100_000)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	maxUploads, err := boundedIntEnv("EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS", 8, 1, 10_000)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	rateLimit, err := boundedIntEnv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", 120, 0, 60_000)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	expensiveTenantRateLimit, err := boundedIntEnv("EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE", 30, 0, 60_000)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	bucketCapacity, err := boundedIntEnv("EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY", 10_000, 1, 1_000_000)
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	trustedProxyCIDRs, err := trustedProxyCIDRsFromEnv("EVYDENCE_TRUSTED_PROXY_CIDRS")
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	return httpRuntimeConfig{
		ReadHeaderTimeout:                readHeaderTimeout,
		ReadTimeout:                      readTimeout,
		WriteTimeout:                     writeTimeout,
		IdleTimeout:                      idleTimeout,
		ShutdownTimeout:                  shutdownTimeout,
		MaxHeaderBytes:                   maxHeaderBytes,
		MaxURLBytes:                      maxURLBytes,
		MaxInboundRequestBytes:           app.EvidenceDocumentLimit,
		MaxInFlightRequests:              maxInFlight,
		MaxConcurrentUploads:             maxUploads,
		RateLimitRequestsPerMinute:       rateLimit,
		ExpensiveTenantRequestsPerMinute: expensiveTenantRateLimit,
		RateLimitBucketCapacity:          bucketCapacity,
		TrustedProxyCIDRs:                trustedProxyCIDRs,
	}, nil
}

func boundedDurationSecondsEnv(name string, fallback, min, max int) (time.Duration, error) {
	seconds, err := boundedIntEnv(name, fallback, min, max)
	if err != nil {
		return 0, err
	}
	return time.Duration(seconds) * time.Second, nil
}

func boundedIntEnv(name string, fallback, min, max int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return parsed, nil
}

func trustedProxyCIDRsFromEnv(name string) ([]string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	trusted := make([]string, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("%s contains an invalid CIDR", name)
		}
		trusted = append(trusted, prefix.Masked().String())
	}
	return trusted, nil
}

func newHTTPServer(addr string, handler http.Handler, config httpRuntimeConfig) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		ReadTimeout:       config.ReadTimeout,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    config.MaxHeaderBytes,
	}
}

func serveHTTP(ctx context.Context, server *http.Server, shutdownTimeout time.Duration) error {
	if ctx == nil {
		return errors.New("API server context is required")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", server.Addr)
	if err != nil {
		return err
	}
	return serveHTTPOnListener(ctx, server, listener, shutdownTimeout)
}

func serveHTTPOnListener(ctx context.Context, server *http.Server, listener net.Listener, shutdownTimeout time.Duration) error {
	if ctx == nil {
		return errors.New("API server context is required")
	}
	if shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("gracefully shut down API server: %w", err)
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func intEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func boolEnv(name string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(name)), "true")
}

func openObjectStore(ctx context.Context) (app.ObjectStore, string, error) {
	return wiring.OpenObjectStore(ctx, wiring.ObjectStoreConfigFromEnv())
}
