package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/identity/httpvalidator"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcdiscovery"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcuserinfo"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/signing/awskms"
	"github.com/aatuh/evydence/internal/adapters/signing/azurekeyvault"
	"github.com/aatuh/evydence/internal/adapters/signing/gcpkms"
	signinggateway "github.com/aatuh/evydence/internal/adapters/signing/httpgateway"
	"github.com/aatuh/evydence/internal/adapters/transparency/httpfetcher"
	transparencygateway "github.com/aatuh/evydence/internal/adapters/transparency/httpgateway"
	cosignverification "github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

const runtimeReadinessTimeout = 5 * time.Second

const maxSigstoreTrustConfigBytes = 1 << 20

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	identity := runtimeinfo.Current()
	log.Printf("evydence api build identity %s", identity.String())
	production := strings.EqualFold(os.Getenv("ENV"), "production")
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	pepper := strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY_PEPPER"))
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
	cfg := app.Config{APIKeyPepper: pepper}
	cfg.WorkerOwnedParserSideEffects = boolEnv("EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS")
	cfg.OIDC = oidcdiscovery.New(oidcdiscovery.Config{
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST"), "true"),
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
	if signer, err := openSigningExecutor(); err != nil {
		return err
	} else {
		cfg.Signer = signer
	}
	var closeStore func()
	var releaseWriterLease func()
	if databaseURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		loadMode, err := postgres.ResolveLoadMode(os.Getenv("EVYDENCE_POSTGRES_LOAD_MODE"), production)
		if err != nil {
			return err
		}
		if production {
			if err := postgres.ValidateProductionLoadMode(loadMode); err != nil {
				return err
			}
		}
		pgStore, err := postgres.OpenWithOptions(ctx, databaseURL, postgres.StoreOptions{LoadMode: loadMode, DisableSnapshotWrites: production})
		if err != nil {
			return err
		}
		closeStore = pgStore.Close
		if production {
			releaseWriterLease, err = pgStore.AcquireAPIWriterLease(ctx)
			if err != nil {
				closeStore()
				return fmt.Errorf("acquire api writer lease: %w", err)
			}
		}
		migrationsDir := envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")
		if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
			if _, err := pgStore.ApplyMigrations(ctx, migrationsDir); err != nil {
				closeStore()
				return fmt.Errorf("apply migrations: %w", err)
			}
		} else if err := pgStore.RequireNoPendingMigrations(ctx, migrationsDir); err != nil {
			closeStore()
			return fmt.Errorf("check migrations: %w", err)
		}
		objectStore, _, err := openObjectStore(ctx)
		if err != nil {
			closeStore()
			return err
		}
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
			closeStore()
			return errors.New("configured object store does not provide readiness checks")
		}
		cfg.ReadinessChecks = append(cfg.ReadinessChecks, app.ReadinessCheck{Name: "object_store", Timeout: runtimeReadinessTimeout, FailureDetail: "object store access is unavailable", Check: objectReadiness.CheckReadiness})
		log.Print("evydence api using postgres state store and configured object store")
	}
	if production {
		cfg.ReadinessChecks = append(cfg.ReadinessChecks, app.ReadinessCheck{Name: "signing_config", Timeout: runtimeReadinessTimeout, FailureDetail: "required signing configuration is unavailable", Check: signingConfigurationReadiness(cfg.Signer)})
	}
	if closeStore != nil {
		defer closeStore()
	}
	if releaseWriterLease != nil {
		defer releaseWriterLease()
	}
	ledgerContext, cancelLedgerLoad := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelLedgerLoad()
	ledger, err := app.NewLedgerWithContext(ledgerContext, cfg)
	if err != nil {
		return fmt.Errorf("create ledger: %w", err)
	}
	if !ledger.HasTenants() && !strings.EqualFold(os.Getenv("EVYDENCE_BOOTSTRAP_DISABLED"), "true") {
		tenant, key, secret, err := ledger.BootstrapTenant(context.Background(), envDefault("EVYDENCE_BOOTSTRAP_TENANT", "Local Tenant"), "local-admin", []string{"*"})
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
	server, err := httpapi.NewServerWithOptions(ledger, httpapi.ServerOptions{
		RateLimitRequestsPerMinute: intEnv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", 0),
		BuildIdentity:              identity,
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	addr := envDefault("EVYDENCE_ADDR", ":8080")
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("evydence api listening on %s", addr)
	return httpServer.ListenAndServe()
}

func openSigningExecutor() (app.SigningExecutor, error) {
	mode := normalizeSigningKeyMode(os.Getenv("EVYDENCE_SIGNING_KEY_MODE"))
	if mode == "aws_kms" {
		region := strings.TrimSpace(os.Getenv("EVYDENCE_AWS_REGION"))
		if region == "" {
			region = strings.TrimSpace(os.Getenv("AWS_REGION"))
		}
		executor, err := awskms.New(context.Background(), awskms.Config{
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
		executor, err := gcpkms.New(context.Background(), gcpkms.Config{
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
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST"), "true"),
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
			AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST"), "true"),
			Timeout:                   time.Duration(intEnv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure transparency proof gateway: %w", err)
		}
		return fetcher, nil
	}
	return httpfetcher.New(httpfetcher.Config{
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST"), "true"),
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
			AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST"), "true"),
			Timeout:                   time.Duration(intEnv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TIMEOUT_SECONDS", 10)) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("configure provider validation gateway: %w", err)
		}
		return validator, nil
	}
	return oidcuserinfo.New(oidcuserinfo.Config{
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST"), "true"),
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
	if strings.TrimSpace(pepper) == "" || strings.TrimSpace(pepper) == "local-dev-pepper-change-me" {
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
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EVYDENCE_OBJECT_STORE"))) {
	case "", "file", "filesystem":
		objectRoot := envDefault("EVYDENCE_OBJECT_DIR", filepath.Join("tmp", "objects"))
		objectStore, err := filesystem.New(objectRoot)
		if err != nil {
			return nil, "", err
		}
		return objectStore, "filesystem root " + objectRoot, nil
	case "s3", "minio":
		objectStore, err := s3store.New(ctx, s3store.Config{
			Endpoint:        os.Getenv("EVYDENCE_S3_ENDPOINT"),
			AccessKeyID:     os.Getenv("EVYDENCE_S3_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("EVYDENCE_S3_SECRET_ACCESS_KEY"),
			Bucket:          os.Getenv("EVYDENCE_S3_BUCKET"),
			Region:          os.Getenv("EVYDENCE_S3_REGION"),
			UseSSL:          strings.EqualFold(os.Getenv("EVYDENCE_S3_USE_SSL"), "true"),
		})
		if err != nil {
			return nil, "", err
		}
		return objectStore, "S3-compatible bucket " + envDefault("EVYDENCE_S3_BUCKET", ""), nil
	default:
		return nil, "", errors.New("unsupported EVYDENCE_OBJECT_STORE")
	}
}
