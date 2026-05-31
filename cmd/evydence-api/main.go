package main

import (
	"context"
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
	"github.com/aatuh/evydence/internal/adapters/identity/oidcdiscovery"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcuserinfo"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/signing/awskms"
	"github.com/aatuh/evydence/internal/adapters/signing/httpgateway"
	"github.com/aatuh/evydence/internal/adapters/transparency/httpfetcher"
	"github.com/aatuh/evydence/internal/app"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
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
	cfg.ProviderAPI = oidcuserinfo.New(oidcuserinfo.Config{
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST"), "true"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_OIDC_USERINFO_TIMEOUT_SECONDS", 10)) * time.Second,
	})
	cfg.Transparency = httpfetcher.New(httpfetcher.Config{
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST"), "true"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_TRANSPARENCY_FETCH_TIMEOUT_SECONDS", 10)) * time.Second,
	})
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
		cfg.Outbox = pgStore
		cfg.ObjectStore = objectStore
		log.Print("evydence api using postgres state store and configured object store")
	}
	if closeStore != nil {
		defer closeStore()
	}
	if releaseWriterLease != nil {
		defer releaseWriterLease()
	}
	ledger, err := app.NewLedgerWithError(cfg)
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
	endpoint := strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_EXECUTOR_URL"))
	if endpoint == "" && signingModeRequiresGateway(mode) {
		return nil, fmt.Errorf("EVYDENCE_SIGNING_KEY_MODE=%s requires EVYDENCE_SIGNING_EXECUTOR_URL because no direct SDK executor is configured", mode)
	}
	if endpoint == "" {
		return nil, nil
	}
	executor, err := httpgateway.New(httpgateway.Config{
		Endpoint:                  endpoint,
		BearerToken:               os.Getenv("EVYDENCE_SIGNING_EXECUTOR_TOKEN"),
		AllowInsecureForLocalhost: strings.EqualFold(os.Getenv("EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST"), "true"),
		Timeout:                   time.Duration(intEnv("EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS", 10)) * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("configure signing executor: %w", err)
	}
	return executor, nil
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
	if signingModeRequiresGateway(normalizedMode) && strings.TrimSpace(signingExecutorURL) == "" {
		return fmt.Errorf("production EVYDENCE_SIGNING_KEY_MODE=%s requires EVYDENCE_SIGNING_EXECUTOR_URL", normalizedMode)
	}
	if printBootstrapSecret {
		return errors.New("production refuses EVYDENCE_PRINT_BOOTSTRAP_SECRET=true")
	}
	return nil
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
	case "gcp_kms", "azure_key_vault", "pkcs11_hsm":
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
