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
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/signing/httpgateway"
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
	if err := validateRuntimeConfig(production, databaseURL, pepper, strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_KEY_MODE")), strings.EqualFold(os.Getenv("EVYDENCE_PRINT_BOOTSTRAP_SECRET"), "true")); err != nil {
		return err
	}
	cfg := app.Config{APIKeyPepper: pepper}
	if signer, err := openSigningExecutor(); err != nil {
		return err
	} else {
		cfg.Signer = signer
	}
	var closeStore func()
	if databaseURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		loadMode, err := postgres.ResolveLoadMode(os.Getenv("EVYDENCE_POSTGRES_LOAD_MODE"), production)
		if err != nil {
			return err
		}
		pgStore, err := postgres.OpenWithOptions(ctx, databaseURL, postgres.StoreOptions{LoadMode: loadMode})
		if err != nil {
			return err
		}
		closeStore = pgStore.Close
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
	endpoint := strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_EXECUTOR_URL"))
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

func validateRuntimeConfig(production bool, databaseURL, pepper, signingKeyMode string, printBootstrapSecret bool) error {
	if !production {
		return nil
	}
	if strings.TrimSpace(databaseURL) == "" {
		return errors.New("production requires EVYDENCE_DATABASE_URL")
	}
	if strings.TrimSpace(pepper) == "" || strings.TrimSpace(pepper) == "local-dev-pepper-change-me" {
		return errors.New("production requires a non-default EVYDENCE_API_KEY_PEPPER")
	}
	if strings.TrimSpace(signingKeyMode) != "external" {
		return errors.New("production requires EVYDENCE_SIGNING_KEY_MODE=external; plaintext local signing keys are dev-only")
	}
	if printBootstrapSecret {
		return errors.New("production refuses EVYDENCE_PRINT_BOOTSTRAP_SECRET=true")
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
