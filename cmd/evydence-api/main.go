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
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
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
	if production {
		if databaseURL == "" {
			return errors.New("production requires EVYDENCE_DATABASE_URL")
		}
		if pepper == "" || pepper == "local-dev-pepper-change-me" {
			return errors.New("production requires a non-default EVYDENCE_API_KEY_PEPPER")
		}
		if strings.TrimSpace(os.Getenv("EVYDENCE_SIGNING_KEY_MODE")) != "external" {
			return errors.New("production requires EVYDENCE_SIGNING_KEY_MODE=external; plaintext local signing keys are dev-only")
		}
	}
	cfg := app.Config{APIKeyPepper: pepper}
	var closeStore func()
	if databaseURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pgStore, err := postgres.Open(ctx, databaseURL)
		if err != nil {
			return err
		}
		closeStore = pgStore.Close
		if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
			if _, err := pgStore.ApplyMigrations(ctx, envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")); err != nil {
				closeStore()
				return fmt.Errorf("apply migrations: %w", err)
			}
		}
		objectRoot := envDefault("EVYDENCE_OBJECT_DIR", filepath.Join("tmp", "objects"))
		objectStore, err := filesystem.New(objectRoot)
		if err != nil {
			closeStore()
			return err
		}
		cfg.Store = pgStore
		cfg.Outbox = pgStore
		cfg.ObjectStore = objectStore
		log.Printf("evydence api using postgres state store and filesystem object store root %s", objectRoot)
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
	server, err := httpapi.NewServer(ledger)
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

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
