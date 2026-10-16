package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	return logging.Run(context.Background(), "migrate", runtimeinfo.Current(), os.Stderr, os.Getenv, runMigrations)
}

func runMigrations(parent context.Context) error {
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("EVYDENCE_DATABASE_URL is required")
	}
	migrationsDir := envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	store, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	applied, err := store.ApplyMigrations(ctx, migrationsDir)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "applied %d migration(s)\n", applied); err != nil {
		return fmt.Errorf("write migration result: %w", err)
	}
	return nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
