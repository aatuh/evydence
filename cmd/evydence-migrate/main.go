package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	environment, err := config.Capture(os.Environ())
	if err != nil {
		logging.RejectStartup(context.Background(), "migrate", runtimeinfo.Current(), os.Stderr)
		return err
	}
	return runMigrationProcess(context.Background(), environment, os.Stderr, applyMigrations)
}

func runMigrationProcess(ctx context.Context, environment config.Environment, output io.Writer, migrate func(context.Context, config.Configuration) error) error {
	input, err := config.Prepare(environment, config.Migrate)
	if err != nil {
		logging.RejectStartup(ctx, "migrate", runtimeinfo.Current(), output)
		return err
	}
	settings, err := config.Resolve(ctx, input, true)
	if err != nil {
		logging.RejectStartup(ctx, "migrate", runtimeinfo.Current(), output)
		return err
	}
	runtime := settings.Runtime()
	return logging.RunConfigured(ctx, "migrate", runtimeinfo.Current(), output, logging.Config{Level: runtime.LogLevel, Format: runtime.LogFormat}, func(ctx context.Context) error {
		return migrate(ctx, settings)
	})
}

func applyMigrations(parent context.Context, settings config.Configuration) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	runtime := settings.Runtime()
	store, err := postgres.Open(ctx, runtime.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer store.Close()
	applied, err := store.ApplyMigrations(ctx, runtime.MigrationsDir)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "applied %d migration(s)\n", applied); err != nil {
		return fmt.Errorf("write migration result: %w", err)
	}
	return nil
}
