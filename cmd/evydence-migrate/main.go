package main

import (
	"context"
	"errors"
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

func applyMigrations(parent context.Context, settings config.Configuration) (resultErr error) {
	runtime := settings.Runtime()
	ctx, cancel := context.WithTimeout(parent, runtime.MigrationTimeout)
	defer cancel()
	var plan postgres.MigrationPlan
	var err error
	if runtime.MigrationTarget != "" {
		plan, err = postgres.PrepareMigrationPlan(ctx, runtime.MigrationsDir, runtime.MigrationTarget, runtime.MigrationChecksumsFile)
		if err != nil {
			return err
		}
		if runtime.MigrationAllowLegacyHistory {
			plan = plan.WithLegacyHistory()
		}
	}
	prepared, err := postgres.PreparePoolConfig(ctx, runtime.DatabaseURL.Reveal())
	if err == nil {
		err = prepared.RequirePoolCapacity(2)
	}
	if err != nil {
		return err
	}
	store, err := postgres.OpenPrepared(ctx, prepared, postgres.StoreOptions{})
	if err != nil {
		return err
	}
	defer store.Close()
	release, err := store.AcquireAPIWriterLease(ctx)
	if err != nil {
		return err
	}
	defer func() {
		timeout := runtime.ShutdownCleanupTimeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), timeout)
		defer stop()
		resultErr = errors.Join(resultErr, release(cleanup))
	}()
	var applied int
	if plan.TargetVersion() != "" {
		applied, err = store.ApplyMigrationPlan(ctx, plan)
	} else {
		applied, err = store.ApplyMigrations(ctx, runtime.MigrationsDir)
	}
	if err != nil {
		switch {
		case errors.Is(err, postgres.ErrMigrationLegacyHistory):
			logging.Emit(ctx, logging.MigrationLegacyHistoryRequired, logging.Fields{Result: logging.Failed})
		case errors.Is(err, postgres.ErrMigrationChecksum):
			logging.Emit(ctx, logging.MigrationChecksumMismatch, logging.Fields{Result: logging.Failed})
		}
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "applied %d migration(s)\n", applied); err != nil {
		return fmt.Errorf("write migration result: %w", err)
	}
	return nil
}
