package main

import (
	"context"
	"io"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/wiring"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func runAPIProcess(ctx context.Context, environment config.Environment, output io.Writer, start func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error) error {
	input, err := config.Prepare(environment, config.API)
	if err != nil {
		logging.RejectStartup(ctx, "api", runtimeinfo.Current(), output)
		return err
	}
	settings, err := config.Resolve(ctx, input, true)
	if err != nil {
		logging.RejectStartup(ctx, "api", runtimeinfo.Current(), output)
		return err
	}
	runtime := settings.Runtime()
	database, err := postgres.PreparePoolConfig(ctx, runtime.DatabaseURL.Reveal())
	if err != nil {
		logging.RejectStartup(ctx, "api", runtimeinfo.Current(), output)
		return err
	}
	return logging.RunConfigured(ctx, "api", runtimeinfo.Current(), output, logging.Config{Level: runtime.LogLevel, Format: runtime.LogFormat}, func(ctx context.Context) error {
		return start(ctx, settings, database)
	})
}

func apiRuntimeConfigFromSettings(settings config.Configuration, database postgres.PreparedPoolConfig) wiring.RuntimeConfig {
	runtime, api, storage := settings.Runtime(), settings.API(), settings.Storage()
	return wiring.RuntimeConfig{
		Process: wiring.API, Profile: wiring.Profile(runtime.Profile), Production: settings.Production(),
		WorkerOwnedParsers: api.WorkerOwnedParserSideEffects, DatabaseURL: runtime.DatabaseURL.Reveal(),
		DatabaseConfiguration: database, LoadMode: runtime.PostgresLoadMode, MigrationsDir: runtime.MigrationsDir,
		SkipMigrations: runtime.SkipMigrations, CleanupTimeout: runtime.ShutdownCleanupTimeout,
		SessionPolicy: sessionPolicyFromSettings(api),
		ObjectStore:   wiring.ObjectStoreConfigFromSettings(storage),
	}
}
