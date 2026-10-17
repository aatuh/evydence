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

func runWorkerProcess(ctx context.Context, environment config.Environment, output io.Writer, start func(context.Context, config.Configuration) error) error {
	return runWorkerRoleProcess(ctx, environment, config.Worker, output, start)
}

func runWorkerRoleProcess(ctx context.Context, environment config.Environment, role config.Role, output io.Writer, start func(context.Context, config.Configuration) error) error {
	input, err := config.Prepare(environment, role)
	if err != nil {
		logging.RejectStartup(ctx, "worker", runtimeinfo.Current(), output)
		return err
	}
	settings, err := config.Resolve(ctx, input, true)
	if err != nil {
		logging.RejectStartup(ctx, "worker", runtimeinfo.Current(), output)
		return err
	}
	runtime := settings.Runtime()
	return logging.RunConfigured(ctx, "worker", runtimeinfo.Current(), output, logging.Config{Level: runtime.LogLevel, Format: runtime.LogFormat}, func(ctx context.Context) error {
		return start(ctx, settings)
	})
}

func workerRuntimeConfigFromSettings(settings config.Configuration) wiring.RuntimeConfig {
	runtime, storage := settings.Runtime(), settings.Storage()
	return wiring.RuntimeConfig{
		Process: wiring.Worker, Profile: wiring.Profile(runtime.Profile), Production: settings.Production(),
		DatabaseURL: runtime.DatabaseURL.Reveal(), LoadMode: runtime.PostgresLoadMode,
		MigrationsDir: runtime.MigrationsDir, SkipMigrations: runtime.SkipMigrations, CleanupTimeout: runtime.ShutdownCleanupTimeout,
		ObjectStore: wiring.ObjectStoreConfig{
			Backend: storage.Kind, Directory: storage.Directory, Endpoint: storage.S3Endpoint,
			Bucket: storage.S3Bucket, Region: storage.S3Region, UseSSL: storage.S3UseSSL,
			AccessKeyID: storage.S3AccessKeyID.Reveal(), SecretAccessKey: storage.S3SecretAccessKey.Reveal(),
		},
	}
}

// Resolve the owned native driver boundary before opening any runtime resource.
// The resulting pool configuration is passed through instead of parsed again.
func prepareWorkerRuntime(ctx context.Context, settings config.Configuration) (wiring.RuntimeConfig, error) {
	runtime := workerRuntimeConfigFromSettings(settings)
	prepared, err := postgres.PreparePoolConfig(ctx, runtime.DatabaseURL)
	if err != nil {
		return wiring.RuntimeConfig{}, err
	}
	runtime.DatabaseConfiguration = prepared
	return runtime, nil
}
