package wiring

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

func runtimeAdapterError(stage string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", stage, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", stage, context.DeadlineExceeded)
	}
	return fmt.Errorf("%s: %s", stage, redaction.Error(err))
}

// RuntimeConfig is the validated process-wide infrastructure selection. A
// caller supplies secrets only to open adapters; Runtime does not copy them
// into plain config fields or include them verbatim in validation errors.
type RuntimeConfig struct {
	Process        Process
	Profile        Profile
	Production     bool
	DatabaseURL    string
	LoadMode       string
	MigrationsDir  string
	SkipMigrations bool
	ObjectStore    ObjectStoreConfig
}

// Runtime owns the shared API/worker infrastructure lifetime. The API's
// transitional Ledger and the worker's job processor compose on these ports.
type Runtime struct {
	Process    Process
	Profile    Profile
	Production bool
	Postgres   *postgres.Store
	Objects    app.ObjectStore
	lease      func()
	closed     sync.Once
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.closed.Do(func() {
		if r.lease != nil {
			r.lease()
		}
		if r.Postgres != nil {
			r.Postgres.Close()
		}
	})
}

// OpenRuntime applies profile, production, migration, and object-store rules
// consistently for the API and worker. Profile, load-mode, and backend
// selection fail before opening durable resources; partial startup releases
// the writer lease and pool.
func OpenRuntime(ctx context.Context, config RuntimeConfig) (_ *Runtime, err error) {
	if ctx == nil {
		return nil, errors.New("runtime context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := ResolveRuntimeProfile(string(config.Profile), config.Production, config.DatabaseURL, config.Process)
	if err != nil {
		return nil, err
	}
	backend := strings.ToLower(strings.TrimSpace(config.ObjectStore.Backend))
	if profile == LocalMemory {
		if backend != "" && backend != "filesystem" {
			return nil, errors.New("EVYDENCE_RUNTIME_PROFILE=local_memory supports only EVYDENCE_OBJECT_STORE=filesystem")
		}
		runtime := &Runtime{Process: config.Process, Profile: profile, Production: config.Production}
		if backend != "" {
			objects, _, err := OpenObjectStore(ctx, config.ObjectStore)
			if err != nil {
				return nil, runtimeAdapterError("open local object store", err)
			}
			runtime.Objects = objects
		}
		return runtime, nil
	}
	loadMode, err := postgres.ResolveLoadMode(config.LoadMode, config.Production)
	if err != nil {
		return nil, errors.New("invalid EVYDENCE_POSTGRES_LOAD_MODE")
	}
	if config.Production {
		if err := postgres.ValidateProductionLoadMode(loadMode); err != nil {
			return nil, err
		}
	}
	if backend != "" && backend != "file" && backend != "filesystem" && backend != "s3" && backend != "minio" {
		return nil, errors.New("unsupported EVYDENCE_OBJECT_STORE")
	}
	store, err := postgres.OpenWithOptions(ctx, config.DatabaseURL, postgres.StoreOptions{LoadMode: loadMode, DisableSnapshotWrites: config.Production})
	if err != nil {
		return nil, runtimeAdapterError("open PostgreSQL runtime", err)
	}
	runtime := &Runtime{Process: config.Process, Profile: profile, Production: config.Production, Postgres: store}
	defer func() {
		if err != nil {
			runtime.Close()
		}
	}()
	if config.Production && config.Process == API {
		runtime.lease, err = store.AcquireAPIWriterLease(ctx)
		if err != nil {
			return nil, runtimeAdapterError("acquire API writer lease", err)
		}
	}
	migrationsDir := strings.TrimSpace(config.MigrationsDir)
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	migrateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if config.SkipMigrations {
		if err = store.RequireNoPendingMigrations(migrateCtx, migrationsDir); err != nil {
			return nil, runtimeAdapterError("check migrations", err)
		}
	} else if _, err = store.ApplyMigrations(migrateCtx, migrationsDir); err != nil {
		return nil, runtimeAdapterError("apply migrations", err)
	}
	runtime.Objects, _, err = OpenObjectStore(ctx, config.ObjectStore)
	if err != nil {
		return nil, runtimeAdapterError("open object store", err)
	}
	return runtime, nil
}
