package wiring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

type borrowedCleanupDiscovery struct {
	ssoDiscoveryWiringFake
	closes int
}

func (d *borrowedCleanupDiscovery) Close() error { d.closes++; return nil }

func TestRuntimeCleanupGracefulRetainsBorrowedProvidersAndReleasesWriter(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	discovery := &borrowedCleanupDiscovery{}
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: PostgreSQL, Production: true, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations", SkipMigrations: true, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}, OIDC: discovery})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	root, cancel := context.WithCancel(t.Context())
	cancel()
	if err = runtime.CloseContext(root, time.Second); err != nil {
		t.Fatal("cleanup inherited canceled work context", err)
	}
	if err = runtime.CloseContext(root, time.Second); err != nil {
		t.Fatal("second cleanup changed outcome", err)
	}
	if discovery.closes != 0 {
		t.Fatal("runtime closed a borrowed provider")
	}
	if err = runtime.Postgres.CheckReadiness(t.Context()); err == nil {
		t.Fatal("owned PostgreSQL pool remained usable")
	}
	next, err := postgres.Open(t.Context(), pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	release, err := next.AcquireAPIWriterLease(t.Context())
	if err != nil {
		t.Fatal("graceful cleanup retained writer lock", err)
	}
	if err = release(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCleanupTimeoutKeepsWriterLeaseUntilProcessExit(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: PostgreSQL, Production: true, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations", SkipMigrations: true, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	uow, err := runtime.Postgres.BeginUnitOfWork(t.Context())
	if err != nil {
		runtime.Close()
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		_ = uow.Rollback(cleanup)
		<-runtime.cleanup.done
		// A real forced daemon exits. The fixture must instead release its own
		// connection explicitly after all assertions, so it cannot leak to tests.
		if err := runtime.lease(cleanup); err != nil {
			t.Error(err)
		}
		runtime.Postgres.Close()
	}()
	if err = runtime.CloseContext(t.Context(), 20*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("active database work did not bound cleanup", err)
	}
	if err = runtime.Postgres.CheckAPIWriterLease(t.Context()); err != nil {
		t.Fatal("forced cleanup released writer while work remained", err)
	}
	next, err := postgres.Open(t.Context(), pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if release, err := next.AcquireAPIWriterLease(t.Context()); err == nil {
		_ = release(t.Context())
		t.Fatal("forced cleanup admitted another writer")
	}
	if err = uow.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = runtime.CloseContext(t.Context(), time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("forced cleanup silently retried or hid failure", err)
	}
	if release, err := next.AcquireAPIWriterLease(t.Context()); err == nil {
		_ = release(t.Context())
		t.Fatal("late cleanup released writer after timeout")
	}
}

func TestRuntimeCleanupPartialStartupReleasesWriter(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var providers OwnedResources
	closes := 0
	providers.Add("provider", func(context.Context) error { closes++; return nil })
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: PostgreSQL, Production: true, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations", SkipMigrations: true, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: file}, CloseOwnedProviders: providers.CloseWithin})
	if err == nil || runtime != nil {
		t.Fatal("partial startup unexpectedly succeeded", err)
	}
	if err = providers.Close(t.Context(), time.Second); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatal("partial startup leaked or double-closed provider", closes)
	}
	next, err := postgres.Open(t.Context(), pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	release, err := next.AcquireAPIWriterLease(t.Context())
	if err != nil {
		t.Fatal("partial startup leaked writer lease", err)
	}
	if err = release(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeOwnedProviderCleanupSharesBudgetBeforeWriterRelease(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	var providers OwnedResources
	var runtime *Runtime
	var providerDeadline time.Time
	var order []string
	providers.Add("provider", func(ctx context.Context) error {
		providerDeadline, _ = ctx.Deadline()
		if time.Until(providerDeadline) > time.Second {
			t.Error("provider cleanup reset runtime budget")
		}
		if err := runtime.Postgres.CheckAPIWriterLease(ctx); err != nil {
			t.Error("provider cleanup ran after writer release", err)
		}
		order = append(order, "provider")
		return nil
	})
	var err error
	runtime, err = OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: PostgreSQL, Production: true, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations", SkipMigrations: true, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}, CloseOwnedProviders: providers.CloseWithin})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	release := runtime.lease
	runtime.lease = func(ctx context.Context) error {
		deadline, _ := ctx.Deadline()
		if !deadline.Equal(providerDeadline) {
			t.Error("lease cleanup reset budget")
		}
		order = append(order, "writer")
		return release(ctx)
	}
	if err = runtime.CloseContext(t.Context(), time.Second); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "provider" || order[1] != "writer" {
		t.Fatal("runtime cleanup dependency order incorrect", order)
	}
	if err = runtime.Postgres.CheckReadiness(t.Context()); err == nil {
		t.Fatal("runtime left owned database open")
	}
}

func TestRuntimeCleanupClosesFactoryOwnedObjectTransport(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	closed := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: Worker, Profile: PostgreSQL, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations", SkipMigrations: true, ObjectStore: ObjectStoreConfig{Backend: "s3", Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "evidence", Region: "us-east-1", AccessKeyID: "access", SecretAccessKey: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err = runtime.CloseContext(t.Context(), time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("runtime did not close owned object-store connection")
	}
}

type borrowedCleanupObjects struct{ closes int }

func (*borrowedCleanupObjects) Put(context.Context, app.Object) error { return nil }
func (*borrowedCleanupObjects) Get(context.Context, string) (app.Object, error) {
	return app.Object{}, nil
}
func (o *borrowedCleanupObjects) Close() error { o.closes++; return nil }

func TestRuntimeCleanupNeverInfersOwnershipFromBorrowedObjectPort(t *testing.T) {
	objects := &borrowedCleanupObjects{}
	runtime := &Runtime{Objects: objects}
	if err := runtime.CloseContext(t.Context(), time.Second); err != nil {
		t.Fatal(err)
	}
	if objects.closes != 0 {
		t.Fatal("runtime closed borrowed object port")
	}
}
