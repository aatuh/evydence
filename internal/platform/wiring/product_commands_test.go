package wiring

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestProductCommandsUseFocusedRepositoriesInsideIdempotencyTransaction(t *testing.T) {
	ctx := context.Background()
	memory := app.NewMemoryUnitOfWorkFactory()
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	if err := app.ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories app.Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_product", Name: "Product Tenant", CreatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildProductCommands(memory)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "ten_product", KeyID: "key_product", Scopes: []string{"product:write"}}
	idempotency := app.IdempotencyUnitOfWork{Transactions: memory, Now: func() time.Time { return now }}
	runs := 0
	create := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		runs++
		product, err := commands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: "Product", Slug: "product"})
		return 201, product, err
	}
	status, response, err := idempotency.WithBody(ctx, actor, "POST", "/v1/products", "product-key", []byte(`{"name":"Product"}`), create)
	if err != nil || status != 201 || response == nil {
		t.Fatalf("focused create status=%d response=%#v err=%v", status, response, err)
	}
	if _, _, err := idempotency.WithBody(ctx, actor, "POST", "/v1/products", "product-key", []byte(`{"name":"Product"}`), create); err != nil || runs != 1 {
		t.Fatalf("replay runs=%d err=%v", runs, err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Products) != 1 || len(snapshot.Idempotency) != 1 || len(snapshot.AuditEntries[actor.TenantID]) != 1 {
		t.Fatalf("focused atomic state products=%d idempotency=%d audit=%d err=%v", len(snapshot.Products), len(snapshot.Idempotency), len(snapshot.AuditEntries[actor.TenantID]), err)
	}
	limited := identitydomain.Actor{
		TenantID: actor.TenantID, UserID: "usr_limited", Scopes: []string{"product:write"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_other", Scopes: []string{"product:write"}}},
	}
	if _, err := commands.CreateProduct(ctx, limited, releaseapp.CreateProductInput{Name: "Denied", Slug: "denied"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("product-scoped human grant created tenant-wide product: %v", err)
	}
}

func TestPostgresCatalogCommandsCommitProductProjectReleaseAuditAndReplayWithoutLedger(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("evydence_product_commands_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	runtime, err := OpenRuntime(ctx, RuntimeConfig{
		Process: API, Profile: PostgreSQL, DatabaseURL: parsed.String(), LoadMode: "relational_only",
		MigrationsDir: "../../../migrations", ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	now := time.Now().UTC()
	if err := app.ExecuteUnitOfWork(ctx, runtime.Postgres, func(ctx context.Context, repositories app.Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_product_live", Name: "Product Tenant", CreatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildProductCommands(runtime.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "ten_product_live", KeyID: "key_product_live", Scopes: []string{"product:write", "project:write", "release:write"}}
	idempotency := app.IdempotencyUnitOfWork{Transactions: runtime.Postgres}
	runs := 0
	create := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		runs++
		product, err := commands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: "Live", Slug: "live"})
		return 201, product, err
	}
	status, response, err := idempotency.WithBody(ctx, actor, "POST", "/v1/products", "live-product", []byte(`{"name":"Live"}`), create)
	if err != nil || status != 201 {
		t.Fatalf("live create status=%d response=%#v err=%v", status, response, err)
	}
	product := response.(releasedomain.Product)
	stored, err := runtime.Postgres.GetProduct(ctx, actor.TenantID, product.ID)
	if err != nil || stored.ID != product.ID || stored.Slug != "live" {
		t.Fatalf("durable product=%#v err=%v", stored, err)
	}
	var auditCount, replayCount int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+quotedSchema+".audit_chain_entries WHERE tenant_id = $1", actor.TenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count durable audit: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+quotedSchema+".idempotency_records WHERE tenant_id = $1 AND state = 'completed'", actor.TenantID).Scan(&replayCount); err != nil {
		t.Fatalf("count durable replay: %v", err)
	}
	if auditCount != 1 || replayCount != 1 {
		t.Fatalf("product commit audit=%d replay=%d, want one each", auditCount, replayCount)
	}
	if _, _, err := idempotency.WithBody(ctx, actor, "POST", "/v1/products", "live-product", []byte(`{"name":"Live"}`), create); err != nil || runs != 1 {
		t.Fatalf("durable replay runs=%d err=%v", runs, err)
	}
	projects, err := BuildProjectCommands(runtime.Postgres, runtime.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	projectRuns := 0
	createProject := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		projectRuns++
		project, err := projects.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: product.ID, Name: "Child"})
		return 201, project, err
	}
	status, response, err = idempotency.WithBody(ctx, actor, "POST", "/v1/projects", "live-project", []byte(`{"name":"Child"}`), createProject)
	if err != nil || status != 201 {
		t.Fatalf("live project status=%d response=%#v err=%v", status, response, err)
	}
	project := response.(releasedomain.Project)
	storedProject, err := runtime.Postgres.GetProject(ctx, actor.TenantID, project.ID)
	if err != nil || storedProject.ProductID != product.ID || storedProject.Name != "Child" {
		t.Fatalf("durable project=%#v err=%v", storedProject, err)
	}
	if _, err := runtime.Postgres.GetProject(ctx, "ten_other", project.ID); !errors.Is(err, releasequery.ErrNotFound) {
		t.Fatalf("foreign tenant project read err=%v, want not found", err)
	}
	if _, _, err := idempotency.WithBody(ctx, actor, "POST", "/v1/projects", "live-project", []byte(`{"name":"Child"}`), createProject); err != nil || projectRuns != 1 {
		t.Fatalf("durable project replay runs=%d err=%v", projectRuns, err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+quotedSchema+".audit_chain_entries WHERE tenant_id = $1", actor.TenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count catalog audits: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+quotedSchema+".idempotency_records WHERE tenant_id = $1 AND state = 'completed'", actor.TenantID).Scan(&replayCount); err != nil {
		t.Fatalf("count catalog replays: %v", err)
	}
	if auditCount != 2 || replayCount != 2 {
		t.Fatalf("catalog commits audit=%d replay=%d, want two each", auditCount, replayCount)
	}
	releases, err := BuildReleaseCommands(runtime.Postgres, runtime.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	releaseRuns := 0
	createRelease := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		releaseRuns++
		release, err := releases.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: product.ID, Version: "1.0.0"})
		return 201, release, err
	}
	status, response, err = idempotency.WithBody(ctx, actor, "POST", "/v1/releases", "live-release", []byte(`{"version":"1.0.0"}`), createRelease)
	if err != nil || status != 201 {
		t.Fatalf("live release status=%d response=%#v err=%v", status, response, err)
	}
	release := response.(releasedomain.Release)
	storedRelease, err := runtime.Postgres.GetRelease(ctx, actor.TenantID, release.ID)
	if err != nil || storedRelease.ProductID != product.ID || storedRelease.Version != "1.0.0" {
		t.Fatalf("durable release=%#v err=%v", storedRelease, err)
	}
	if _, err := runtime.Postgres.GetRelease(ctx, "ten_other", release.ID); !errors.Is(err, releasequery.ErrNotFound) {
		t.Fatalf("foreign tenant release read err=%v, want not found", err)
	}
	if _, _, err := idempotency.WithBody(ctx, actor, "POST", "/v1/releases", "live-release", []byte(`{"version":"1.0.0"}`), createRelease); err != nil || releaseRuns != 1 {
		t.Fatalf("durable release replay runs=%d err=%v", releaseRuns, err)
	}
	if _, err := releases.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: product.ID, Version: "1.0.0"}); !errors.Is(err, releaseapp.ErrConflict) {
		t.Fatalf("duplicate durable release version err=%v, want conflict", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+quotedSchema+".audit_chain_entries WHERE tenant_id = $1", actor.TenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count catalog audits: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+quotedSchema+".idempotency_records WHERE tenant_id = $1 AND state = 'completed'", actor.TenantID).Scan(&replayCount); err != nil {
		t.Fatalf("count catalog replays: %v", err)
	}
	if auditCount != 3 || replayCount != 3 {
		t.Fatalf("catalog commits audit=%d replay=%d, want three each", auditCount, replayCount)
	}
}
