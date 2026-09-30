package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type memoryProjectParentReader struct{ factory app.UnitOfWorkFactory }

func (r memoryProjectParentReader) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	var product releasedomain.Product
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repositories app.Repositories) error {
		value, err := repositories.ReleaseCatalog.GetProduct(ctx, tenantID, id)
		if err != nil {
			return err
		}
		product = releasedomain.Product{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug, CreatedAt: value.CreatedAt}
		return nil
	})
	return product, err
}

func TestProjectCommandsReadDirectlyCreatedProductWithoutLedger(t *testing.T) {
	ctx := context.Background()
	memory := app.NewMemoryUnitOfWorkFactory()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if err := app.ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories app.Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_catalog", Name: "Catalog", CreatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	products, err := BuildProductCommands(memory)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "ten_catalog", KeyID: "key_catalog", Scopes: []string{"product:write", "project:write"}}
	product, err := products.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: "Parent", Slug: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	projects, err := BuildProjectCommands(memoryProjectParentReader{factory: memory}, memory)
	if err != nil {
		t.Fatal(err)
	}
	idempotency := app.IdempotencyUnitOfWork{Transactions: memory, Now: func() time.Time { return now }}
	runs := 0
	create := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		runs++
		project, err := projects.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: product.ID, Name: "Child"})
		return 201, project, err
	}
	if _, _, err := idempotency.WithBody(ctx, actor, "POST", "/v1/projects", "project-key", []byte(`{"name":"Child"}`), create); err != nil {
		t.Fatalf("direct project create: %v", err)
	}
	if _, _, err := idempotency.WithBody(ctx, actor, "POST", "/v1/projects", "project-key", []byte(`{"name":"Child"}`), create); err != nil || runs != 1 {
		t.Fatalf("direct project replay runs=%d err=%v", runs, err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Products) != 1 || len(snapshot.Projects) != 1 || len(snapshot.Idempotency) != 1 || len(snapshot.AuditEntries[actor.TenantID]) != 2 {
		t.Fatalf("direct catalog state products=%d projects=%d replays=%d audits=%d err=%v", len(snapshot.Products), len(snapshot.Projects), len(snapshot.Idempotency), len(snapshot.AuditEntries[actor.TenantID]), err)
	}
	limited := identitydomain.Actor{TenantID: actor.TenantID, UserID: "usr_limited", Scopes: []string{"project:write"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_other", Scopes: []string{"project:write"}}}}
	if _, err := projects.CreateProject(ctx, limited, releaseapp.CreateProjectInput{ProductID: product.ID, Name: "Denied"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign product grant created project: %v", err)
	}
	foreign := domain.Actor{TenantID: "ten_other", KeyID: "key_other", Scopes: []string{"project:write"}}
	if _, err := projects.CreateProject(ctx, foreign, releaseapp.CreateProjectInput{ProductID: product.ID, Name: "Denied"}); !errors.Is(err, releaseapp.ErrNotFound) {
		t.Fatalf("foreign tenant saw parent: %v", err)
	}
}
