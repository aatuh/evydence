package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type catalogGuardFake struct {
	tenantLocks, productReads int
	denied                    bool
	parent                    CatalogCreationProduct
}

func (f *catalogGuardFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.denied && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *catalogGuardFake) LockCatalogCreationTenant(context.Context, string) error {
	f.tenantLocks++
	return nil
}
func (f *catalogGuardFake) ReadCatalogCreationProduct(context.Context, string, string) (CatalogCreationProduct, error) {
	f.productReads++
	return f.parent, nil
}
func (f *catalogGuardFake) ExecuteProduct(ctx context.Context, fn func(context.Context, ProductTransaction) error) error {
	return fn(ctx, f)
}
func (f *catalogGuardFake) ExecuteProject(ctx context.Context, fn func(context.Context, ProjectTransaction) error) error {
	return fn(ctx, f)
}
func (f *catalogGuardFake) ExecuteReleaseCreation(ctx context.Context, fn func(context.Context, ReleaseCreationTransaction) error) error {
	return fn(ctx, f)
}
func (*catalogGuardFake) ProductSlugExists(context.Context, string, string) (bool, error) {
	panic("guard read slug uniqueness")
}
func (*catalogGuardFake) ReleaseVersionExists(context.Context, string, string, string) (bool, error) {
	panic("guard read release uniqueness")
}
func (*catalogGuardFake) ReadProductCoordinates(context.Context, string, string) (ProductCoordinates, error) {
	panic("guard read parent slug")
}
func (*catalogGuardFake) InsertProduct(context.Context, releasedomain.Product) error {
	panic("guard wrote product")
}
func (*catalogGuardFake) InsertProject(context.Context, releasedomain.Project) error {
	panic("guard wrote project")
}
func (*catalogGuardFake) InsertRelease(context.Context, releasedomain.Release) error {
	panic("guard wrote release")
}
func (*catalogGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard wrote audit")
}

func TestCatalogCreationGuardsNeverReadMetadataUniquenessOrGenerateWrites(t *testing.T) {
	f := &catalogGuardFake{parent: CatalogCreationProduct{ID: "product", TenantID: "tenant"}}
	clock := application.ClockFunc(func() time.Time { panic("guard used clock") })
	ids := application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })
	p, err := NewProductCommands(ProductCommandConfig{Authorizer: f, Transactions: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewProjectCommands(ProjectCommandConfig{Reader: f, Authorizer: f, Transactions: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReleaseCommands(ReleaseCommandConfig{Reader: f, Authorizer: f, Transactions: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{ScopeProductWrite, ScopeProjectWrite, ScopeReleaseWrite}}
	checks := []func() error{func() error {
		return p.AuthorizeProductCreation(t.Context(), a, CreateProductInput{Name: "Product", Slug: "slug"})
	}, func() error {
		return j.AuthorizeProjectCreation(t.Context(), a, CreateProjectInput{ProductID: "product", Name: "Project"})
	}, func() error {
		return r.AuthorizeReleaseCreation(t.Context(), a, CreateReleaseInput{ProductID: "product", Version: "1"})
	}}
	for _, check := range checks {
		if err := check(); err != nil {
			t.Fatal(err)
		}
	}
	if f.tenantLocks != 3 || f.productReads != 2 {
		t.Fatal("catalog guard reached incorrect ownership points", f)
	}
	f.denied = true
	for _, check := range checks {
		if err := check(); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("denied grant retained replay", err)
		}
	}
	f.denied = false
	f.parent.TenantID = "other"
	for _, check := range checks[1:] {
		if err := check(); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign parent retained replay", err)
		}
	}
}
