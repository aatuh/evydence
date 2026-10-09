package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// This transaction has no full-product reader: slug uniqueness needs one bit.
type productSlugTransaction struct {
	exists       bool
	denied       error
	product      releasedomain.Product
	audit        []application.AuditEvent
	request      application.AuthorizationRequest
	tenant, slug string
}

func (t *productSlugTransaction) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	t.request = r
	return t.denied
}
func (t *productSlugTransaction) ProductSlugExists(_ context.Context, tenant, slug string) (bool, error) {
	t.tenant, t.slug = tenant, slug
	return t.exists, nil
}
func (t *productSlugTransaction) InsertProduct(_ context.Context, p releasedomain.Product) error {
	t.product = p
	return nil
}
func (t *productSlugTransaction) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	t.audit = append(t.audit, e)
	return application.AuditReceipt{ID: e.ID}, nil
}
func (t *productSlugTransaction) ExecuteProduct(ctx context.Context, fn func(context.Context, ProductTransaction) error) error {
	return fn(ctx, t)
}

func TestProductCommandsNeedOnlySlugExistenceAndTransactionAuthorization(t *testing.T) {
	fixture := newServiceFixture(t)
	tx := &productSlugTransaction{}
	commands, err := NewProductCommands(ProductCommandConfig{Authorizer: fixture.authorizer, Transactions: tx, Clock: application.ClockFunc(func() time.Time { return fixture.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_slug" })})
	if err != nil {
		t.Fatal(err)
	}
	p, err := commands.CreateProduct(t.Context(), fixture.actor, CreateProductInput{Name: " Product ", Slug: " product "})
	want := releasedomain.Product{ID: "prod_slug", TenantID: fixture.actor.TenantID, Name: "Product", Slug: "product", CreatedAt: fixture.now}
	if err != nil || !reflect.DeepEqual(p, want) || !reflect.DeepEqual(tx.product, want) || tx.tenant != fixture.actor.TenantID || tx.slug != "product" || len(tx.audit) != 1 || tx.audit[0].SubjectID != p.ID || tx.audit[0].EntryType != "product.created" || !tx.audit[0].OccurredAt.Equal(p.CreatedAt) {
		t.Fatal("narrow product command changed metadata/audit", p, tx, err)
	}
	if tx.request.Scope != ScopeProductWrite || !tx.request.TenantWide || tx.request.ScopeOnly || tx.request.Resources != (application.ResourceReferences{}) {
		t.Fatal("product transaction authorization widened", tx.request)
	}
	tx.exists = true
	tx.product = releasedomain.Product{}
	tx.audit = nil
	if v, err := commands.CreateProduct(t.Context(), fixture.actor, CreateProductInput{Name: "Duplicate", Slug: "product"}); !errors.Is(err, ErrConflict) || v.ID != "" || tx.product.ID != "" || len(tx.audit) != 0 {
		t.Fatal("existing slug changed metadata or audit", v, tx, err)
	}
	tx.exists = false
	tx.denied = application.ErrForbidden
	tx.tenant = ""
	if v, err := commands.CreateProduct(t.Context(), fixture.actor, CreateProductInput{Name: "Denied", Slug: "product"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" || tx.product.ID != "" || len(tx.audit) != 0 || tx.tenant != "" {
		t.Fatal("revoked transaction grant read or wrote product", v, tx, err)
	}
}
