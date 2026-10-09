package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresProductCreationUsesSlugExistenceAndAtomicReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Products'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('large','tenant',repeat('x',9000000),'large')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildProductCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"product:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"product:write"}}}}
	if v, err := commands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: "Duplicate", Slug: "large"}); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
		t.Fatal("existing slug did not conflict", v, err)
	}
	denied := actor
	denied.ResourceGrants = nil
	if v, err := commands.CreateProduct(ctx, denied, releaseapp.CreateProductInput{Name: "Denied", Slug: "new"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("removed grant created product", v, err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "large", Scopes: []string{"product:write"}}}
	if v, err := commands.CreateProduct(ctx, denied, releaseapp.CreateProductInput{Name: "Denied", Slug: "new"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("product grant created tenant-level resource", v, err)
	}
	for _, value := range []string{"bad\x00text", string([]byte{255}), strings.Repeat("界", 22000)} {
		for _, in := range []releaseapp.CreateProductInput{{Name: value, Slug: "new"}, {Name: "Product", Slug: value}} {
			if v, err := commands.CreateProduct(ctx, actor, in); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" {
				t.Fatal("unsupported product storage text accepted", v.ID, err)
			}
		}
	}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if counts() != [3]int{1, 0, 0} {
		t.Fatal("denied/invalid product committed effects", counts())
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	rollback := errors.New("rollback product creation")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, _ app.Repositories) (int, any, error) {
			runs++
			p, err := commands.CreateProduct(txCtx, actor, releaseapp.CreateProductInput{Name: " Product ", Slug: " product "})
			if err != nil {
				return 0, nil, err
			}
			if p.Name != "Product" || p.Slug != "product" || p.TenantID != "tenant" || p.CreatedAt.Nanosecond()%1000 != 0 || p.CreatedAt.Location() != time.UTC {
				return 0, nil, errors.New("product metadata/time changed")
			}
			if _, err := commands.CreateProduct(txCtx, actor, releaseapp.CreateProductInput{Name: "Pending duplicate", Slug: "product"}); !errors.Is(err, releaseapp.ErrConflict) {
				return 0, nil, errors.New("pending slug invisible")
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, p, nil
		}
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "rollback", []byte(`{}`), run(true)); !errors.Is(err, rollback) || counts() != [3]int{1, 0, 0} {
		t.Fatal("product rollback leaked effects", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "success", []byte(`{}`), run(false)); err != nil || counts() != [3]int{2, 1, 1} {
		t.Fatal("product compound commit failed", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "success", []byte(`{}`), run(false)); err != nil || runs != 2 || counts() != [3]int{2, 1, 1} {
		t.Fatal("product replay repeated command", err, runs, counts())
	}
	other := identitydomain.Actor{TenantID: "other", KeyID: "key", Scopes: []string{"product:write"}}
	if v, err := commands.CreateProduct(ctx, other, releaseapp.CreateProductInput{Name: "Other product", Slug: "product"}); err != nil || v.TenantID != "other" || counts() != [3]int{3, 2, 1} {
		t.Fatal("slug uniqueness crossed tenant boundary", v, err, counts())
	}
}

func TestPostgresProductCreationSerializesAbsentSlugs(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Concurrent products')`); err != nil {
		t.Fatal(err)
	}
	one, err := BuildProductCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildProductCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"product:write"}}
	type result struct {
		p   releasedomain.Product
		err error
	}
	results := make(chan result, 8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			<-start
			commands := one
			if i%2 != 0 {
				commands = two
			}
			p, err := commands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: "Concurrent", Slug: "concurrent"})
			results <- result{p, err}
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err == nil && r.p.ID != "" && r.p.Slug == "concurrent" {
			winners++
		} else if !errors.Is(r.err, releaseapp.ErrConflict) || r.p.ID != "" {
			t.Fatal("unexpected slug race result", r.p.ID, r.err)
		}
	}
	var products, audits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM audit_chain_entries)`).Scan(&products, &audits); err != nil || winners != 1 || products != 1 || audits != 1 {
		t.Fatal("slug race duplicated effects", winners, products, audits, err)
	}
}
