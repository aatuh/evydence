package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresReleaseCreationReadsBoundedPendingProductAndVersion(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Release boundary'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildReleaseCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"release:write"}}}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	rollback := errors.New("rollback pending release parent")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			runs++
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: "product", TenantID: "tenant", Name: strings.Repeat("x", 9000000), Slug: "product", CreatedAt: time.Now().UTC()}); err != nil {
				return 0, nil, err
			}
			release, err := commands.CreateRelease(txCtx, actor, releaseapp.CreateReleaseInput{ProductID: "product", Version: " 1.0.0 "})
			if err != nil {
				return 0, nil, err
			}
			if release.ProductID != "product" || release.Version != "1.0.0" || release.TenantID != "tenant" || release.State.String() != "draft" || release.Revision != 1 {
				return 0, nil, errors.New("release fields changed")
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, release, nil
		}
	}
	counts := func() [4]int {
		t.Helper()
		var n [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM releases),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/releases", "pending-release-rollback", []byte("{}"), run(true)); !errors.Is(err, rollback) || counts() != [4]int{} {
		t.Fatal("pending parent or compound rollback failed", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/releases", "pending-release-success", []byte("{}"), run(false)); err != nil || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("pending release parent was not visible", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/releases", "pending-release-success", []byte("{}"), run(false)); err != nil || runs != 2 || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("release replay repeated compound command", err, runs, counts())
	}
	if v, err := commands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: "product", Version: "1.0.0"}); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
		t.Fatal("duplicate product version accepted", v.ID, err)
	}
	foreign := actor
	foreign.TenantID = "other"
	if v, err := commands.CreateRelease(ctx, foreign, releaseapp.CreateReleaseInput{ProductID: "product", Version: "2"}); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" {
		t.Fatal("foreign parent visible", v.ID, err)
	}
	denied := actor
	denied.ResourceGrants = nil
	if v, err := commands.CreateRelease(ctx, denied, releaseapp.CreateReleaseInput{ProductID: "product", Version: "2"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("ungranted release parent accepted", v.ID, err)
	}
	for _, version := range []string{"bad\x00version", string([]byte{255}), strings.Repeat("界", 22000)} {
		if v, err := commands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: "product", Version: version}); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" {
			t.Fatal("unsupported release storage text accepted", v.ID, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE products SET slug=repeat('界',22000)WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	if v, err := commands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: "product", Version: "2"}); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("oversized parent returned or effects committed", v.ID, err, counts())
	}
}

func TestPostgresReleaseCreationSerializesAbsentProductVersion(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Concurrent release');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('second','tenant','Second','second')`); err != nil {
		t.Fatal(err)
	}
	one, err := BuildReleaseCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildReleaseCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"release:write"}}
	type result struct {
		v   releasedomain.Release
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
			v, err := commands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: "product", Version: "1"})
			results <- result{v, err}
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err == nil && r.v.ID != "" && r.v.Version == "1" {
			winners++
		} else if !errors.Is(r.err, releaseapp.ErrConflict) || r.v.ID != "" {
			t.Fatal("unexpected version race result", r.v.ID, r.err)
		}
	}
	var releases, audits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM releases),(SELECT count(*)FROM audit_chain_entries)`).Scan(&releases, &audits); err != nil || winners != 1 || releases != 1 || audits != 1 {
		t.Fatal("version race duplicated effects", winners, releases, audits, err)
	}
	if v, err := two.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: "second", Version: "1"}); err != nil || v.ProductID != "second" || v.Version != "1" {
		t.Fatal("version uniqueness crossed product boundary", v, err)
	}
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM releases),(SELECT count(*)FROM audit_chain_entries)`).Scan(&releases, &audits); err != nil || releases != 2 || audits != 2 {
		t.Fatal("second product effects", releases, audits, err)
	}
}
