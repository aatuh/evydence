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

func TestPostgresReleaseTransitionsSeePendingReleaseAndRollBackTogether(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Pending release')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildReleaseStateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	rollback := errors.New("rollback pending release transitions")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			runs++
			at := time.Now().UTC().Truncate(time.Microsecond)
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: "product", TenantID: "tenant", Name: strings.Repeat("x", 9000000), Slug: "product", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: "release", TenantID: "tenant", ProductID: "product", Version: "1.0.0", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			frozen, err := commands.FreezeRelease(txCtx, actor, "release", 1)
			if err != nil {
				return 0, nil, err
			}
			approved, err := commands.ApproveRelease(txCtx, actor, "release", 2)
			if err != nil {
				return 0, nil, err
			}
			if approved.ID != "release" || approved.TenantID != "tenant" || approved.ProductID != "product" || approved.Version != "1.0.0" || !approved.CreatedAt.Equal(at) || approved.State.String() != "approved" || approved.Revision != 3 || frozen.FrozenAt == nil || approved.FrozenAt == nil || !approved.FrozenAt.Equal(*frozen.FrozenAt) || approved.ApprovedAt == nil {
				return 0, nil, errors.New("release transition changed immutable fields or lifecycle")
			}
			if fail {
				return 0, nil, rollback
			}
			return 200, approved, nil
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
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-release", "rollback", nil, run(true)); !errors.Is(err, rollback) || counts() != [4]int{} {
		t.Fatal("pending release transition or compound rollback failed", err, counts())
	}
	if status, response, err := executor.WithBody(ctx, actor, "POST", "/pending-release", "success", nil, run(false)); err != nil || status != 200 || response.(releasedomain.Release).Revision != 3 || counts() != [4]int{1, 1, 2, 1} {
		t.Fatal("pending release transitions not committed", status, err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-release", "success", nil, run(false)); err != nil || runs != 2 || counts() != [4]int{1, 1, 2, 1} {
		t.Fatal("replay repeated pending transitions", err, runs, counts())
	}
}

func TestPostgresReleaseTransitionsBoundReadsAndSerializeRevision(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Transitions'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product','1.0.0','draft',1)`); err != nil {
		t.Fatal(err)
	}
	one, err := BuildReleaseStateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildReleaseStateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	foreign := actor
	foreign.TenantID = "other"
	denied := actor
	denied.ResourceGrants = nil
	wrongGrant := actor
	wrongGrant.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "product", Scopes: []string{"release:write"}}}
	for _, tc := range []struct {
		actor identitydomain.Actor
		want  error
	}{{foreign, releaseapp.ErrNotFound}, {denied, application.ErrForbidden}, {wrongGrant, application.ErrForbidden}} {
		if v, err := one.FreezeRelease(ctx, tc.actor, "release", 1); !errors.Is(err, tc.want) || v.ID != "" {
			t.Fatal("release isolation/grants failed", v.ID, err)
		}
	}
	for _, id := range []string{"bad\x00id", string([]byte{255}), strings.Repeat("x", 1025)} {
		if v, err := one.FreezeRelease(ctx, actor, id, 1); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" {
			t.Fatal("invalid release ID accepted", v.ID, err)
		}
	}
	for _, change := range []string{`UPDATE releases SET version=repeat('界',22000)`, `UPDATE products SET slug=repeat('界',22000)`} {
		if _, err := pool.Exec(ctx, change); err != nil {
			t.Fatal(err)
		}
		if v, err := one.FreezeRelease(ctx, actor, "release", 1); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
			t.Fatal("oversized stored transition fields accepted", v.ID, err)
		}
		if _, err := pool.Exec(ctx, `UPDATE releases SET version='1.0.0';UPDATE products SET slug='product'`); err != nil {
			t.Fatal(err)
		}
	}
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
			v, err := commands.FreezeRelease(ctx, actor, "release", 1)
			results <- result{v, err}
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err == nil && r.v.ID == "release" && r.v.State.String() == "frozen" && r.v.Revision == 2 && r.v.FrozenAt != nil {
			winners++
		} else if revision, ok := releaseapp.CurrentRevision(r.err); !ok || revision != 2 || !errors.Is(r.err, releaseapp.ErrConflict) || r.v.ID != "" {
			t.Fatal("unexpected transition race result", r.v.ID, r.err, revision, ok)
		}
	}
	var revision int64
	var audits int
	if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*)FROM audit_chain_entries)FROM releases WHERE id='release'`).Scan(&revision, &audits); err != nil || winners != 1 || revision != 2 || audits != 1 {
		t.Fatal("release race duplicated state/audit", winners, revision, audits, err)
	}
	if v, err := two.ApproveRelease(ctx, denied, "release", 2); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("removed grant retained approval access", v.ID, err)
	}
	if v, err := two.ApproveRelease(ctx, actor, "release", 2); err != nil || v.Revision != 3 || v.State.String() != "approved" || v.FrozenAt == nil || v.ApprovedAt == nil {
		t.Fatal("approve failed", v.ID, err)
	}
	if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*)FROM audit_chain_entries)FROM releases WHERE id='release'`).Scan(&revision, &audits); err != nil || revision != 3 || audits != 2 {
		t.Fatal("approval effects wrong", revision, audits, err)
	}
}
