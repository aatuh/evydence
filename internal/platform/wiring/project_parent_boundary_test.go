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
)

func TestPostgresProjectCreationReadsBoundedPendingProductCoordinates(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Project boundary'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildProjectCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"project:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"project:write"}}}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	rollback := errors.New("rollback pending project parent")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			runs++
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: "product", TenantID: "tenant", Name: strings.Repeat("x", 9000000), Slug: "product", CreatedAt: time.Now().UTC()}); err != nil {
				return 0, nil, err
			}
			project, err := commands.CreateProject(txCtx, actor, releaseapp.CreateProjectInput{ProductID: "product", Name: " Child "})
			if err != nil {
				return 0, nil, err
			}
			if project.ProductID != "product" || project.Name != "Child" || project.TenantID != "tenant" {
				return 0, nil, errors.New("project coordinates changed")
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, project, nil
		}
	}
	counts := func() [4]int {
		t.Helper()
		var n [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM projects),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/projects", "pending-rollback", []byte("{}"), run(true)); !errors.Is(err, rollback) || counts() != [4]int{} {
		t.Fatal("pending parent or compound rollback failed", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/projects", "pending-success", []byte("{}"), run(false)); err != nil || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("pending product coordinates not visible", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/projects", "pending-success", []byte("{}"), run(false)); err != nil || runs != 2 || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("project replay repeated compound command", err, runs, counts())
	}
	foreign := actor
	foreign.TenantID = "other"
	if v, err := commands.CreateProject(ctx, foreign, releaseapp.CreateProjectInput{ProductID: "product", Name: "Denied"}); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" {
		t.Fatal("foreign parent visible", v.ID, err)
	}
	denied := actor
	denied.ResourceGrants = nil
	if v, err := commands.CreateProject(ctx, denied, releaseapp.CreateProjectInput{ProductID: "product", Name: "Denied"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("ungranted parent accepted", v.ID, err)
	}
	for _, name := range []string{"bad\x00name", string([]byte{255}), strings.Repeat("界", 22000)} {
		if v, err := commands.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: "product", Name: name}); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" {
			t.Fatal("unsupported project storage text accepted", v.ID, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE products SET slug=repeat('界',22000)WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	if v, err := commands.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: "product", Name: "Overflow"}); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("oversized parent slug returned or effects committed", v.ID, err, counts())
	}
}
