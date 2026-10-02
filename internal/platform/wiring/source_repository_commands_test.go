package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestPostgresSourceRepositoryCreationSerializesReuseAndChecksCurrentOwner(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Sources'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('foreign-product','other','Other','other')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('other-project','tenant','product','Other'),('foreign-project','other','foreign-product','Other')`)
	one, err := BuildSourceRepositoryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildSourceRepositoryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: "project", Provider: "github", FullName: "org/api", CloneURL: "https://example.test/org/api.git", DefaultBranch: "main"}
	type result struct {
		v   integrationdomain.SourceRepository
		err error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, err := c.CreateSourceRepository(ctx, a, in)
			results <- result{v, err}
		}(i)
	}
	id := ""
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err != nil || r.v.ID == "" {
			t.Fatal(r)
		}
		if id == "" {
			id = r.v.ID
		}
		if id != r.v.ID {
			t.Fatal("duplicate source identity", r.v.ID, id)
		}
	}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM source_repositories WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if counts() != [3]int{1, 1, 0} {
		t.Fatal("concurrent reuse duplicated effects", counts())
	}
	changed := in
	changed.ProjectID = "other-project"
	changed.CloneURL = "changed"
	changed.DefaultBranch = "changed"
	if v, err := one.CreateSourceRepository(ctx, a, changed); err != nil || v.ID != id || v.ProjectID != in.ProjectID || v.CloneURL != in.CloneURL || v.DefaultBranch != in.DefaultBranch || counts() != [3]int{1, 1, 0} {
		t.Fatal("reuse mutated stored metadata", v, err)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}}
	if v, err := one.CreateSourceRepository(ctx, human, changed); !errors.Is(err, application.ErrForbidden) || v.ID != "" || counts() != [3]int{1, 1, 0} {
		t.Fatal("submitted project grant revealed existing repository", v, err)
	}
	detached := in
	detached.ProjectID = ""
	detached.FullName = "org/detached"
	if _, err := one.CreateSourceRepository(ctx, human, detached); !errors.Is(err, application.ErrForbidden) || counts() != [3]int{1, 1, 0} {
		t.Fatal("scoped human created detached repository", err)
	}
	foreign := in
	foreign.ProjectID = "foreign-project"
	if _, err := one.CreateSourceRepository(ctx, a, foreign); !errors.Is(err, integrationapp.ErrNotFound) || counts() != [3]int{1, 1, 0} {
		t.Fatal("foreign project accepted", err)
	}
	for _, table := range []string{"source_repositories", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_source_repository()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected source failure';END$$`)
		exec(`CREATE TRIGGER reject_source_repository BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_source_repository()`)
		request := in
		request.FullName = "org/failed"
		if v, err := one.CreateSourceRepository(ctx, a, request); err == nil || v.ID != "" || counts() != [3]int{1, 1, 0} {
			t.Fatal("partial repository creation", table, v, err, counts())
		}
		exec(`DROP TRIGGER reject_source_repository ON ` + table)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/repositories", "source-replay", []byte(`{"full_name":"org/replay"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			request := in
			request.FullName = "org/replay"
			v, err := one.CreateSourceRepository(ctx, a, request)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counts() != [3]int{2, 2, 0} {
		t.Fatal("replay duplicated effects", counts())
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:write"}}}
	if v, err := one.CreateSourceRepository(ctx, human, in); err != nil || v.ID != id || counts() != [3]int{2, 2, 0} {
		t.Fatal("current owner grant rejected", v, err)
	}
	human.ResourceGrants = nil
	if _, err := one.CreateSourceRepository(ctx, human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant retained source access", err)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"source:write"}}}
	v, err := one.CreateSourceRepository(ctx, human, detached)
	if err != nil || v.ProjectID != "" || counts() != [3]int{3, 3, 0} {
		t.Fatal("tenant-wide detached creation rejected", v, err, counts())
	}
	var actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT actor_type,actor_id FROM audit_chain_entries WHERE tenant_id='tenant' AND subject_id=$1`, v.ID).Scan(&actorType, &actorID); err != nil || actorType != "human_user" || actorID != "human" {
		t.Fatal("incorrect source actor audit", actorType, actorID, err)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}
	exec(`UPDATE source_repositories SET clone_url=repeat('x',9000000)WHERE id=$1`, id)
	if v, err := one.CreateSourceRepository(ctx, human, changed); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("unauthorized caller reached oversized private metadata", v, err)
	}
	if v, err := one.CreateSourceRepository(ctx, a, in); !errors.Is(err, integrationapp.ErrConflict) || v.ID != "" || strings.Contains(v.CloneURL, "x") {
		t.Fatal("oversized metadata returned", v, err)
	}
}
