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

func TestPostgresSourceBranchUpsertSerializesCurrentStateAndAuditsAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Source'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('foreign','other','Other','other')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('other-project','tenant','product','Other'),('foreign','other','foreign','Foreign')`)
	exec(`INSERT INTO source_repositories(id,tenant_id,project_id,provider,full_name,clone_url,schema_version,created_at)VALUES('repo','tenant','project','git','org/api',repeat('x',9000000),'source-repository.v1.0.0',now()),('another','tenant','other-project','git','org/another',NULL,'source-repository.v1.0.0',now()),('detached','tenant',NULL,'git','org/detached',NULL,'source-repository.v1.0.0',now()),('foreign','other','foreign','git','other/api',NULL,'source-repository.v1.0.0',now())`)
	exec(`INSERT INTO source_commits(id,tenant_id,repository_id,sha,author,committed_at,schema_version,created_at)VALUES('head','tenant','repo',repeat('a',40),repeat('x',9000000),now(),'source-commit.v1.0.0',now()),('other-head','tenant','another',repeat('b',40),NULL,now(),'source-commit.v1.0.0',now()),('foreign-head','other','foreign',repeat('c',40),NULL,now(),'source-commit.v1.0.0',now())`)
	one, err := BuildSourceBranchCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildSourceBranchCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	in := integrationapp.UpsertSourceBranchInput{RepositoryID: "repo", Name: "main", HeadCommitID: "head", Protected: true, ProtectionHash: "initial-snapshot"}
	type result struct {
		v   integrationdomain.SourceBranch
		err error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, err := c.UpsertSourceBranch(ctx, a, in)
			results <- result{v, err}
		}(i)
	}
	var original integrationdomain.SourceBranch
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err != nil || r.v.ID == "" {
			t.Fatal(r)
		}
		if original.ID == "" {
			original = r.v
		}
		if r.v != original {
			t.Fatal("concurrent upsert changed branch identity", r.v, original)
		}
	}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM source_branches WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	var creates, updates int
	if err := pool.QueryRow(ctx, `SELECT count(*)FILTER(WHERE entry_type='source_branch.created'),count(*)FILTER(WHERE entry_type='source_branch.updated') FROM audit_chain_entries WHERE subject_id=$1`, original.ID).Scan(&creates, &updates); err != nil || creates != 1 || updates != 7 || counts() != [3]int{1, 8, 0} {
		t.Fatal(creates, updates, err, counts())
	}
	for _, id := range []string{"other-head", "foreign-head", "missing", " "} {
		request := in
		request.HeadCommitID = id
		if v, err := one.UpsertSourceBranch(ctx, a, request); !errors.Is(err, integrationapp.ErrNotFound) || v.ID != "" || counts() != [3]int{1, 8, 0} {
			t.Fatal("invalid head changed branch", id, v, err)
		}
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}}
	if v, err := one.UpsertSourceBranch(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("wrong project accepted", v, err)
	}
	human.ResourceGrants = nil
	if _, err := one.UpsertSourceBranch(ctx, human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant retained access", err)
	}
	foreign := in
	foreign.RepositoryID = "foreign"
	foreign.HeadCommitID = "foreign-head"
	if _, err := one.UpsertSourceBranch(ctx, a, foreign); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("foreign repository accepted", err)
	}
	readHash := func() string {
		t.Helper()
		var hash string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(protection_hash,'') FROM source_branches WHERE id=$1`, original.ID).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	for _, table := range []string{"source_branches", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_source_branch()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected source failure';END$$`)
		events := "INSERT"
		if table == "source_branches" {
			events = "INSERT OR UPDATE"
		}
		exec(`CREATE TRIGGER reject_source_branch BEFORE ` + events + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_source_branch()`)
		for _, name := range []string{"main", "failed-create"} {
			request := in
			request.Name, request.ProtectionHash = name, "failed-update"
			if v, err := one.UpsertSourceBranch(ctx, a, request); err == nil || v.ID != "" || counts() != [3]int{1, 8, 0} || readHash() != in.ProtectionHash {
				t.Fatal("partial branch mutation", table, v, err, counts())
			}
		}
		exec(`DROP TRIGGER reject_source_branch ON ` + table)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/branches", "branch-replay", []byte(`{"protection_hash":"replay"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			request := in
			request.ProtectionHash = "replay-snapshot"
			v, err := one.UpsertSourceBranch(ctx, a, request)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counts() != [3]int{1, 9, 0} || readHash() != "replay-snapshot" {
		t.Fatal("replay reran update", counts(), readHash())
	}
	called := false
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/branches", "branch-replay", []byte(`{"protection_hash":"changed"}`), func(context.Context, app.Repositories) (int, any, error) { called = true; return 201, nil, nil }); !errors.Is(err, app.ErrIdempotencyConflict) || called {
		t.Fatal("changed replay accepted", err, called)
	}
	for i := 0; i < 2; i++ {
		go func(i int) {
			request := in
			request.ProtectionHash = []string{"first", "second"}[i]
			c := one
			if i != 0 {
				c = two
			}
			v, err := c.UpsertSourceBranch(ctx, a, request)
			results <- result{v, err}
		}(i)
	}
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil || r.v.ID != original.ID || r.v.CreatedAt != original.CreatedAt {
			t.Fatal(r)
		}
	}
	var latestHash string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(payload_hash,'') FROM audit_chain_entries WHERE subject_id=$1 ORDER BY sequence DESC LIMIT 1`, original.ID).Scan(&latestHash); err != nil || latestHash != readHash() || counts() != [3]int{1, 11, 0} {
		t.Fatal("branch state detached from latest ordered audit", latestHash, readHash(), err, counts())
	}
	called = false
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/branches", "branch-replay", []byte(`{"protection_hash":"replay"}`), func(context.Context, app.Repositories) (int, any, error) { called = true; return 201, nil, nil }); err != nil || called || readHash() != latestHash || counts() != [3]int{1, 11, 0} {
		t.Fatal("old replay reapplied stale branch state", err, called, readHash(), counts())
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:write"}}}
	clear := in
	clear.HeadCommitID, clear.ProtectionHash, clear.Protected = "", "", false
	v, err := one.UpsertSourceBranch(ctx, human, clear)
	if err != nil || v.ID != original.ID || v.CreatedAt != original.CreatedAt || v.HeadCommitID != "" || v.Protected || v.ProtectionHash != "" || counts() != [3]int{1, 12, 0} {
		t.Fatal("replacement defaults failed", v, err)
	}
	var actorType string
	if err := pool.QueryRow(ctx, `SELECT actor_type FROM audit_chain_entries WHERE subject_id=$1 ORDER BY sequence DESC LIMIT 1`, v.ID).Scan(&actorType); err != nil || actorType != "human_user" {
		t.Fatal(actorType, err)
	}
	detached := clear
	detached.RepositoryID = "detached"
	if _, err := one.UpsertSourceBranch(ctx, human, detached); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("scoped grant accessed detached repository", err)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"source:write"}}}
	if _, err := one.UpsertSourceBranch(ctx, human, detached); err != nil || counts() != [3]int{2, 13, 0} {
		t.Fatal("tenant grant rejected", err, counts())
	}
	exec(`UPDATE source_branches SET protection_hash=repeat('x',9000000) WHERE id=$1`, original.ID)
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}
	if v, err := one.UpsertSourceBranch(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("unauthorized metadata read", v, err)
	}
	if v, err := one.UpsertSourceBranch(ctx, a, in); !errors.Is(err, integrationapp.ErrConflict) || v.ID != "" || strings.Contains(v.ProtectionHash, "x") {
		t.Fatal("oversized private metadata returned", v, err)
	}
}
func TestSourceBranchCommandsRequireTransactions(t *testing.T) {
	if _, err := BuildSourceBranchCommands(nil); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
}
