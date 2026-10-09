package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestPostgresPullRequestRecordingAppendsSnapshotsAndAuditsAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Sources'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('foreign','other','Other','other')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('other-project','tenant','product','Other'),('foreign','other','foreign','Foreign')`)
	exec(`INSERT INTO source_repositories(id,tenant_id,project_id,provider,full_name,clone_url,schema_version,created_at)VALUES('repo','tenant','project','git','org/api',repeat('x',9000000),'source-repository.v1.0.0',now()),('another','tenant','other-project','git','org/another',NULL,'source-repository.v1.0.0',now()),('detached','tenant',NULL,'git','org/detached',NULL,'source-repository.v1.0.0',now()),('foreign','other','foreign','git','other/api',NULL,'source-repository.v1.0.0',now())`)
	exec(`INSERT INTO source_commits(id,tenant_id,repository_id,sha,author,committed_at,schema_version,created_at)VALUES('head','tenant','repo',repeat('a',40),repeat('x',9000000),now(),'source-commit.v1.0.0',now()),('other-head','tenant','another',repeat('b',40),NULL,now(),'source-commit.v1.0.0',now()),('foreign-head','other','foreign',repeat('c',40),NULL,now(),'source-commit.v1.0.0',now())`)
	exec(`INSERT INTO pull_requests(id,tenant_id,repository_id,provider,provider_id,title,state,schema_version,created_at)VALUES('historical','tenant','repo','git','17',repeat('x',9000000),'open','pull-request.v1.0.0',now())`)
	one, err := BuildPullRequestCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildPullRequestCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	in := integrationapp.RecordPullRequestInput{RepositoryID: "repo", ProviderID: "17", Title: "private title", State: "merged", SourceBranch: "feature", TargetBranch: "main", HeadCommitID: "head", ReviewDecision: "private review text"}
	type result struct {
		v   integrationdomain.PullRequest
		err error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, err := c.RecordPullRequest(ctx, a, in)
			results <- result{v, err}
		}(i)
	}
	ids := make(map[string]bool)
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err != nil || r.v.ID == "" || ids[r.v.ID] || r.v.Provider != "git" || r.v.ProviderID != "17" || r.v.Title != in.Title || r.v.State != in.State || r.v.HeadCommitID != "head" || r.v.ReviewDecision != in.ReviewDecision || r.v.CreatedAt.Location().String() != "UTC" {
			t.Fatal(r)
		}
		ids[r.v.ID] = true
	}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM pull_requests WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if counts() != [3]int{9, 8, 0} {
		t.Fatal("snapshot recording deduplicated or duplicated effects", counts())
	}
	var size int
	if err := pool.QueryRow(ctx, `SELECT octet_length(title)FROM pull_requests WHERE id='historical'`).Scan(&size); err != nil || size != 9000000 {
		t.Fatal("historical snapshot changed", size, err)
	}
	var leaked bool
	if err := pool.QueryRow(ctx, `SELECT COALESCE(bool_or(row_to_json(a)::text LIKE '%private title%' OR row_to_json(a)::text LIKE '%private review text%'),false) FROM audit_chain_entries a`).Scan(&leaked); err != nil || leaked {
		t.Fatal("review metadata copied to audit", leaked, err)
	}
	for _, id := range []string{"other-head", "foreign-head", "missing", " "} {
		request := in
		request.HeadCommitID = id
		if v, err := one.RecordPullRequest(ctx, a, request); !errors.Is(err, integrationapp.ErrNotFound) || v.ID != "" || counts() != [3]int{9, 8, 0} {
			t.Fatal("invalid head persisted", id, v, err)
		}
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}}
	if v, err := one.RecordPullRequest(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("wrong project allowed", v, err)
	}
	human.ResourceGrants = nil
	if _, err := one.RecordPullRequest(ctx, human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant allowed", err)
	}
	foreign := in
	foreign.RepositoryID, foreign.HeadCommitID = "foreign", "foreign-head"
	if _, err := one.RecordPullRequest(ctx, a, foreign); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("foreign repository allowed", err)
	}
	for _, table := range []string{"pull_requests", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_pull_request()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected source failure';END$$`)
		exec(`CREATE TRIGGER reject_pull_request BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_pull_request()`)
		if v, err := one.RecordPullRequest(ctx, a, in); err == nil || v.ID != "" || counts() != [3]int{9, 8, 0} {
			t.Fatal("partial snapshot persisted", table, v, err, counts())
		}
		exec(`DROP TRIGGER reject_pull_request ON ` + table)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/pull-requests", "pr-replay", []byte(`{"provider_id":"17"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			v, err := one.RecordPullRequest(ctx, a, in)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counts() != [3]int{10, 9, 0} {
		t.Fatal("replay added snapshot", counts())
	}
	called := false
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/pull-requests", "pr-replay", []byte(`{"provider_id":"changed"}`), func(context.Context, app.Repositories) (int, any, error) { called = true; return 201, nil, nil }); !errors.Is(err, app.ErrIdempotencyConflict) || called {
		t.Fatal("changed replay accepted", err, called)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:write"}}}
	v, err := one.RecordPullRequest(ctx, human, in)
	if err != nil || v.ID == "" || counts() != [3]int{11, 10, 0} {
		t.Fatal("current grant rejected", v, err)
	}
	var actorType string
	if err := pool.QueryRow(ctx, `SELECT actor_type FROM audit_chain_entries WHERE subject_id=$1`, v.ID).Scan(&actorType); err != nil || actorType != "human_user" {
		t.Fatal(actorType, err)
	}
	detached := in
	detached.RepositoryID, detached.HeadCommitID = "detached", ""
	if _, err := one.RecordPullRequest(ctx, human, detached); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("scoped grant accepted detached repository", err)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"source:write"}}}
	if _, err := one.RecordPullRequest(ctx, human, detached); err != nil || counts() != [3]int{12, 11, 0} {
		t.Fatal("tenant grant rejected", err, counts())
	}
	exec(`UPDATE source_repositories SET provider=repeat('x',65537)WHERE id='repo'`)
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}
	if v, err := one.RecordPullRequest(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("unauthorized provider metadata read", v, err)
	}
	if v, err := one.RecordPullRequest(ctx, a, in); !errors.Is(err, integrationapp.ErrConflict) || v.ID != "" || counts() != [3]int{12, 11, 0} {
		t.Fatal("oversized provider accepted", v, err)
	}
	in.Provider = "explicit-provider"
	if v, err := one.RecordPullRequest(ctx, a, in); err != nil || v.Provider != in.Provider || counts() != [3]int{13, 12, 0} {
		t.Fatal("explicit provider loaded unrelated oversized metadata", v, err)
	}
}
func TestPullRequestCommandsRequireTransactions(t *testing.T) {
	if _, err := BuildPullRequestCommands(nil); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
}
