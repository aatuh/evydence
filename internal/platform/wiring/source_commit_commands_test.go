package wiring

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestPostgresSourceCommitRecordingSerializesReuseAndPreservesPrivacy(t *testing.T) {
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
	exec(`INSERT INTO source_repositories(id,tenant_id,project_id,provider,full_name,clone_url,schema_version,created_at)VALUES('repo','tenant','project','git','org/api',repeat('x',9000000),'source-repository.v1.0.0',now()),('detached','tenant',NULL,'git','org/detached',NULL,'source-repository.v1.0.0',now()),('foreign','other','foreign','git','other/api',NULL,'source-repository.v1.0.0',now())`)
	one, err := BuildSourceCommitCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildSourceCommitCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	in := integrationapp.RecordSourceCommitInput{RepositoryID: "repo", SHA: strings.Repeat("ab", 20), Author: " Original ", Message: " message with private contents ", CommittedAt: time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.FixedZone("offset", 3600))}
	type result struct {
		v   integrationdomain.SourceCommit
		err error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			c, request := one, in
			if i%2 != 0 {
				c = two
				request.SHA = strings.ToUpper(request.SHA)
			}
			v, err := c.RecordSourceCommit(ctx, a, request)
			results <- result{v, err}
		}(i)
	}
	var original integrationdomain.SourceCommit
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err != nil || r.v.ID == "" {
			t.Fatal(r)
		}
		if original.ID == "" {
			original = r.v
		}
		if r.v != original {
			t.Fatal("concurrent duplicate changed commit", r.v, original)
		}
	}
	wantHash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(in.Message)))
	if original.SHA != in.SHA || original.Author != "Original" || original.MessageHash != wantHash || original.CommittedAt != in.CommittedAt.UTC().Truncate(time.Microsecond) {
		t.Fatal(original)
	}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM source_commits WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if counts() != [3]int{1, 1, 0} {
		t.Fatal("duplicated effects", counts())
	}
	changed := in
	changed.Author, changed.Message = "changed", "changed"
	changed.CommittedAt = original.CommittedAt.Add(time.Hour)
	if v, err := one.RecordSourceCommit(ctx, a, changed); err != nil || v != original || counts() != [3]int{1, 1, 0} {
		t.Fatal("reuse changed immutable data", v, err)
	}
	var storedSHA, storedAuthor, storedHash, actorType string
	if err := pool.QueryRow(ctx, `SELECT sha,author,message_hash FROM source_commits WHERE id=$1`, original.ID).Scan(&storedSHA, &storedAuthor, &storedHash); err != nil || storedSHA != original.SHA || storedAuthor != "Original" || storedHash != wantHash {
		t.Fatal(storedSHA, storedAuthor, storedHash, err)
	}
	if err := pool.QueryRow(ctx, `SELECT actor_type FROM audit_chain_entries WHERE subject_id=$1`, original.ID).Scan(&actorType); err != nil || actorType != "api_key" {
		t.Fatal(actorType, err)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}}
	if v, err := one.RecordSourceCommit(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("wrong project exposed commit", v, err)
	}
	human.ResourceGrants[0].ResourceID = "project"
	if v, err := one.RecordSourceCommit(ctx, human, in); err != nil || v != original {
		t.Fatal("owner grant rejected", v, err)
	}
	human.ResourceGrants = nil
	if _, err := one.RecordSourceCommit(ctx, human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant retained access", err)
	}
	foreign := in
	foreign.RepositoryID = "foreign"
	if _, err := one.RecordSourceCommit(ctx, a, foreign); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("foreign repository accepted", err)
	}
	detached := in
	detached.RepositoryID = "detached"
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:write"}}}
	if _, err := one.RecordSourceCommit(ctx, human, detached); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("scoped grant accessed detached repository", err)
	}
	for _, table := range []string{"source_commits", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_source_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected source failure';END$$`)
		exec(`CREATE TRIGGER reject_source_commit BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_source_commit()`)
		request := in
		request.SHA = strings.Repeat("c", 40)
		if v, err := one.RecordSourceCommit(ctx, a, request); err == nil || v.ID != "" || counts() != [3]int{1, 1, 0} {
			t.Fatal("partial commit persisted", table, v, err, counts())
		}
		exec(`DROP TRIGGER reject_source_commit ON ` + table)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/commits", "commit-replay", []byte(`{"sha":"replay"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			request := in
			request.SHA = strings.Repeat("d", 40)
			v, err := one.RecordSourceCommit(ctx, a, request)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counts() != [3]int{2, 2, 0} {
		t.Fatal("replay duplicated effects", counts())
	}
	called := false
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/source/commits", "commit-replay", []byte(`{"sha":"changed"}`), func(context.Context, app.Repositories) (int, any, error) { called = true; return 201, nil, nil }); !errors.Is(err, app.ErrIdempotencyConflict) || called {
		t.Fatal("changed replay accepted", err, called)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"source:write"}}}
	v, err := one.RecordSourceCommit(ctx, human, detached)
	if err != nil || v.RepositoryID != "detached" || counts() != [3]int{3, 3, 0} {
		t.Fatal("tenant grant denied", v, err)
	}
	if err := pool.QueryRow(ctx, `SELECT actor_type FROM audit_chain_entries WHERE subject_id=$1`, v.ID).Scan(&actorType); err != nil || actorType != "human_user" {
		t.Fatal(actorType, err)
	}
	exec(`UPDATE source_commits SET author=repeat('x',9000000) WHERE id=$1`, original.ID)
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}
	if v, err := one.RecordSourceCommit(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("unauthorized metadata read", v, err)
	}
	if v, err := one.RecordSourceCommit(ctx, a, in); !errors.Is(err, integrationapp.ErrConflict) || v.ID != "" {
		t.Fatal("oversized commit metadata returned", v, err)
	}
}
func TestSourceCommitCommandsRequireTransactions(t *testing.T) {
	if _, err := BuildSourceCommitCommands(nil); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
}
