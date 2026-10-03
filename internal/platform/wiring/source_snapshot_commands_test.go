package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func TestPostgresSourceSnapshotCommitsOneWorkflowWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Sources'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('foreign','other','Foreign','foreign')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('other-project','tenant','product','Other'),('foreign','other','foreign','Foreign')`)
	one, err := BuildSourceSnapshotCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildSourceSnapshotCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	in := integrationapp.SourceSnapshotInput{ProjectID: "project", Repository: integrationapp.SourceSnapshotRepositoryInput{FullName: "org/api", CloneURL: "opaque", DefaultBranch: "main"}, Commit: &integrationapp.SourceSnapshotCommitInput{SHA: strings.Repeat("A", 40), Author: "author", Message: " private exact message "}, Branch: &integrationapp.SourceSnapshotBranchInput{Name: "main", Protected: true, ProtectionHash: "opaque"}, PullRequest: &integrationapp.SourceSnapshotPullRequestInput{ProviderID: "17", Title: "Change", State: "merged", SourceBranch: "feature", TargetBranch: "main", ReviewDecision: "submitted review"}}
	counts := func() [6]int {
		t.Helper()
		var n [6]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM source_repositories WHERE tenant_id='tenant'),(SELECT count(*)FROM source_commits WHERE tenant_id='tenant'),(SELECT count(*)FROM source_branches WHERE tenant_id='tenant'),(SELECT count(*)FROM pull_requests WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// A late validation failure must roll back earlier components even without
	// an ambient HTTP idempotency transaction.
	bad := in
	badPR := *in.PullRequest
	badPR.State = "invalid"
	bad.PullRequest = &badPR
	if v, err := one.RecordSourceSnapshot(ctx, a, "github", bad); !errors.Is(err, integrationapp.ErrValidation) || v.Repository.ID != "" || counts() != [6]int{} {
		t.Fatal("partial standalone snapshot committed", v, err, counts())
	}
	missingTitle := in
	missingTitlePR := *in.PullRequest
	missingTitlePR.Title = ""
	missingTitle.PullRequest = &missingTitlePR
	if v, err := one.RecordSourceSnapshot(ctx, a, "github", missingTitle); !errors.Is(err, integrationapp.ErrValidation) || v != (integrationapp.SourceSnapshotResult{}) || counts() != [6]int{} {
		t.Fatal("missing title or partial snapshot accepted", v, err, counts())
	}
	for _, table := range []string{"source_repositories", "source_commits", "source_branches", "pull_requests", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_source_snapshot()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected snapshot failure';END$$`)
		exec(`CREATE TRIGGER reject_source_snapshot BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_source_snapshot()`)
		if v, err := one.RecordSourceSnapshot(ctx, a, "github", in); err == nil || v.Repository.ID != "" || counts() != [6]int{} {
			t.Fatal("partial workflow persisted", table, v, err, counts())
		}
		exec(`DROP TRIGGER reject_source_snapshot ON ` + table)
	}
	type result struct {
		v   integrationapp.SourceSnapshotResult
		err error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, err := c.RecordSourceSnapshot(ctx, a, "github", in)
			results <- result{v, err}
		}(i)
	}
	var original integrationapp.SourceSnapshotResult
	prIDs := map[string]bool{}
	hash := sha256.Sum256([]byte(in.Commit.Message))
	wantHash := "sha256:" + hex.EncodeToString(hash[:])
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		v := r.v
		if v.Repository.ID == "" || v.Commit.ID == "" || v.Branch.ID == "" || v.PullRequest.ID == "" || prIDs[v.PullRequest.ID] || v.Commit.RepositoryID != v.Repository.ID || v.Branch.RepositoryID != v.Repository.ID || v.PullRequest.RepositoryID != v.Repository.ID || v.Branch.HeadCommitID != v.Commit.ID || v.PullRequest.HeadCommitID != v.Commit.ID || v.PullRequest.Provider != "github" || v.Commit.MessageHash != wantHash || v.Commit.SHA != strings.Repeat("a", 40) || v.Commit.CommittedAt.IsZero() || v.Commit.CommittedAt.Location().String() != "UTC" {
			t.Fatal(v)
		}
		if i > 0 && (v.Repository != original.Repository || v.Commit != original.Commit || v.Branch.ID != original.Branch.ID) {
			t.Fatal("identity or immutable commit changed", v, original)
		}
		original = v
		prIDs[v.PullRequest.ID] = true
	}
	if counts() != [6]int{1, 1, 1, 8, 18, 0} {
		t.Fatal("workflow deduplicated PRs or duplicated immutable records", counts())
	}
	var leaked bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM source_commits c WHERE row_to_json(c)::text LIKE '%private exact message%') OR EXISTS(SELECT 1 FROM audit_chain_entries a WHERE row_to_json(a)::text LIKE '%private exact message%')`).Scan(&leaked); err != nil || leaked {
		t.Fatal("raw commit message persisted", leaked, err)
	}
	// Existing branch mutations and new commits must roll back too.
	changed := in
	changedCommit := *in.Commit
	changedCommit.SHA = strings.Repeat("b", 40)
	changed.Commit = &changedCommit
	changedBranch := *in.Branch
	changedBranch.Protected = false
	changedBranch.ProtectionHash = "changed"
	changed.Branch = &changedBranch
	changed.PullRequest = &badPR
	if v, err := one.RecordSourceSnapshot(ctx, a, "github", changed); !errors.Is(err, integrationapp.ErrValidation) || v.Repository.ID != "" || counts() != [6]int{1, 1, 1, 8, 18, 0} {
		t.Fatal("branch update rollback failed", v, err, counts())
	}
	var head, protection string
	var protected bool
	if err := pool.QueryRow(ctx, `SELECT head_commit_id,protected,protection_hash FROM source_branches WHERE id=$1`, original.Branch.ID).Scan(&head, &protected, &protection); err != nil || head != original.Commit.ID || !protected || protection != "opaque" {
		t.Fatal("prior branch changed on failure", head, protected, protection, err)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}}
	wrong := in
	wrong.ProjectID = "other-project"
	if _, err := one.RecordSourceSnapshot(ctx, human, "github", wrong); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("actual repository owner bypassed", err)
	}
	human.ResourceGrants = nil
	if _, err := one.RecordSourceSnapshot(ctx, human, "github", in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant accepted", err)
	}
	foreign := in
	foreign.ProjectID = "foreign"
	if _, err := one.RecordSourceSnapshot(ctx, a, "github", foreign); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("foreign project accepted", err)
	}
	if counts() != [6]int{1, 1, 1, 8, 18, 0} {
		t.Fatal("denied workflow wrote effects", counts())
	}
	// Bind to the actual idempotency UoW and compare complete replay payloads.
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	var response []byte
	for i := 0; i < 2; i++ {
		status, body, err := executor.WithBody(ctx, a, "POST", "/v1/collectors/github/source-snapshots", "snapshot-replay", []byte(`{"repository":{"full_name":"org/api"}}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			v, err := one.RecordSourceSnapshot(ctx, a, "github", in)
			return 201, v, err
		})
		if err != nil || status != 201 {
			t.Fatal(status, err)
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		// PostgreSQL stores JSONB, so replay reconstructs maps rather than Go
		// structs. Compare every value in canonical JSON order, not struct field
		// order on the first response versus sorted map order on replay.
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		encoded, err = json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && string(encoded) != string(response) {
			t.Fatal("replay response changed")
		}
		response = encoded
	}
	if counts() != [6]int{1, 1, 1, 9, 20, 0} || strings.Contains(string(response), "private exact message") {
		t.Fatal("replay repeated or leaked workflow", counts(), string(response))
	}
	called := false
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/collectors/github/source-snapshots", "snapshot-replay", []byte(`{"repository":{"full_name":"changed"}}`), func(context.Context, app.Repositories) (int, any, error) { called = true; return 201, nil, nil }); !errors.Is(err, app.ErrIdempotencyConflict) || called {
		t.Fatal("changed request replay accepted", err, called)
	}
	noCommit := in
	noCommit.Commit = nil
	v, err := one.RecordSourceSnapshot(ctx, a, "github", noCommit)
	if err != nil || v.Commit.ID != "" || v.Branch.HeadCommitID != "" || v.PullRequest.HeadCommitID != "" || counts() != [6]int{1, 1, 1, 10, 22, 0} {
		t.Fatal(v, err, counts())
	}
	repoOnly := in
	repoOnly.Commit, repoOnly.Branch, repoOnly.PullRequest = nil, nil, nil
	v, err = one.RecordSourceSnapshot(ctx, a, "github", repoOnly)
	if err != nil || v.Repository != original.Repository || v.Commit.ID != "" || v.Branch.ID != "" || v.PullRequest.ID != "" || counts() != [6]int{1, 1, 1, 10, 22, 0} {
		t.Fatal(v, err, counts())
	}
	repoOnly.Repository.FullName = "org/gitlab"
	v, err = two.RecordSourceSnapshot(ctx, a, "gitlab", repoOnly)
	if err != nil || v.Repository.Provider != "gitlab" || counts() != [6]int{2, 1, 1, 10, 23, 0} {
		t.Fatal(v, err, counts())
	}
	exec(`UPDATE source_repositories SET clone_url=repeat('x',9000000)WHERE id=$1`, original.Repository.ID)
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"source:write"}}}
	if _, err := one.RecordSourceSnapshot(ctx, human, "github", wrong); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("private metadata read before actual owner grant", err)
	}
	if v, err := one.RecordSourceSnapshot(ctx, a, "github", in); !errors.Is(err, integrationapp.ErrConflict) || v.Repository.ID != "" || counts() != [6]int{2, 1, 1, 10, 23, 0} {
		t.Fatal("oversized stored metadata accepted", v, err, counts())
	}
	exec(`UPDATE source_repositories SET clone_url='opaque'WHERE id=$1`, original.Repository.ID)
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:write"}}}
	repoOnly.Repository.FullName = "org/api"
	if v, err := one.RecordSourceSnapshot(ctx, human, "github", repoOnly); err != nil || v.Repository != original.Repository || counts() != [6]int{2, 1, 1, 10, 23, 0} {
		t.Fatal("current project grant rejected", v, err)
	}
	detached := repoOnly
	detached.ProjectID, detached.Repository.FullName = "", "org/detached"
	if _, err := one.RecordSourceSnapshot(ctx, human, "github", detached); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("scoped human created detached repository", err)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"source:write"}}}
	if v, err := one.RecordSourceSnapshot(ctx, human, "github", detached); err != nil || v.Repository.ProjectID != "" || counts() != [6]int{3, 1, 1, 10, 24, 0} {
		t.Fatal("tenant grant rejected", v, err, counts())
	}
	other := a
	other.TenantID = "other"
	foreign = repoOnly
	foreign.ProjectID = "foreign"
	if v, err := two.RecordSourceSnapshot(ctx, other, "github", foreign); err != nil || v.Repository.TenantID != "other" || v.Repository.ID == original.Repository.ID || counts() != [6]int{3, 1, 1, 10, 24, 0} {
		t.Fatal("repository identity crossed tenant boundary", v, err, counts())
	}
}
func TestSourceSnapshotCommandsRequireTransactions(t *testing.T) {
	if _, err := BuildSourceSnapshotCommands(nil); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
}
