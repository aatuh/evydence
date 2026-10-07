package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

type sourceWriteNativeCase struct{ path, body, table string }

func sourceWriteNativeCases() []sourceWriteNativeCase {
	return []sourceWriteNativeCase{
		{"/v1/source/commits", `{"repository_id":" repo ","sha":"` + strings.Repeat("AB", 20) + `","author":" Author ","message":" exact sensitive message "}`, "source_commits"},
		{"/v1/source/branches", `{"repository_id":" repo ","name":" main ","head_commit_id":" head ","protected":true,"protection_hash":" opaque "}`, "source_branches"},
		{"/v1/source/pull-requests", `{"repository_id":" repo ","provider_id":" 17 ","title":" Change ","state":" open ","head_commit_id":" head ","source_branch":" feature ","target_branch":" main ","review_decision":" recorded "}`, "pull_requests"},
	}
}

func seedSourceWritesNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO source_repositories(id,tenant_id,project_id,provider,full_name,schema_version,created_at)VALUES('repo','tenant','project','github','org/api','source-repository.v1.0.0',now()),('other-repo','tenant','other-project','gitlab','org/other','source-repository.v1.0.0',now());INSERT INTO source_commits(id,tenant_id,repository_id,sha,committed_at,schema_version,created_at)VALUES('head','tenant','repo',repeat('b',40),now(),'source-commit.v1.0.0',now()),('other-head','tenant','other-repo',repeat('c',40),now(),'source-commit.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
}

func sourceWritesNativeHTTP(t *testing.T, store *postgres.Store, tc sourceWriteNativeCase, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, nil)
	if opts.SourceCommitCommands == nil || opts.SourceBranchCommands == nil || opts.PullRequestCommands == nil {
		t.Fatal("missing native source write composition")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", tc.path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), "exact sensitive message") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native source status=%d want=%d canary=%t path=%s: %s", w.Code, want, noReload.Intact(t.Context()), tc.path, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("source replay lost key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("source lost problem contract")
	}
	return w.Body.String()
}

func sourceWritesNativeCounts(t *testing.T, p *pgxpool.Pool) [7]int {
	t.Helper()
	var n [7]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM source_commits),(SELECT count(*)FROM source_branches),(SELECT count(*)FROM pull_requests),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresSourceWritesNativeHTTPReplayPreservesDistinctWriteSemantics(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceWritesNative(t, p)
	for _, tc := range sourceWriteNativeCases() {
		one := sourceWritesNativeHTTP(t, store, tc, "initial", tc.body, 201)
		assertRetentionHTTPReplay(t, one, sourceWritesNativeHTTP(t, store, tc, "initial", tc.body, 201))
		sourceWritesNativeHTTP(t, store, tc, "initial", tc.body+" ", 409)
		switch tc.table {
		case "source_commits":
			var e struct {
				Data domain.SourceCommit `json:"data"`
			}
			err := json.Unmarshal([]byte(one), &e)
			if err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.RepositoryID != "repo" || e.Data.SHA != strings.Repeat("ab", 20) || e.Data.Author != "Author" || e.Data.MessageHash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(" exact sensitive message "))) || e.Data.SchemaVersion != domain.SourceCommitSchemaVersion || e.Data.CommittedAt != e.Data.CreatedAt || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
				t.Fatal("commit contract changed", one, err)
			}
			changed := strings.Replace(tc.body, `"author":" Author "`, `"author":"Changed","committed_at":"2026-01-01T00:00:00Z"`, 1)
			assertRetentionHTTPReplay(t, one, sourceWritesNativeHTTP(t, store, tc, "natural-reuse", changed, 201))
		case "source_branches":
			var e struct {
				Data domain.SourceBranch `json:"data"`
			}
			err := json.Unmarshal([]byte(one), &e)
			if err != nil || e.Data.ID == "" || e.Data.RepositoryID != "repo" || e.Data.Name != "main" || e.Data.HeadCommitID != "head" || !e.Data.Protected || e.Data.ProtectionHash != "opaque" || e.Data.SchemaVersion != domain.SourceBranchSchemaVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
				t.Fatal("branch contract changed", one, err)
			}
			changed := `{"repository_id":"repo","name":"main","protected":false}`
			update := sourceWritesNativeHTTP(t, store, tc, "replacement", changed, 201)
			var u struct {
				Data domain.SourceBranch `json:"data"`
			}
			if err := json.Unmarshal([]byte(update), &u); err != nil || u.Data.ID != e.Data.ID || u.Data.CreatedAt != e.Data.CreatedAt || u.Data.HeadCommitID != "" || u.Data.Protected || u.Data.ProtectionHash != "" {
				t.Fatal("branch replacement failed", update, err)
			}
			assertRetentionHTTPReplay(t, one, sourceWritesNativeHTTP(t, store, tc, "initial", tc.body, 201))
			var protected bool
			if err := p.QueryRow(t.Context(), `SELECT protected FROM source_branches WHERE id=$1`, e.Data.ID).Scan(&protected); err != nil || protected {
				t.Fatal("old replay reverted branch", protected, err)
			}
		case "pull_requests":
			var e struct {
				Data domain.PullRequest `json:"data"`
			}
			err := json.Unmarshal([]byte(one), &e)
			if err != nil || e.Data.ID == "" || e.Data.RepositoryID != "repo" || e.Data.Provider != "github" || e.Data.ProviderID != "17" || e.Data.Title != "Change" || e.Data.State != "open" || e.Data.HeadCommitID != "head" || e.Data.SourceBranch != "feature" || e.Data.TargetBranch != "main" || e.Data.ReviewDecision != "recorded" || e.Data.SchemaVersion != domain.PullRequestSchemaVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
				t.Fatal("PR contract changed", one, err)
			}
			changed := strings.Replace(tc.body, `"state":" open "`, `"state":"merged","title":"Changed"`, 1)
			changed = strings.Replace(changed, `"title":" Change ",`, "", 1)
			next := sourceWritesNativeHTTP(t, store, tc, "new-snapshot", changed, 201)
			var n struct {
				Data domain.PullRequest `json:"data"`
			}
			if err := json.Unmarshal([]byte(next), &n); err != nil || n.Data.ID == e.Data.ID || n.Data.State != "merged" || n.Data.Title != "Changed" {
				t.Fatal("PR overwrote original snapshot", next, err)
			}
			assertRetentionHTTPReplay(t, one, sourceWritesNativeHTTP(t, store, tc, "initial", tc.body, 201))
		}
		var principal, kind string
		if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type FROM audit_chain_entries WHERE entry_type=$1 LIMIT 1`, map[string]string{"source_commits": "source_commit.recorded", "source_branches": "source_branch.created", "pull_requests": "pull_request.recorded"}[tc.table]).Scan(&principal, &kind); err != nil || principal != "user" || kind != "human_user" {
			t.Fatal("source lost caller audit", principal, kind, err)
		}
	}
	if got := sourceWritesNativeCounts(t, p); got != [7]int{3, 1, 2, 5, 0, 6, 0} {
		t.Fatal("source write/replay effects changed", got)
	}
}

func TestPostgresSourceWritesNativeHTTPUsesOnlyCurrentIdentifiersOnReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceWritesNative(t, p)
	first := map[string]string{}
	for _, tc := range sourceWriteNativeCases() {
		first[tc.path] = sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 201)
	}
	opts := subjectVerificationOptions(t, store, nil)
	a, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		guard := func(ctx context.Context) error {
			switch tc.table {
			case "source_commits":
				return opts.SourceCommitCommands.AuthorizeSourceCommitRecording(ctx, a, integrationapp.RecordSourceCommitInput{RepositoryID: "repo", SHA: strings.Repeat("ab", 20)})
			case "source_branches":
				return opts.SourceBranchCommands.AuthorizeSourceBranchUpsert(ctx, a, integrationapp.UpsertSourceBranchInput{RepositoryID: "repo", Name: "main", HeadCommitID: "head"})
			default:
				return opts.PullRequestCommands.AuthorizePullRequestRecording(ctx, a, integrationapp.RecordPullRequestInput{RepositoryID: "repo", ProviderID: "17", Title: "Change", State: "open", HeadCommitID: "head"})
			}
		}
		if _, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", tc.path, "historical", []byte(tc.body), guard, func(context.Context) (int, any, error) {
			return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Provider is indexed. Keep its deliberately invalid value over the
	// command's byte bound but within PostgreSQL's compressed index capacity;
	// the other metadata still exceeds nine MB and must remain unread on replay.
	if _, err := p.Exec(t.Context(), `UPDATE source_repositories SET provider=repeat('p',65537),clone_url=repeat('private-',1200000);UPDATE source_commits SET author=repeat('private-',1200000);UPDATE source_branches SET protection_hash=repeat('private-',1200000);UPDATE pull_requests SET title=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE products SET name=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		assertRetentionHTTPReplay(t, first[tc.path], sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 201))
		if out := sourceWritesNativeHTTP(t, store, tc, "historical", tc.body, 201); !strings.Contains(out, "9007199254740993") {
			t.Fatal("historical source number rounded", out)
		}
	}
	for _, grant := range []struct {
		kind, id string
		allowed  bool
	}{{"product", "product", true}, {"project", "project", true}, {"product", "other-product", false}, {"project", "other-project", false}, {"release", "release", false}, {"tenant", "other", false}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		want := 403
		if grant.allowed {
			want = 201
		}
		for _, tc := range sourceWriteNativeCases() {
			sourceWritesNativeHTTP(t, store, tc, "original", tc.body, want)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 404)
	}
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE source_commits SET repository_id='other-repo'WHERE id='head'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		want := 404
		if tc.table == "source_commits" {
			want = 201
		}
		sourceWritesNativeHTTP(t, store, tc, "original", tc.body, want)
	}
	if _, err := p.Exec(t.Context(), `UPDATE source_commits SET repository_id='repo'WHERE id='head';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 403)
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceWriteNativeCases() {
		sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 401)
	}
	if got := sourceWritesNativeCounts(t, p); got != [7]int{3, 1, 1, 3, 0, 6, 0} {
		t.Fatal("source guard/replay wrote effects", got)
	}
}

func TestPostgresSourceWritesNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, tc := range sourceWriteNativeCases() {
		for _, stage := range []string{"domain", "audit", "replay", "commit"} {
			t.Run(tc.table+"-"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedSourceWritesNative(t, p)
				baseline := sourceWritesNativeCounts(t, p)
				table := tc.table
				if stage == "audit" || stage == "commit" {
					table = "audit_chain_entries"
				}
				if stage == "replay" {
					table = "idempotency_records"
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_source_write BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_source_write()", table)
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_source_write BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_source_write()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_source_write AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_source_write()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_source_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-source-write-failure';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				sourceWritesNativeHTTP(t, store, tc, "failed", tc.body, 500)
				want := baseline
				if stage == "domain" || stage == "audit" {
					want[6]++
				}
				if got := sourceWritesNativeCounts(t, p); got != want {
					t.Fatal("source write partially committed", got, want)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_source_write ON "+table); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if want[6] > baseline[6] {
					sourceWritesNativeHTTP(t, store, tc, key, tc.body, 409)
					key = "recovered"
				}
				one := sourceWritesNativeHTTP(t, store, tc, key, tc.body, 201)
				assertRetentionHTTPReplay(t, one, sourceWritesNativeHTTP(t, store, tc, key, tc.body, 201))
				want[map[string]int{"source_commits": 0, "source_branches": 1, "pull_requests": 2}[tc.table]]++
				want[3]++
				want[5]++
				if got := sourceWritesNativeCounts(t, p); got != want {
					t.Fatal("source recovery duplicated effects", got, want)
				}
			})
		}
	}
}

func TestPostgresSourceWritesNativeBranchReplacementRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"domain", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceWritesNative(t, p)
			tc := sourceWriteNativeCases()[1]
			original := sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 201)
			baseline := sourceWritesNativeCounts(t, p)
			table := "source_branches"
			trigger := `CREATE TRIGGER reject_source_update BEFORE UPDATE ON source_branches FOR EACH ROW EXECUTE FUNCTION reject_source_update()`
			if stage == "audit" {
				table = "audit_chain_entries"
				trigger = `CREATE TRIGGER reject_source_update BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_source_update()`
			}
			if stage == "replay" {
				table = "idempotency_records"
				trigger = `CREATE TRIGGER reject_source_update BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_source_update()`
			}
			if stage == "commit" {
				table = "audit_chain_entries"
				trigger = `CREATE CONSTRAINT TRIGGER reject_source_update AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_source_update()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_source_update()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-source-update-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			changed := `{"repository_id":"repo","name":"main","protected":false}`
			sourceWritesNativeHTTP(t, store, tc, "failed-update", changed, 500)
			want := baseline
			if stage == "domain" || stage == "audit" {
				want[6]++
			}
			if got := sourceWritesNativeCounts(t, p); got != want {
				t.Fatal("branch update partially committed", stage, got, want)
			}
			var head, protection string
			var protected bool
			if err := p.QueryRow(t.Context(), `SELECT head_commit_id,protected,protection_hash FROM source_branches WHERE tenant_id='tenant'AND repository_id='repo'AND name='main'`).Scan(&head, &protected, &protection); err != nil || head != "head" || !protected || protection != "opaque" {
				t.Fatal("failed update changed prior branch", head, protected, protection, err)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_source_update ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed-update"
			if want[6] > baseline[6] {
				sourceWritesNativeHTTP(t, store, tc, key, changed, 409)
				key = "recovered-update"
			}
			updated := sourceWritesNativeHTTP(t, store, tc, key, changed, 201)
			assertRetentionHTTPReplay(t, updated, sourceWritesNativeHTTP(t, store, tc, key, changed, 201))
			assertRetentionHTTPReplay(t, original, sourceWritesNativeHTTP(t, store, tc, "original", tc.body, 201))
			want[3]++
			want[5]++
			if got := sourceWritesNativeCounts(t, p); got != want {
				t.Fatal("branch update recovery duplicated effects", stage, got, want)
			}
			if err := p.QueryRow(t.Context(), `SELECT COALESCE(head_commit_id,''),protected,COALESCE(protection_hash,'')FROM source_branches WHERE tenant_id='tenant'AND repository_id='repo'AND name='main'`).Scan(&head, &protected, &protection); err != nil || head != "" || protected || protection != "" {
				t.Fatal("old replay reverted new branch state", head, protected, protection, err)
			}
		})
	}
}
