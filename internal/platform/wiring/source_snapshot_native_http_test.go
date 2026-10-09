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

func snapshotNativeBody(t *testing.T, name, project string, mask int) string {
	t.Helper()
	body := map[string]any{"project_id": project, "repository": map[string]any{"full_name": name, "clone_url": " opaque ", "default_branch": " main "}}
	if mask&1 != 0 {
		body["commit"] = map[string]any{"sha": strings.Repeat("AB", 20), "author": " Author ", "message": " private snapshot message "}
	}
	if mask&2 != 0 {
		body["branch"] = map[string]any{"name": " main ", "protected": true, "protection_hash": " opaque "}
	}
	if mask&4 != 0 {
		body["pull_request"] = map[string]any{"provider_id": " 17 ", "title": " Change ", "state": " open ", "source_branch": " feature ", "target_branch": " main ", "review_decision": " recorded "}
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func snapshotNativeInput() integrationapp.SourceSnapshotInput {
	return integrationapp.SourceSnapshotInput{ProjectID: "project", Repository: integrationapp.SourceSnapshotRepositoryInput{FullName: "org/api", CloneURL: "opaque", DefaultBranch: "main"}, Commit: &integrationapp.SourceSnapshotCommitInput{SHA: strings.Repeat("ab", 20), Author: "Author", Message: " private snapshot message "}, Branch: &integrationapp.SourceSnapshotBranchInput{Name: "main", Protected: true, ProtectionHash: "opaque"}, PullRequest: &integrationapp.SourceSnapshotPullRequestInput{ProviderID: "17", Title: "Change", State: "open", SourceBranch: "feature", TargetBranch: "main", ReviewDecision: "recorded"}}
}

func snapshotNativeHTTP(t *testing.T, store *postgres.Store, provider, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	if o.SourceSnapshotCommands == nil {
		t.Fatal("missing native snapshot composition")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/collectors/"+provider+"/source-snapshots", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), "private snapshot message") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native snapshot provider=%s status=%d want=%d canary=%t: %s", provider, w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("snapshot lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("snapshot lost problem contract")
	}
	return w.Body.String()
}

func snapshotNativeCounts(t *testing.T, p *pgxpool.Pool) [8]int {
	t.Helper()
	var n [8]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM source_repositories),(SELECT count(*)FROM source_commits),(SELECT count(*)FROM source_branches),(SELECT count(*)FROM pull_requests),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6], &n[7]); err != nil {
		t.Fatal(err)
	}
	return n
}

type snapshotPublicData struct {
	Repository  domain.SourceRepository `json:"repository"`
	Commit      domain.SourceCommit     `json:"commit"`
	Branch      domain.SourceBranch     `json:"branch"`
	PullRequest domain.PullRequest      `json:"pull_request"`
}

func snapshotDecodePublic(t *testing.T, raw string) snapshotPublicData {
	t.Helper()
	var e struct {
		Data snapshotPublicData `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	return e.Data
}

func TestPostgresSourceSnapshotNativeHTTPAllOptionalComponentsAndRestartReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	for _, provider := range []string{"github", "gitlab"} {
		for mask := 0; mask < 8; mask++ {
			name := fmt.Sprintf("org/%s-%d", provider, mask)
			key := fmt.Sprintf("optional-%d", mask)
			body := snapshotNativeBody(t, name, " project ", mask)
			one := snapshotNativeHTTP(t, store, provider, key, body, 201)
			v := snapshotDecodePublic(t, one)
			if v.Repository.ID == "" || v.Repository.TenantID != "tenant" || v.Repository.ProjectID != "project" || v.Repository.Provider != provider || v.Repository.FullName != name || v.Repository.CloneURL != "opaque" || v.Repository.DefaultBranch != "main" || v.Repository.SchemaVersion != domain.SourceRepositorySchemaVersion || v.Repository.CreatedAt.IsZero() || v.Repository.CreatedAt.Nanosecond()%1000 != 0 {
				t.Fatal("repository snapshot contract changed", one)
			}
			if mask&1 != 0 {
				if v.Commit.ID == "" || v.Commit.TenantID != "tenant" || v.Commit.RepositoryID != v.Repository.ID || v.Commit.SHA != strings.Repeat("ab", 20) || v.Commit.Author != "Author" || v.Commit.MessageHash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(" private snapshot message "))) || v.Commit.SchemaVersion != domain.SourceCommitSchemaVersion || v.Commit.CommittedAt != v.Commit.CreatedAt || v.Commit.CreatedAt.IsZero() || v.Commit.CreatedAt.Nanosecond()%1000 != 0 {
					t.Fatal("commit snapshot changed", one)
				}
			} else if v.Commit != (domain.SourceCommit{}) {
				t.Fatal("omitted commit lost zero object", one)
			}
			if mask&2 != 0 {
				if v.Branch.ID == "" || v.Branch.TenantID != "tenant" || v.Branch.RepositoryID != v.Repository.ID || v.Branch.Name != "main" || v.Branch.HeadCommitID != v.Commit.ID || !v.Branch.Protected || v.Branch.ProtectionHash != "opaque" || v.Branch.SchemaVersion != domain.SourceBranchSchemaVersion || v.Branch.CreatedAt.IsZero() || v.Branch.CreatedAt.Nanosecond()%1000 != 0 {
					t.Fatal("branch snapshot changed", one)
				}
			} else if v.Branch != (domain.SourceBranch{}) {
				t.Fatal("omitted branch lost zero object", one)
			}
			if mask&4 != 0 {
				if v.PullRequest.ID == "" || v.PullRequest.TenantID != "tenant" || v.PullRequest.RepositoryID != v.Repository.ID || v.PullRequest.Provider != provider || v.PullRequest.ProviderID != "17" || v.PullRequest.Title != "Change" || v.PullRequest.State != "open" || v.PullRequest.HeadCommitID != v.Commit.ID || v.PullRequest.SourceBranch != "feature" || v.PullRequest.TargetBranch != "main" || v.PullRequest.ReviewDecision != "recorded" || v.PullRequest.SchemaVersion != domain.PullRequestSchemaVersion || v.PullRequest.CreatedAt.IsZero() || v.PullRequest.CreatedAt.Nanosecond()%1000 != 0 {
					t.Fatal("PR snapshot changed", one)
				}
			} else if v.PullRequest != (domain.PullRequest{}) {
				t.Fatal("omitted PR lost zero object", one)
			}
			assertRetentionHTTPReplay(t, one, snapshotNativeHTTP(t, store, provider, key, body, 201))
			snapshotNativeHTTP(t, store, provider, key, body+" ", 409)
		}
	}
	if got := snapshotNativeCounts(t, p); got != [8]int{16, 8, 8, 8, 40, 0, 16, 0} {
		t.Fatal("optional/replay effects changed", got)
	}
	var wrongActor, leaked bool
	if err := p.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM audit_chain_entries WHERE actor_id<>'user'OR actor_type<>'human_user'),EXISTS(SELECT 1 FROM source_commits c WHERE row_to_json(c)::text LIKE '%private snapshot message%')OR EXISTS(SELECT 1 FROM audit_chain_entries a WHERE row_to_json(a)::text LIKE '%private snapshot message%')`).Scan(&wrongActor, &leaked); err != nil || wrongActor || leaked {
		t.Fatal("snapshot lost caller or persisted raw message", wrongActor, leaked, err)
	}
}

func TestPostgresSourceSnapshotNativeHTTPReplayUsesOnlyCurrentRepositoryAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	body := snapshotNativeBody(t, "org/api", "project", 7)
	first := map[string]string{}
	o := subjectVerificationOptions(t, store, nil)
	a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "gitlab"} {
		first[provider] = snapshotNativeHTTP(t, store, provider, "original", body, 201)
		if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/collectors/"+provider+"/source-snapshots", "historical", []byte(body), func(ctx context.Context) error {
			return o.SourceSnapshotCommands.AuthorizeSourceSnapshot(ctx, a, provider, snapshotNativeInput())
		}, func(context.Context) (int, any, error) {
			return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE source_repositories SET clone_url=repeat('private-',1200000),default_branch=repeat('private-',1200000);UPDATE source_commits SET author=repeat('private-',1200000);UPDATE source_branches SET protection_hash=repeat('private-',1200000);UPDATE pull_requests SET title=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE products SET name=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "gitlab"} {
		assertRetentionHTTPReplay(t, first[provider], snapshotNativeHTTP(t, store, provider, "original", body, 201))
		if out := snapshotNativeHTTP(t, store, provider, "historical", body, 201); !strings.Contains(out, "9007199254740993") {
			t.Fatal("snapshot historical number rounded", out)
		}
		snapshotNativeHTTP(t, store, provider, "oversized-fresh", body, 409)
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
		for _, provider := range []string{"github", "gitlab"} {
			snapshotNativeHTTP(t, store, provider, "original", body, want)
			snapshotNativeHTTP(t, store, provider, "submitted-other", snapshotNativeBody(t, "org/api", "other-project", 7), 403)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "gitlab"} {
		snapshotNativeHTTP(t, store, provider, "original", body, 404)
	}
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "gitlab"} {
		snapshotNativeHTTP(t, store, provider, "original", body, 403)
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "gitlab"} {
		snapshotNativeHTTP(t, store, provider, "original", body, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "gitlab"} {
		snapshotNativeHTTP(t, store, provider, "original", body, 401)
	}
	if got := snapshotNativeCounts(t, p); got != [8]int{2, 2, 2, 2, 8, 0, 4, 2} {
		t.Fatal("snapshot replay/denial changed effects", got)
	}
}

func TestPostgresSourceSnapshotNativeHTTPRollbackAndRecoveryAtEveryStage(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceRepositoryNative(t, p)
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_snapshot()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-snapshot-write-failure';END$$`); err != nil {
				t.Fatal(err)
			}
			for _, stage := range []string{"repository", "commit", "branch", "pull-request", "late-audit", "replay", "outer-commit"} {
				baseline := snapshotNativeCounts(t, p)
				table := map[string]string{"repository": "source_repositories", "commit": "source_commits", "branch": "source_branches", "pull-request": "pull_requests", "late-audit": "audit_chain_entries", "replay": "idempotency_records", "outer-commit": "audit_chain_entries"}[stage]
				trigger := fmt.Sprintf("CREATE TRIGGER reject_native_snapshot BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_snapshot()", table)
				if stage == "late-audit" {
					trigger = `CREATE TRIGGER reject_native_snapshot BEFORE INSERT ON audit_chain_entries FOR EACH ROW WHEN(NEW.entry_type='pull_request.recorded')EXECUTE FUNCTION reject_native_snapshot()`
				}
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_native_snapshot BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_snapshot()`
				}
				if stage == "outer-commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_native_snapshot AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_snapshot()`
				}
				if _, err := p.Exec(t.Context(), trigger); err != nil {
					t.Fatal(err)
				}
				body := snapshotNativeBody(t, "org/failure-"+stage, "project", 7)
				key := "failed-" + stage
				snapshotNativeHTTP(t, store, provider, key, body, 500)
				want := baseline
				if stage != "replay" && stage != "outer-commit" {
					want[7]++
				}
				if got := snapshotNativeCounts(t, p); got != want {
					t.Fatal("partial snapshot committed", stage, got, want)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_snapshot ON "+table); err != nil {
					t.Fatal(err)
				}
				if want[7] > baseline[7] {
					snapshotNativeHTTP(t, store, provider, key, body, 409)
					key = "recovered-" + stage
				}
				one := snapshotNativeHTTP(t, store, provider, key, body, 201)
				assertRetentionHTTPReplay(t, one, snapshotNativeHTTP(t, store, provider, key, body, 201))
				for i := 0; i < 4; i++ {
					want[i]++
				}
				want[4] += 4
				want[6]++
				if got := snapshotNativeCounts(t, p); got != want {
					t.Fatal("snapshot recovery duplicated effects", stage, got, want)
				}
			}
		})
	}
}

func TestPostgresSourceSnapshotNativeHTTPLateFailurePreservesExistingBranch(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceRepositoryNative(t, p)
			body := snapshotNativeBody(t, "org/api", "project", 7)
			original := snapshotNativeHTTP(t, store, provider, "original", body, 201)
			branchID := snapshotDecodePublic(t, original).Branch.ID
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_snapshot_update()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-snapshot-update-failure';END$$`); err != nil {
				t.Fatal(err)
			}
			readBranch := func() string {
				t.Helper()
				var raw string
				if err := p.QueryRow(t.Context(), `SELECT row_to_json(b)::text FROM source_branches b WHERE id=$1`, branchID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			for i, stage := range []string{"branch-update", "pull-request", "late-audit", "replay", "outer-commit"} {
				before := readBranch()
				baseline := snapshotNativeCounts(t, p)
				table := map[string]string{"branch-update": "source_branches", "pull-request": "pull_requests", "late-audit": "audit_chain_entries", "replay": "idempotency_records", "outer-commit": "audit_chain_entries"}[stage]
				trigger := `CREATE TRIGGER reject_snapshot_update BEFORE UPDATE ON source_branches FOR EACH ROW EXECUTE FUNCTION reject_snapshot_update()`
				if stage == "pull-request" {
					trigger = `CREATE TRIGGER reject_snapshot_update BEFORE INSERT ON pull_requests FOR EACH ROW EXECUTE FUNCTION reject_snapshot_update()`
				}
				if stage == "late-audit" {
					trigger = `CREATE TRIGGER reject_snapshot_update BEFORE INSERT ON audit_chain_entries FOR EACH ROW WHEN(NEW.entry_type='pull_request.recorded')EXECUTE FUNCTION reject_snapshot_update()`
				}
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_snapshot_update BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_snapshot_update()`
				}
				if stage == "outer-commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_snapshot_update AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_snapshot_update()`
				}
				if _, err := p.Exec(t.Context(), trigger); err != nil {
					t.Fatal(err)
				}
				var input map[string]any
				if err := json.Unmarshal([]byte(body), &input); err != nil {
					t.Fatal(err)
				}
				input["commit"].(map[string]any)["sha"] = strings.Repeat(fmt.Sprintf("%x", i+2), 40)
				input["branch"].(map[string]any)["protected"] = false
				input["branch"].(map[string]any)["protection_hash"] = "changed"
				input["pull_request"].(map[string]any)["state"] = "merged"
				raw, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				changed := string(raw)
				key := "failed-" + stage
				snapshotNativeHTTP(t, store, provider, key, changed, 500)
				want := baseline
				if stage != "replay" && stage != "outer-commit" {
					want[7]++
				}
				if got := snapshotNativeCounts(t, p); got != want || readBranch() != before {
					t.Fatal("late failure changed branch or partial snapshot", stage, got, want)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_snapshot_update ON "+table); err != nil {
					t.Fatal(err)
				}
				if want[7] > baseline[7] {
					snapshotNativeHTTP(t, store, provider, key, changed, 409)
					key = "recovered-" + stage
				}
				one := snapshotNativeHTTP(t, store, provider, key, changed, 201)
				v := snapshotDecodePublic(t, one)
				if v.Branch.ID != branchID || v.Branch.Protected || v.Branch.ProtectionHash != "changed" || v.Branch.HeadCommitID != v.Commit.ID || v.PullRequest.State != "merged" {
					t.Fatal("branch replacement recovery failed", one)
				}
				updated := readBranch()
				assertRetentionHTTPReplay(t, one, snapshotNativeHTTP(t, store, provider, key, changed, 201))
				assertRetentionHTTPReplay(t, original, snapshotNativeHTTP(t, store, provider, "original", body, 201))
				if readBranch() != updated {
					t.Fatal("old snapshot replay reverted branch", stage)
				}
				want[1]++
				want[3]++
				want[4] += 3
				want[6]++
				if got := snapshotNativeCounts(t, p); got != want {
					t.Fatal("late snapshot recovery duplicated effects", stage, got, want)
				}
			}
		})
	}
}
