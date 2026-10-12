package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func seedAnswerLibrary(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSummaryMetadata(t, p)
	seedQTemplateControls(t, p)
}
func answerLibraryCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM questionnaire_answer_library),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func answerLibraryInput() packageapp.CreateAnswerLibraryEntryInput {
	return packageapp.CreateAnswerLibraryEntryInput{QuestionID: " q ", ControlID: " control ", ProductID: "product", ReleaseID: "release", Answer: " Draft answer ", EvidenceIDs: []string{" a ", "a"}}
}
func answerLibraryActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:write"}}}}
}
func TestPostgresAnswerLibraryWritesAndValidatesCurrentParentsWithoutPayloads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedAnswerLibrary(t, p)
	c, err := BuildAnswerLibraryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAnswerLibraryCommands(nil); err == nil {
		t.Fatal("missing transactions accepted")
	}
	a, in := answerLibraryActor(), answerLibraryInput()
	v, err := c.CreateAnswerLibraryEntry(t.Context(), a, in)
	if err != nil || v.Answer != "Draft answer" || !reflect.DeepEqual(v.EvidenceIDs, []string{"a", "a"}) || !reflect.DeepEqual(v.Limitations, []string{packageapp.AnswerLibraryReviewLimitation}) {
		t.Fatal("focused answer differs", v, err)
	}
	var auditActor, auditType, hash string
	if err := p.QueryRow(t.Context(), `SELECT actor_id,entry_type,coalesce(payload_hash,'')FROM audit_chain_entries WHERE subject_id=$1`, v.ID).Scan(&auditActor, &auditType, &hash); err != nil || auditActor != "user" || auditType != "questionnaire_answer_library.created" || hash != "" {
		t.Fatal("audit shape differs", err)
	}
	// Inferred product ownership authorizes release-only input but does not
	// populate raw response coordinates or widen explicit product filtering.
	in.ProductID = ""
	in.EvidenceIDs = []string{"b"}
	v, err = c.CreateAnswerLibraryEntry(t.Context(), a, in)
	if err != nil || v.ProductID != "" || v.ReleaseID != "release" {
		t.Fatal("release-only compatibility", v, err)
	}
	in.ProductID = "product"
	if _, err := c.CreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("inferred evidence product widened raw matching", err)
	}
	for _, id := range []string{"foreign", "outside", "missing"} {
		in = answerLibraryInput()
		in.EvidenceIDs = []string{id}
		if _, err := c.CreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatal("foreign/outside citation accepted", id, err)
		}
	}
	in = answerLibraryInput()
	in.ControlID = "foreign"
	if _, err := c.CreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("foreign control accepted", err)
	}
	in = answerLibraryInput()
	in.ProductID = "second-product"
	if _, err := c.CreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("root mismatch accepted", err)
	}
	in = answerLibraryInput()
	for _, sql := range []string{`UPDATE evidence_items SET project_id='missing' WHERE id='a'`, `UPDATE evidence_items SET project_id='project',build_id='missing' WHERE id='a'`, `UPDATE evidence_items SET build_id=NULL,deployment_id='missing' WHERE id='a'`} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		if _, err := c.CreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, packageapp.ErrConflict) {
			t.Fatal("stale evidence parent accepted", err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET deployment_id=NULL WHERE id='a';UPDATE security_controls SET framework_id='foreign-framework' WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("foreign framework accepted", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE security_controls SET framework_id='framework' WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	if err := (answerLibraryTransactions{store}).ExecuteAnswerLibrary(t.Context(), "tenant", func(ctx context.Context, tx packageapp.AnswerLibraryTransaction) error {
		s, err := tx.ReadAnswerLibraryScope(ctx, "tenant", "product", "release")
		if err != nil {
			return err
		}
		if err := tx.ValidateAnswerLibraryReferences(ctx, s, "control", []string{"a"}); err != nil {
			return err
		}
		for table, id := range map[string]string{"tenants": "tenant", "products": "product", "projects": "project", "releases": "release", "evidence_items": "a", "security_controls": "control", "control_frameworks": "framework"} {
			other, err := p.Begin(ctx)
			if err != nil {
				return err
			}
			_, err = other.Exec(ctx, `SELECT id FROM `+table+` WHERE id=$1 FOR UPDATE NOWAIT`, id)
			_ = other.Rollback(context.WithoutCancel(ctx))
			if err == nil {
				t.Fatal("selected parent not locked", table)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if answerLibraryCounts(t, p) != [3]int{2, 2, 0} {
		t.Fatal("failed command published")
	}
}
func TestPostgresAnswerLibraryRollbackAndDirectWriterValidation(t *testing.T) {
	for _, stage := range []string{"insert", "audit", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedAnswerLibrary(t, p)
			c, err := BuildAnswerLibraryCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			table := "questionnaire_answer_library"
			if stage == "audit" {
				table = "audit_chain_entries"
			}
			trigger := `CREATE TRIGGER reject_answer BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_answer()`
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_answer AFTER INSERT ON questionnaire_answer_library DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_answer()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_answer()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private answer storage';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			v, err := c.CreateAnswerLibraryEntry(t.Context(), answerLibraryActor(), answerLibraryInput())
			if err == nil || v.ID != "" || answerLibraryCounts(t, p) != [3]int{} {
				t.Fatal("failed write committed", stage, v, err)
			}
		})
	}
	store, p := openHTMLReportWiringStore(t)
	seedAnswerLibrary(t, p)
	for _, kind := range []string{"schema", "noncanonical", "unsorted", "foreign", "parent", "encoded"} {
		in, _ := packageapp.NormalizeAnswerLibraryInput(answerLibraryInput())
		v := packagedomain.QuestionnaireAnswerLibraryEntry{ID: "bad", TenantID: "tenant", QuestionID: in.QuestionID, ControlID: in.ControlID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Answer: in.Answer, EvidenceIDs: in.EvidenceIDs, Limitations: in.Limitations, SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: time.Now().UTC()}
		want := packageapp.ErrValidation
		switch kind {
		case "schema":
			v.SchemaVersion = "bad"
		case "noncanonical":
			v.Answer = " Draft "
		case "unsorted":
			v.EvidenceIDs = []string{"b", "a"}
		case "foreign":
			v.ControlID = "foreign"
			want = packageapp.ErrNotFound
		case "parent":
			v.EvidenceIDs = []string{"foreign"}
			want = packageapp.ErrNotFound
		case "encoded":
			v.Limitations = make([]string, 20)
			for i := range v.Limitations {
				v.Limitations[i] = strings.Repeat("<", 65536)
			}
		}
		err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
			r, ok := repos.Enterprise.(interface {
				InsertFocusedAnswerLibraryEntry(context.Context, packagedomain.QuestionnaireAnswerLibraryEntry) error
			})
			if !ok {
				t.Fatal("focused writer missing")
			}
			return r.InsertFocusedAnswerLibraryEntry(ctx, v)
		})
		if !errors.Is(err, want) || answerLibraryCounts(t, p) != [3]int{} {
			t.Fatal("forged direct write committed", kind, err)
		}
	}
}
func answerLibraryHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.AnswerLibraryCommands == nil {
		t.Fatal("answer write still Ledger-backed", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/questionnaire-answer-library", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "payload_ref") {
		t.Fatalf("unsafe/legacy answer status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	return w.Body.String()
}
func TestPostgresAnswerLibraryHTTPRestartReplayCurrentOwnershipAndRollback(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedAnswerLibrary(t, p)
	const body = `{"question_id":"q","control_id":"control","product_id":"product","release_id":"release","answer":"Draft answer","evidence_ids":["a","a"]}`
	one, two := answerLibraryHTTP(t, store, "answer", body, 201), answerLibraryHTTP(t, store, "answer", body, 201)
	var x, y any
	if json.Unmarshal([]byte(one), &x) != nil || json.Unmarshal([]byte(two), &y) != nil || !reflect.DeepEqual(x, y) || answerLibraryCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("restart replay duplicated effects")
	}
	answerLibraryHTTP(t, store, "answer", strings.Replace(body, "Draft answer", "Other", 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	answerLibraryHTTP(t, store, "answer", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='release',resource_id='release' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	answerLibraryHTTP(t, store, "answer", body, 201)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET project_id='missing' WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	answerLibraryHTTP(t, store, "answer", body, 409)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET project_id='project' WHERE id='a';UPDATE security_controls SET framework_id='foreign-framework' WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	answerLibraryHTTP(t, store, "answer", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE security_controls SET framework_id='framework' WHERE id='control';CREATE FUNCTION reject_answer_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private answer storage';END$$;CREATE CONSTRAINT TRIGGER reject_answer_http AFTER INSERT ON questionnaire_answer_library DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_answer_http()`); err != nil {
		t.Fatal(err)
	}
	answerLibraryHTTP(t, store, "failed", body, 500)
	if answerLibraryCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("failed HTTP answer committed replay/audit")
	}
}
func TestPostgresAnswerLibraryFencePrecedesCitationLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedAnswerLibrary(t, p)
	c, err := BuildAnswerLibraryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leader, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.AuthorizeCreateAnswerLibraryEntry(ctx, answerLibraryActor(), answerLibraryInput()) }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("guard bypassed worker fence", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				continue
			}
			if _, err := leader.Exec(ctx, `SELECT id FROM evidence_items WHERE id='a' FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("evidence locked before fence", err)
			}
			if err := leader.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("guard did not resume", ctx.Err())
			}
			return
		}
	}
}
