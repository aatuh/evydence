package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func questionnairePackageHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.QuestionnairePackageCommands == nil {
		t.Fatal("production remains Ledger-backed", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/questionnaire-packages", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) {
		t.Fatalf("status=%d want=%d Ledger canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	for _, marker := range []string{"private-prompt-marker", "private-payload-ref", "foreign-answer-secret", "do-not-load-manifest", "private package storage"} {
		if strings.Contains(w.Body.String(), marker) {
			t.Fatal("private metadata leaked", marker)
		}
	}
	return w.Body.String()
}
func TestPostgresQuestionnairePackageHTTPRestartReplayDowngradeAndAtomicFailure(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedDraftMetadata(t, p)
	if _, err := p.Exec(t.Context(), `DELETE FROM questionnaire_answer_library WHERE id='specific'`); err != nil {
		t.Fatal(err)
	}
	const body = `{"template_id":"template","package_id":"package","product_id":"product","release_id":"release"}`
	original := questionnairePackageHTTP(t, store, "saved", body, 201)
	if !strings.Contains(original, "private-global-answer") {
		t.Fatal("tenant grant lost global answer")
	}
	if replay := questionnairePackageHTTP(t, store, "saved", body, 201); replay != original || questionnairePackageCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("restart replay changed output/effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	questionnairePackageHTTP(t, store, "saved", body, 409)
	if scoped := questionnairePackageHTTP(t, store, "scoped", body, 201); strings.Contains(scoped, "private-global-answer") {
		t.Fatal("downgrade retained private answer")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	if restored := questionnairePackageHTTP(t, store, "saved", body, 201); restored != original {
		t.Fatal("restored authority changed replay")
	}
	questionnairePackageHTTP(t, store, "saved", `{"template_id":"template"}`, 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	questionnairePackageHTTP(t, store, "saved", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"insert", "audit", "commit"} {
		table := "questionnaire_packages"
		setup := `CREATE OR REPLACE FUNCTION reject_questionnaire_package_http() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private package storage';END$$;`
		if stage == "commit" {
			setup += `CREATE CONSTRAINT TRIGGER reject_questionnaire_package_http AFTER INSERT ON questionnaire_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_questionnaire_package_http()`
		} else {
			if stage == "audit" {
				table = "audit_chain_entries"
			}
			setup += `CREATE TRIGGER reject_questionnaire_package_http BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_questionnaire_package_http()`
		}
		if _, err := p.Exec(t.Context(), setup); err != nil {
			t.Fatal(err)
		}
		questionnairePackageHTTP(t, store, "failure-"+stage, body, 500)
		if questionnairePackageCounts(t, p) != [3]int{2, 2, 2} {
			t.Fatal("failed HTTP committed partial effects", stage)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_questionnaire_package_http ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	for i, bad := range []string{`{"template_id":null}`, `{"template_id":"template","package_id":null}`, `{"template_id":"template","unknown":true}`} {
		questionnairePackageHTTP(t, store, fmt.Sprint(i), bad, 400)
	}
	// Historical body-only keys carry no permission snapshot. They must not
	// replay private text through the new permission-bound endpoint.
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(t.Context(), actor, "POST", "/v1/questionnaire-packages", "legacy", []byte(body), func(context.Context, app.Repositories) (int, any, error) {
		return 201, map[string]string{"answer": "private-global-answer"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	questionnairePackageHTTP(t, store, "legacy", body, 409)
	if questionnairePackageCounts(t, p) != [3]int{2, 2, 3} {
		t.Fatal("historical replay created effects")
	}
}
func TestPostgresQuestionnairePackageFencePrecedesParentLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnairePackageCommands(store)
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
	go func() {
		done <- c.AuthorizeCreateQuestionnairePackage(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}, packageapp.CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "package", ProductID: "product", ReleaseID: "release"})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("package bypassed fence", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
			var waiting bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if !waiting {
				continue
			}
			if _, err := leader.Exec(ctx, `SELECT id FROM questionnaire_templates WHERE id='template' FOR UPDATE NOWAIT;SELECT id FROM customer_security_packages WHERE id='package' FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("parent lock preceded fence", err)
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
				t.Fatal("fence did not resume", ctx.Err())
			}
			return
		}
	}
}

func questionnairePackageCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var n [3]int
	if err := p.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM questionnaire_packages),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresQuestionnairePackageAssociationDoesNotFilterOrDownload(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE questionnaire_templates SET questions=jsonb_set(questions,'{2,evidence_type}','"note"') WHERE id='template';UPDATE customer_security_packages SET expires_at=now()-interval '1 day' WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildQuestionnairePackageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.CreateQuestionnairePackage(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}, packageapp.CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "package"})
	if err != nil || v.ProductID != "" || v.ReleaseID != "" || v.Responses[0].Answer != "private-global-answer" || !reflect.DeepEqual(v.Responses[2].EvidenceIDs, []string{"outside"}) {
		t.Fatal("association became an implicit filter/download", v, err)
	}
	var access int
	if err := p.QueryRow(t.Context(), `SELECT access_count FROM customer_security_packages WHERE id='package'`).Scan(&access); err != nil || access != 0 {
		t.Fatal("reference generation recorded download access", err)
	}
}

func TestPostgresQuestionnairePackageCurrentParentsStayLockedThroughCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnairePackageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
	in := packageapp.CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "package", ProductID: "product", ReleaseID: "release"}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = executor.WithBody(t.Context(), a, "POST", "/v1/questionnaire-packages", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateQuestionnairePackage(ctx, a, in)
		if err != nil {
			return 0, nil, err
		}
		for _, row := range []struct{ table, id string }{{"tenants", "tenant"}, {"products", "product"}, {"releases", "release"}, {"questionnaire_templates", "template"}, {"customer_security_packages", "package"}, {"questionnaire_answer_library", "specific"}, {"evidence_items", "b"}, {"projects", "project"}} {
			other, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = other.Exec(ctx, `SELECT id FROM `+row.table+` WHERE id=$1 FOR UPDATE NOWAIT`, row.id)
			_ = other.Rollback(context.WithoutCancel(ctx))
			var locked *pgconn.PgError
			if !errors.As(err, &locked) || locked.Code != "55P03" {
				t.Fatal("selected row unlocked before commit", row, err)
			}
		}
		return 201, v, nil
	})
	if err != nil || questionnairePackageCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("locked command failed", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE customer_security_packages SET tenant_id='other',product_id='other-product',release_id=NULL WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeCreateQuestionnairePackage(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("foreign association visible", err)
	}
}
func TestPostgresQuestionnairePackageScopedSelectionAndLegacyHash(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnairePackageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildQuestionnairePackageCommands(nil); err == nil {
		t.Fatal("nil transactions accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:write"}}}}
	in := packageapp.CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "package", ProductID: "product", ReleaseID: "release"}
	v, err := c.CreateQuestionnairePackage(t.Context(), a, in)
	if err != nil || len(v.Responses) != 3 || v.Responses[0].Answer != "Reviewed answer" || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, []string{"b"}) || !reflect.DeepEqual(v.Responses[1].EvidenceIDs, []string{"a"}) || len(v.Responses[2].EvidenceIDs) != 0 {
		t.Fatal("selection changed", v, err)
	}
	legacy := make([]domain.QuestionnaireResponse, len(v.Responses))
	for i, r := range v.Responses {
		legacy[i] = domain.QuestionnaireResponse{QuestionID: r.QuestionID, Answer: r.Answer, EvidenceIDs: r.EvidenceIDs, Limitations: r.Limitations}
	}
	hash, err := application.NormalizedJSONHash(legacy)
	if err != nil || hash != v.ManifestHash || questionnairePackageCounts(t, p) != [3]int{1, 1, 0} {
		t.Fatal("legacy hash/atomic effects differ", err)
	}
	in.ProductID = ""
	v, err = c.CreateQuestionnairePackage(t.Context(), a, in)
	if err != nil || v.ProductID != "" || v.Responses[0].Answer == "Reviewed answer" || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, []string{"b"}) {
		t.Fatal("resolved product changed raw selection", v, err)
	}
	for _, bad := range []packageapp.CreateQuestionnairePackageInput{{TemplateID: "template", PackageID: "package"}, {TemplateID: "template", PackageID: "package", ProductID: "second-product"}, {TemplateID: "template", PackageID: "missing", ProductID: "product"}, {TemplateID: "template", PackageID: "package", ProductID: "product", ReleaseID: "second-release"}} {
		if v, err := c.CreateQuestionnairePackage(t.Context(), a, bad); err == nil || v.ID != "" || questionnairePackageCounts(t, p) != [3]int{2, 2, 0} {
			t.Fatal("association widened scope", bad, err)
		}
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: "package", Scopes: []string{"package:write"}}}
	if err := c.AuthorizeCreateQuestionnairePackage(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("package-only grant authorized evidence selection", err)
	}
}
func TestPostgresQuestionnairePackagePrivateFieldsBoundsAndRollback(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnairePackageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:write"}}}}
	in := packageapp.CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "package", ProductID: "product", ReleaseID: "release"}
	if _, err := p.Exec(t.Context(), `UPDATE questionnaire_templates SET questions=jsonb_set(questions,'{0,prompt}',to_jsonb(repeat('private-prompt-marker',400000))) WHERE id='template';UPDATE questionnaire_answer_library SET answer=repeat('private-global-answer',400000) WHERE id='global';UPDATE customer_security_packages SET manifest=jsonb_build_object('private',repeat('do-not-load-manifest',400000)) WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	v, err := c.CreateQuestionnairePackage(t.Context(), a, in)
	if err != nil || v.Responses[0].Answer != "Reviewed answer" {
		t.Fatal("unused text crossed bounded port", err)
	}
	for _, stage := range []string{"questionnaire_packages", "audit_chain_entries", "commit"} {
		table := stage
		setup := `CREATE OR REPLACE FUNCTION reject_questionnaire_package_stage() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private package storage';END$$;`
		if stage == "commit" {
			table = "questionnaire_packages"
			setup += `CREATE CONSTRAINT TRIGGER reject_questionnaire_package_stage AFTER INSERT ON questionnaire_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_questionnaire_package_stage()`
		} else {
			setup += `CREATE TRIGGER reject_questionnaire_package_stage BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_questionnaire_package_stage()`
		}
		if _, err := p.Exec(t.Context(), setup); err != nil {
			t.Fatal(err)
		}
		if v, err := c.CreateQuestionnairePackage(t.Context(), a, in); err == nil || v.ID != "" || questionnairePackageCounts(t, p) != [3]int{1, 1, 0} {
			t.Fatal("partial package escaped", stage, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_questionnaire_package_stage ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"outside", "foreign", "missing"} {
		if _, err := p.Exec(t.Context(), `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY[$1] WHERE id='specific'`, id); err != nil {
			t.Fatal(err)
		}
		if v, err := c.CreateQuestionnairePackage(t.Context(), a, in); err == nil || v.ID != "" || questionnairePackageCounts(t, p) != [3]int{1, 1, 0} {
			t.Fatal("foreign citation accepted", id, err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY['b'],answer=repeat('x',65537) WHERE id='specific'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateQuestionnairePackage(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("oversized winner read", err)
	}
}
func TestPostgresQuestionnairePackageFocusedWriterChecksHashAndQuestionIdentity(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnairePackageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.CreateQuestionnairePackage(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}, packageapp.CreateQuestionnairePackageInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hash", "question", "oversized"} {
		bad := v
		bad.ID = "forged"
		bad.Responses = append([]packagedomain.QuestionnaireResponse(nil), v.Responses...)
		switch kind {
		case "hash":
			bad.ManifestHash = "sha256:forged"
		case "question":
			bad.Responses[0].QuestionID = "unexpected"
		case "oversized":
			bad.Responses[0].Answer = strings.Repeat("x", 65537)
		}
		if kind != "hash" {
			raw, err := packageapp.EncodeQuestionnaireResponses(bad.Responses)
			if err != nil {
				t.Fatal(err)
			}
			bad.ManifestHash, err = application.NormalizedJSONHash(json.RawMessage(raw))
			if err != nil {
				t.Fatal(err)
			}
		}
		err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
			writer, ok := repos.Enterprise.(interface {
				InsertFocusedQuestionnairePackage(context.Context, packagedomain.QuestionnairePackage) error
			})
			if !ok {
				t.Fatal("focused writer absent")
			}
			return writer.InsertFocusedQuestionnairePackage(ctx, bad)
		})
		if !errors.Is(err, packageapp.ErrValidation) || questionnairePackageCounts(t, p) != [3]int{1, 1, 0} {
			t.Fatal("forged document stored", kind, err)
		}
	}
}
