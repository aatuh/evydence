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

func seedDraftMetadata(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSummaryMetadata(t, p)
	if _, err := p.Exec(t.Context(), `
INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version)VALUES('framework','tenant','Framework','framework','1','active','control-framework.v1');
INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)VALUES('control','tenant','framework','C','Control','Private objective','[]','[]','[]','security-control.v1');
INSERT INTO control_evidence(id,tenant_id,control_id,evidence_type,subject_type,subject_id,product_id,release_id,confidence,schema_version)VALUES('link','tenant','control','sbom','evidence','b','product','release','recorded','control-evidence.v1');
INSERT INTO questionnaire_templates(id,tenant_id,name,version,questions,schema_version,created_at)VALUES('template','tenant','Questionnaire','1','[{"id":"q1","prompt":"private-prompt-marker","control_id":"control","evidence_type":"sbom"},{"id":"q2","prompt":"private-prompt-marker","evidence_type":"build"},{"id":"q3","prompt":"private-prompt-marker","evidence_type":"missing"}]','questionnaire-template.v1',now());
INSERT INTO questionnaire_answer_library(id,tenant_id,question_id,control_id,evidence_type,product_id,release_id,answer,evidence_ids,limitations,schema_version,created_at)
VALUES('global','tenant','q1',NULL,NULL,NULL,NULL,'private-global-answer','{}','{}','questionnaire-answer-library.v1',now()+interval '1 hour'),
('specific','tenant','q1','control','sbom','product','release','Reviewed answer',ARRAY['b'],ARRAY['Human review'],'questionnaire-answer-library.v1',now()),
('foreign-answer','other','q1',NULL,NULL,NULL,NULL,'foreign-answer-secret','{}','{}','questionnaire-answer-library.v1',now()+interval '2 hours')`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresDraftFocusedInsertRejectsInvalidDocuments(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnaireDraftCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.CreateQuestionnaireDraft(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:read"}}, packageapp.CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hash", "answer", "limitations", "encoded"} {
		t.Run(kind, func(t *testing.T) {
			bad := v
			bad.ID = "forged-draft"
			bad.Responses = append([]packagedomain.QuestionnaireResponse(nil), v.Responses...)
			switch kind {
			case "hash":
				bad.ManifestHash = "sha256:forged"
			case "answer":
				bad.Responses[0].Answer = strings.Repeat("x", packageapp.MaxQuestionnaireDraftAnswerBytes+1)
			case "limitations":
				bad.Responses[0].Limitations = make([]string, packageapp.MaxQuestionnaireDraftLimitations+1)
			case "encoded":
				bad.Limitations = []string{strings.Repeat("x", packageapp.MaxGeneratedReportBytes+1)}
			}
			if kind != "hash" {
				encoded, err := packageapp.EncodeQuestionnaireResponses(bad.Responses)
				if err != nil {
					t.Fatal(err)
				}
				bad.ManifestHash, err = application.NormalizedJSONHash(json.RawMessage(encoded))
				if err != nil {
					t.Fatal(err)
				}
			}
			err = app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
				writer, ok := repos.Future.(interface {
					InsertFocusedQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error
				})
				if !ok {
					t.Fatal("focused writer missing")
				}
				return writer.InsertFocusedQuestionnaireDraft(ctx, bad)
			})
			if !errors.Is(err, packageapp.ErrValidation) || draftCounts(t, p) != [3]int{1, 1, 0} {
				t.Fatal("invalid draft document stored", err)
			}
		})
	}
}

func TestPostgresDraftFencePrecedesTemplateLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnaireDraftCommands(store)
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
		done <- c.AuthorizeCreateQuestionnaireDraft(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:read"}}, packageapp.CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("draft bypassed worker fence", err)
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
			if _, err := leader.Exec(ctx, `SELECT id FROM questionnaire_templates WHERE id='template' FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("template lock precedes worker fence", err)
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
				t.Fatal("draft fence did not resume", ctx.Err())
			}
			return
		}
	}
}
func draftCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := p.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM questionnaire_drafts),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestPostgresDraftUsesScopedAnswersControlEvidenceAndLegacyHash(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnaireDraftCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildQuestionnaireDraftCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:read"}}}}
	in := packageapp.CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"}
	v, err := c.CreateQuestionnaireDraft(t.Context(), a, in)
	if err != nil || len(v.Responses) != 3 || v.Responses[0].Answer != "Reviewed answer" || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, []string{"b"}) || !reflect.DeepEqual(v.Responses[1].EvidenceIDs, []string{"a"}) || len(v.Responses[2].EvidenceIDs) != 0 {
		t.Fatal("draft selection/fallback differs", v, err)
	}
	legacy := make([]domain.QuestionnaireResponse, len(v.Responses))
	for i, r := range v.Responses {
		legacy[i] = domain.QuestionnaireResponse{QuestionID: r.QuestionID, Answer: r.Answer, EvidenceIDs: r.EvidenceIDs, Limitations: r.Limitations}
	}
	want, err := application.NormalizedJSONHash(legacy)
	if err != nil || want != v.ManifestHash {
		t.Fatal("legacy normalized hash differs", err)
	}
	var hash, actor string
	if err := p.QueryRow(t.Context(), `SELECT d.manifest_hash,a.actor_id FROM questionnaire_drafts d JOIN audit_chain_entries a ON a.subject_id=d.id AND a.tenant_id=d.tenant_id WHERE d.id=$1`, v.ID).Scan(&hash, &actor); err != nil || hash != v.ManifestHash || actor != "user" {
		t.Fatal("draft audit not atomic", err)
	}
	releaseOnly, err := c.CreateQuestionnaireDraft(t.Context(), a, packageapp.CreateQuestionnaireDraftInput{TemplateID: "template", ReleaseID: "release"})
	if err != nil || releaseOnly.ProductID != "" || releaseOnly.Responses[0].Answer == "Reviewed answer" || !reflect.DeepEqual(releaseOnly.Responses[0].EvidenceIDs, []string{"b"}) {
		t.Fatal("release-only input inferred library product filter", err)
	}
	// A product grant cannot obtain tenant-wide reusable text via drafting.
	if _, err := p.Exec(t.Context(), `DELETE FROM questionnaire_answer_library WHERE id='specific'`); err != nil {
		t.Fatal(err)
	}
	v, err = c.CreateQuestionnaireDraft(t.Context(), a, in)
	if err != nil || v.Responses[0].Answer == "private-global-answer" || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, []string{"b"}) {
		t.Fatal("global answer bypassed its grant", v, err)
	}
	for _, bad := range []packageapp.CreateQuestionnaireDraftInput{{TemplateID: "template", ProductID: "product", ReleaseID: "second-release"}, {TemplateID: "template", ProductID: "other-product"}, {TemplateID: "missing", ProductID: "product"}} {
		if _, err := c.CreateQuestionnaireDraft(t.Context(), a, bad); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatal("foreign or mismatched root accepted", err)
		}
	}
	a.ResourceGrants = nil
	if err := c.AuthorizeCreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant replayed draft", err)
	}
}

func TestPostgresDraftIgnoresUnusedPrivateTextAndRejectsMisleadingLinks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnaireDraftCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:read"}}}}
	in := packageapp.CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"}
	if _, err := p.Exec(t.Context(), `UPDATE questionnaire_templates SET questions=jsonb_set(questions,'{0,prompt}',to_jsonb(repeat('private-prompt-marker',400000))) WHERE id='template';UPDATE questionnaire_answer_library SET answer=repeat('private-global-answer',400000) WHERE id='global'`); err != nil {
		t.Fatal(err)
	}
	v, err := c.CreateQuestionnaireDraft(t.Context(), a, in)
	if err != nil || v.Responses[0].Answer != "Reviewed answer" {
		t.Fatal("unused private text bounded valid draft", err)
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM questionnaire_answer_library WHERE id='specific'`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"outside", "foreign", "missing"} {
		if _, err := p.Exec(t.Context(), `UPDATE control_evidence SET subject_id=$1 WHERE id='link'`, id); err != nil {
			t.Fatal(err)
		}
		if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) || v.ID != "" || draftCounts(t, p) != [3]int{1, 1, 0} {
			t.Fatal("misleading link escaped scope", id, err)
		}
	}
}
func TestPostgresDraftBoundsCitationsAndAtomicFailures(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDraftMetadata(t, p)
	c, err := BuildQuestionnaireDraftCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"package:read"}}
	in := packageapp.CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"}
	for _, stage := range []string{"questionnaire_drafts", "audit_chain_entries", "commit"} {
		table := stage
		setup := `CREATE OR REPLACE FUNCTION reject_draft_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private draft storage';END$$;`
		if stage == "commit" {
			table = "questionnaire_drafts"
			setup += `CREATE CONSTRAINT TRIGGER reject_draft_stage AFTER INSERT ON questionnaire_drafts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_draft_stage()`
		} else {
			setup += `CREATE TRIGGER reject_draft_stage BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_draft_stage()`
		}
		if _, err := p.Exec(t.Context(), setup); err != nil {
			t.Fatal(err)
		}
		if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); err == nil || v.ID != "" || draftCounts(t, p) != [3]int{} {
			t.Fatal("partial draft escaped", stage, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_draft_stage ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"outside", "foreign", "missing"} {
		if _, err := p.Exec(t.Context(), `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY[$1] WHERE id='specific'`, id); err != nil {
			t.Fatal(err)
		}
		if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); err == nil || v.ID != "" || draftCounts(t, p) != [3]int{} {
			t.Fatal("invalid library citation accepted", id, err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY['b'],answer=repeat('x',65537) WHERE id='specific'`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" {
		t.Fatal("unbounded private answer", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE questionnaire_answer_library SET answer='Reviewed answer' WHERE id='specific';UPDATE questionnaire_templates SET questions=(SELECT jsonb_agg(jsonb_build_object('id','q-'||n,'prompt','private-prompt-marker')) FROM generate_series(1,513)n) WHERE id='template'`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" || draftCounts(t, p) != [3]int{} {
		t.Fatal("question bound silently truncated", err)
	}
}
func draftHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.QuestionnaireDraftCommands == nil {
		t.Fatal("draft remains Ledger-backed", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/questionnaire-drafts", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-prompt-marker") || strings.Contains(w.Body.String(), "private-payload-ref") || strings.Contains(w.Body.String(), "foreign-answer-secret") || strings.Contains(w.Body.String(), "private draft storage") {
		t.Fatalf("unsafe/legacy draft status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	return w.Body.String()
}
func TestPostgresDraftHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedDraftMetadata(t, p)
	body := `{"template_id":"template","product_id":"product","release_id":"release"}`
	one, two := draftHTTP(t, store, "draft", body, 201), draftHTTP(t, store, "draft", body, 201)
	var x, y any
	if json.Unmarshal([]byte(one), &x) != nil || json.Unmarshal([]byte(two), &y) != nil || !reflect.DeepEqual(x, y) || draftCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("draft replay changed effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='evidence_viewer',resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	draftHTTP(t, store, "draft", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin',resource_type='tenant',resource_id='tenant' WHERE id='grant';CREATE FUNCTION reject_draft_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private draft storage';END$$;CREATE CONSTRAINT TRIGGER reject_draft_http AFTER INSERT ON questionnaire_drafts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_draft_http()`); err != nil {
		t.Fatal(err)
	}
	draftHTTP(t, store, "failed", body, 500)
	if draftCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("failed draft HTTP committed effects")
	}
	for i, bad := range []string{`{"template_id":null}`, `{"template_id":"template","product_id":null}`, `{"template_id":"template","unknown":true}`} {
		draftHTTP(t, store, fmt.Sprint(i), bad, 400)
	}
}

func TestPostgresDraftReplayCannotRetainTenantWideAnswersAfterDowngrade(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedDraftMetadata(t, p)
	if _, err := p.Exec(t.Context(), `DELETE FROM questionnaire_answer_library WHERE id='specific'`); err != nil {
		t.Fatal(err)
	}
	const body = `{"template_id":"template","product_id":"product","release_id":"release"}`
	original := draftHTTP(t, store, "scope-snapshot", body, 201)
	if !strings.Contains(original, "private-global-answer") {
		t.Fatal("tenant authority lost reusable global answer")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	draftHTTP(t, store, "scope-snapshot", body, 409)
	scoped := draftHTTP(t, store, "scoped", body, 201)
	if strings.Contains(scoped, "private-global-answer") || draftCounts(t, p) != [3]int{2, 2, 2} {
		t.Fatal("downgrade exposed old private answer")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	restored := draftHTTP(t, store, "scope-snapshot", body, 201)
	if restored != original || draftCounts(t, p) != [3]int{2, 2, 2} {
		t.Fatal("restored authority did not replay original draft")
	}
}
