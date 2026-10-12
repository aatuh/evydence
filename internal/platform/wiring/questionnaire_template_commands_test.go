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
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func seedQTemplateControls(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('other','Other')ON CONFLICT(id)DO NOTHING;
INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version)VALUES('framework','tenant','Framework','framework','1','active','control-framework.v1'),('foreign-framework','other','Other','other','1','active','control-framework.v1');
INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)VALUES('control','tenant','framework','C','Control','private control objective','[]','[]','[]','security-control.v1'),('foreign','other','foreign-framework','F','Foreign','private foreign objective','[]','[]','[]','security-control.v1');`); err != nil {
		t.Fatal(err)
	}
}
func qTemplateCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM questionnaire_templates),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func qTemplateInput() packageapp.CreateQuestionnaireTemplateInput {
	return packageapp.CreateQuestionnaireTemplateInput{Name: " Customer ", Version: "1", Questions: []packagedomain.QuestionnaireQuestion{{ID: "b", Prompt: "Review?", ControlID: " control ", AllowedFields: []string{" z ", "a", "a"}}, {ID: "a", Prompt: "Build?"}}}
}

func TestPostgresQTemplateWritesOwnedDefinitionAndLocksSelectedParents(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedQTemplateControls(t, p)
	c, err := BuildQuestionnaireTemplateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildQuestionnaireTemplateCommands(nil); err == nil {
		t.Fatal("missing factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"package:write"}}}}
	in := qTemplateInput()
	v, err := c.CreateQuestionnaireTemplate(t.Context(), a, in)
	if err != nil || v.Name != "Customer" || v.Questions[0].ControlID != "control" || !reflect.DeepEqual(v.Questions[0].AllowedFields, []string{"a", "a", "z"}) {
		t.Fatal("focused creation differs", v, err)
	}
	var raw []byte
	var actor, entryType, payloadHash string
	if err := p.QueryRow(t.Context(), `SELECT t.questions,a.actor_id,a.entry_type,coalesce(a.payload_hash,'') FROM questionnaire_templates t JOIN audit_chain_entries a ON a.subject_id=t.id AND a.tenant_id=t.tenant_id WHERE t.id=$1`, v.ID).Scan(&raw, &actor, &entryType, &payloadHash); err != nil {
		t.Fatal(err)
	}
	var legacy []domain.QuestionnaireQuestion
	if json.Unmarshal(raw, &legacy) != nil || len(legacy) != 2 || legacy[0].ID != "b" || actor != "user" || entryType != "questionnaire_template.created" || payloadHash != "" {
		t.Fatal("stored shape/audit differs")
	}
	for _, id := range []string{"missing", "foreign"} {
		in.Questions[0].ControlID = id
		if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatal("foreign/missing control accepted", err)
		}
	}
	a.ResourceGrants[0].ResourceType = "product"
	if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, qTemplateInput()); err == nil {
		t.Fatal("scoped grant wrote tenant template")
	}
	a.KeyID = "key"
	a.UserID = ""
	a.TenantID = "absent"
	in = qTemplateInput()
	in.Questions[0].ControlID = ""
	if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("missing tenant accepted without controls", err)
	}
	// Framework ownership must match the control, not merely its identifier.
	if _, err := p.Exec(t.Context(), `UPDATE security_controls SET framework_id='foreign-framework' WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	a.TenantID = "tenant"
	if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, qTemplateInput()); !errors.Is(err, packageapp.ErrNotFound) || qTemplateCounts(t, p) != [3]int{1, 1, 0} {
		t.Fatal("mismatched framework accepted", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE security_controls SET framework_id='framework' WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	// While the guard owns locks, selected parent mutations must fail NOWAIT.
	if err := (qTemplateTransactions{store}).ExecuteQuestionnaireTemplate(t.Context(), a.TenantID, func(ctx context.Context, tx packageapp.QuestionnaireTemplateTransaction) error {
		if err := tx.ValidateQuestionnaireTemplateScope(ctx, a.TenantID, []string{"control"}); err != nil {
			return err
		}
		for _, table := range []string{"tenants", "security_controls", "control_frameworks"} {
			id := map[string]string{"tenants": "tenant", "security_controls": "control", "control_frameworks": "framework"}[table]
			tx, err := p.Begin(ctx)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `SELECT id FROM `+table+` WHERE id=$1 FOR UPDATE NOWAIT`, id)
			_ = tx.Rollback(context.WithoutCancel(ctx))
			if err == nil {
				t.Fatal("guard did not lock parent", table)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresQTemplateFailuresAndDirectWriterValidation(t *testing.T) {
	for _, stage := range []string{"insert", "audit", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedQTemplateControls(t, p)
			c, err := BuildQuestionnaireTemplateCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			table := "questionnaire_templates"
			if stage == "audit" {
				table = "audit_chain_entries"
			}
			trigger := `CREATE TRIGGER reject_q_template BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_q_template()`
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_q_template AFTER INSERT ON questionnaire_templates DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_q_template()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_q_template()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private template storage';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
			v, err := c.CreateQuestionnaireTemplate(t.Context(), a, qTemplateInput())
			if err == nil || v.ID != "" || qTemplateCounts(t, p) != [3]int{} {
				t.Fatal("failed write committed", stage, v, err)
			}
		})
	}
	store, p := openHTMLReportWiringStore(t)
	seedQTemplateControls(t, p)
	for _, kind := range []string{"schema", "duplicate", "noncanonical", "encoded", "foreign"} {
		in, _ := packageapp.NormalizeQuestionnaireTemplateInput(qTemplateInput())
		v := packagedomain.QuestionnaireTemplate{ID: "bad", TenantID: "tenant", Name: in.Name, Version: in.Version, Questions: in.Questions, SchemaVersion: packagedomain.QuestionnaireTemplateVersion, CreatedAt: time.Now().UTC()}
		want := packageapp.ErrValidation
		switch kind {
		case "schema":
			v.SchemaVersion = "wrong"
		case "duplicate":
			v.Questions[1].ID = v.Questions[0].ID
		case "noncanonical":
			v.Name = " Customer "
		case "foreign":
			v.Questions[0].ControlID = "foreign"
			want = packageapp.ErrNotFound
		case "encoded":
			v.Questions = make([]packagedomain.QuestionnaireQuestion, 50)
			for i := range v.Questions {
				v.Questions[i] = packagedomain.QuestionnaireQuestion{ID: fmt.Sprint(i), Prompt: strings.Repeat("<", 65536)}
			}
		}
		err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
			w, ok := repos.Enterprise.(interface {
				InsertFocusedQuestionnaireTemplate(context.Context, packagedomain.QuestionnaireTemplate) error
			})
			if !ok {
				t.Fatal("focused writer missing")
			}
			return w.InsertFocusedQuestionnaireTemplate(ctx, v)
		})
		if !errors.Is(err, want) || qTemplateCounts(t, p) != [3]int{} {
			t.Fatal("invalid durable template accepted", kind, err)
		}
	}
}
func qTemplateHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.QuestionnaireTemplateCommands == nil {
		t.Fatal("template still Ledger-backed", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/questionnaire-templates", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private control objective") || strings.Contains(w.Body.String(), "private foreign objective") || strings.Contains(w.Body.String(), "private template storage") {
		t.Fatalf("unsafe/legacy template status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	return w.Body.String()
}
func TestPostgresQTemplateHTTPRestartReplayAndAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedQTemplateControls(t, p)
	const body = `{"name":"Customer","version":"1","questions":[{"id":"q","prompt":"Review?","control_id":"control"}]}`
	one, two := qTemplateHTTP(t, store, "template", body, 201), qTemplateHTTP(t, store, "template", body, 201)
	var x, y any
	if json.Unmarshal([]byte(one), &x) != nil || json.Unmarshal([]byte(two), &y) != nil || !reflect.DeepEqual(x, y) || qTemplateCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("restart replay duplicated effects")
	}
	qTemplateHTTP(t, store, "template", strings.Replace(body, "Customer", "Other", 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='p' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	qTemplateHTTP(t, store, "template", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant';UPDATE security_controls SET framework_id='foreign-framework' WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	qTemplateHTTP(t, store, "template", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE security_controls SET framework_id='framework' WHERE id='control';CREATE FUNCTION reject_q_template_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private template storage';END$$;CREATE CONSTRAINT TRIGGER reject_q_template_http AFTER INSERT ON questionnaire_templates DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_q_template_http()`); err != nil {
		t.Fatal(err)
	}
	qTemplateHTTP(t, store, "failed", strings.Replace(body, `"version":"1"`, `"version":"2"`, 1), 500)
	if qTemplateCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("failed HTTP template committed replay/audit")
	}
}
func TestPostgresQTemplateFencePrecedesParentLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedQTemplateControls(t, p)
	c, err := BuildQuestionnaireTemplateCommands(store)
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
		done <- c.AuthorizeCreateQuestionnaireTemplate(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}, qTemplateInput())
	}()
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
			if _, err := leader.Exec(ctx, `SELECT id FROM security_controls WHERE id='control' FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("control locked before fence", err)
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
