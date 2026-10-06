package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func (c nativeReportTemplateCase) guard(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) error {
	if c.kind == "create" {
		return o.ReportTemplateCommands.AuthorizeReportTemplateCreation(ctx, a, packageapp.CreateReportTemplateInput{Name: "New definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "subject_type", "generated_at", "unknown"}, Template: "inert-data-marker"})
	}
	return o.ReportTemplateCommands.AuthorizeReportRendering(ctx, a, packageapp.RenderReportInput{TemplateID: "template", SubjectType: " release ", SubjectID: " nonexistent-label-only "})
}
func (c nativeReportTemplateCase) create(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) (int, any, error) {
	if c.kind == "create" {
		v, err := o.ReportTemplateCommands.CreateCustomReportTemplate(ctx, a, packageapp.CreateReportTemplateInput{Name: "New definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "subject_type", "generated_at", "unknown"}, Template: "inert-data-marker"})
		return 201, domain.CustomReportTemplate{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Version: v.Version, ReportType: v.ReportType, AllowedFields: v.AllowedFields, Template: v.Template, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
	}
	v, err := o.ReportTemplateCommands.RenderCustomReport(ctx, a, packageapp.RenderReportInput{TemplateID: "template", SubjectType: " release ", SubjectID: " nonexistent-label-only "})
	return 201, domain.RenderedCustomReport{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Output: v.Output, Hash: v.Hash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
}

type nativeReportTemplateCase struct{ kind, path, body string }

func nativeReportTemplateCases() []nativeReportTemplateCase {
	return []nativeReportTemplateCase{
		{"create", "/v1/report-templates", `{"name":" New definition ","version":" 1 ","report_type":" metadata ","allowed_fields":["subject_id","generated_at","subject_type","subject_id","unknown"],"template":" inert-data-marker "}`},
		{"render", "/v1/report-templates/template/render", `{"subject_type":" release ","subject_id":" nonexistent-label-only "}`},
	}
}
func seedReportTemplateNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO report_templates(id,tenant_id,name,version,report_type,allowed_fields,template,schema_version,created_at)VALUES('template','tenant','Existing','1','metadata',ARRAY['subject_id','subject_type','generated_at','unknown'],'inert-data-marker','report-template.v1.0.0','2026-10-01T00:00:00Z'),('foreign-template','other','Foreign','1','metadata',ARRAY['subject_id'],'foreign-inert','report-template.v1.0.0','2026-10-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
}
func reportTemplateNativeHTTP(t *testing.T, store *postgres.Store, c nativeReportTemplateCase, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", c.path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native report %s status=%d want=%d loads=%d: %s", c.kind, w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("report lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("report lost Problem Details")
	}
	return w.Body.String()
}
func reportTemplateNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var n [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM report_templates),(SELECT count(*)FROM rendered_reports),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestPostgresReportTemplatesNativeReplayAndCurrentAuthority(t *testing.T) {
	for _, c := range nativeReportTemplateCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedReportTemplateNative(t, p)
			one := reportTemplateNativeHTTP(t, store, c, "original", c.body, 201)
			var e struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &e); err != nil || string(e.Data["tenant_id"]) != `"tenant"` {
				t.Fatal("report contract changed", one, err)
			}
			if c.kind == "create" {
				if string(e.Data["name"]) != `"New definition"` || string(e.Data["version"]) != `"1"` || string(e.Data["template"]) != `"inert-data-marker"` || string(e.Data["allowed_fields"]) != `["generated_at","subject_id","subject_type","unknown"]` {
					t.Fatal("template normalization changed", one)
				}
			} else {
				var report struct {
					Data domain.RenderedCustomReport `json:"data"`
				}
				if err := json.Unmarshal([]byte(one), &report); err != nil {
					t.Fatal(err)
				}
				v := report.Data
				if v.SubjectType != "release" || v.SubjectID != "nonexistent-label-only" || v.Output["subject_type"] != " release " || v.Output["subject_id"] != " nonexistent-label-only " || len(v.Output) != 3 || v.Output["unknown"] != nil {
					t.Fatal("label-only render or whitespace semantics changed", one)
				}
				if hash, err := (reportOutputHasher{}).HashReportOutput(t.Context(), v.Output); err != nil || hash != v.Hash {
					t.Fatal("report hash changed", hash, v.Hash, err)
				}
			}
			assertDeploymentCreationReplay(t, one, reportTemplateNativeHTTP(t, store, c, "original", c.body, 201))
			reportTemplateNativeHTTP(t, store, c, "original", c.body+" ", 409)
			if c.kind == "create" {
				reportTemplateNativeHTTP(t, store, c, "duplicate", c.body, 409)
			}
			if _, err := p.Exec(t.Context(), `UPDATE report_templates SET template=repeat('private-',1200000),report_type=repeat('private-',1200000),allowed_fields=ARRAY[repeat('private-',1200000)]`); err != nil {
				t.Fatal(err)
			}
			assertDeploymentCreationReplay(t, one, reportTemplateNativeHTTP(t, store, c, "original", c.body, 201))
			if c.kind == "render" {
				reportTemplateNativeHTTP(t, store, c, "oversized-fresh", c.body, 409)
			}
			for _, g := range []struct{ kind, id string }{{"product", "product"}, {"project", "project"}, {"release", "nonexistent-label-only"}, {"tenant", "other"}} {
				if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
					t.Fatal(err)
				}
				reportTemplateNativeHTTP(t, store, c, "original", c.body, 403)
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='collector'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			// A known role downgrade removes report permission immediately.
			reportTemplateNativeHTTP(t, store, c, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			assertDeploymentCreationReplay(t, one, reportTemplateNativeHTTP(t, store, c, "original", c.body, 201))
			if c.kind == "render" {
				if _, err := p.Exec(t.Context(), `UPDATE report_templates SET tenant_id='other'WHERE id='template'`); err != nil {
					t.Fatal(err)
				}
				reportTemplateNativeHTTP(t, store, c, "original", c.body, 404)
				if _, err := p.Exec(t.Context(), `UPDATE report_templates SET tenant_id='tenant'WHERE id='template'`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			reportTemplateNativeHTTP(t, store, c, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
				t.Fatal(err)
			}
			reportTemplateNativeHTTP(t, store, c, "original", c.body, 401)
			want := [5]int{3, 0, 1, 1, 1}
			if c.kind == "render" {
				want = [5]int{2, 1, 1, 1, 1}
			}
			if got := reportTemplateNativeCounts(t, p); got != want {
				t.Fatal("report replay/denial wrote effects", got, want)
			}
		})
	}
}

func TestPostgresReportTemplatesNativeRollbackAndRecovery(t *testing.T) {
	for _, c := range nativeReportTemplateCases() {
		for _, stage := range []string{"record", "audit", "replay", "commit"} {
			t.Run(c.kind+"/"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedReportTemplateNative(t, p)
				table := "report_templates"
				if c.kind == "render" {
					table = "rendered_reports"
				}
				if stage != "record" {
					table = map[string]string{"audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_native_template BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_template()", table)
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_native_template BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_template()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_native_template AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_template()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_template()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-template-write-failure';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				reportTemplateNativeHTTP(t, store, c, "failed", c.body, 500)
				want := [5]int{2, 0, 0, 0, 0}
				if stage == "record" || stage == "audit" {
					want[4] = 1
				}
				if got := reportTemplateNativeCounts(t, p); got != want {
					t.Fatal("report partially committed", stage, got, want)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_template ON "+table); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if want[4] == 1 {
					reportTemplateNativeHTTP(t, store, c, key, c.body, 409)
					key = "recovered"
				}
				one := reportTemplateNativeHTTP(t, store, c, key, c.body, 201)
				assertDeploymentCreationReplay(t, one, reportTemplateNativeHTTP(t, store, c, key, c.body, 201))
				if c.kind == "create" {
					want[0]++
				} else {
					want[1]++
				}
				want[2]++
				want[3]++
				if got := reportTemplateNativeCounts(t, p); got != want {
					t.Fatal("report recovery duplicated effects", stage, got, want)
				}
			})
		}
	}
}

func TestPostgresReportTemplateGuardsKeepOwnershipLocksThroughReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedReportTemplateNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"report:read"}}
	for _, c := range nativeReportTemplateCases() {
		calls, guards := 0, 0
		for range 2 {
			_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "locks", []byte(c.body), func(ctx context.Context) error {
				if err := c.guard(ctx, o, a); err != nil {
					return err
				}
				guards++
				for _, tc := range []struct {
					table, id string
					blocked   bool
				}{{"tenants", "tenant", true}, {"report_templates", "template", c.kind == "render"}, {"report_templates", "foreign-template", false}, {"products", "product", false}, {"projects", "project", false}, {"sso_sessions", "operator-session", false}} {
					probe, err := p.Begin(ctx)
					if err != nil {
						return err
					}
					_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
					_ = probe.Rollback(context.WithoutCancel(ctx))
					var pe *pgconn.PgError
					if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
						t.Fatal("template guard lost ownership lock or reached unrelated row", tc, err)
					}
				}
				return nil
			}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		if calls != 1 || guards != 2 {
			t.Fatal("template guard skipped replay or executed twice", c.kind, calls, guards)
		}
	}
	if got := reportTemplateNativeCounts(t, p); got != [5]int{2, 0, 0, 2, 0} {
		t.Fatal("template guard wrote domain effects", got)
	}
}

func TestPostgresReportTemplatesNativeConcurrentReplayWritesOnce(t *testing.T) {
	for _, c := range nativeReportTemplateCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedReportTemplateNative(t, p)
			o := subjectVerificationOptions(t, store, nil)
			a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"report:read"}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var calls atomic.Int32
			type reply struct {
				status int
				value  any
				err    error
			}
			done, start := make(chan reply, 2), make(chan struct{})
			for range 2 {
				go func() {
					<-start
					s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", c.path, "concurrent", []byte(c.body), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(ctx context.Context) (int, any, error) { calls.Add(1); return c.create(ctx, o, a) })
					done <- reply{s, v, err}
				}()
			}
			close(start)
			var replies [2]string
			for n := range replies {
				select {
				case r := <-done:
					if r.err != nil || r.status != 201 {
						t.Fatal(r.status, r.err)
					}
					b, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					replies[n] = string(b)
				case <-ctx.Done():
					t.Fatal("report leaked transaction", ctx.Err())
				}
			}
			assertDeploymentCreationReplay(t, replies[0], replies[1])
			want := [5]int{3, 0, 1, 1, 0}
			if c.kind == "render" {
				want = [5]int{2, 1, 1, 1, 0}
			}
			if got := reportTemplateNativeCounts(t, p); calls.Load() != 1 || got != want {
				t.Fatal("concurrent report duplicated effects", calls.Load(), got, want)
			}
		})
	}
}

func TestPostgresReportTemplateCancelledGuardsReleaseFenceBeforeOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedReportTemplateNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"report:read"}}
	for _, c := range nativeReportTemplateCases() {
		leader, err := p.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
		if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
			t.Fatal(err)
		}
		pid := leader.Conn().PgConn().PID()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.guard(ctx, o, a) }()
		waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
			var blocked bool
			err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
			return blocked, err
		}, done)
		if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
			t.Fatal("template ownership lock preceded writer fence", err)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("guard lost cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("template cancellation leaked transaction")
		}
		if err := leader.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := c.guard(t.Context(), o, a); err != nil {
			t.Fatal("cancelled guard leaked fence", err)
		}
	}
	if got := reportTemplateNativeCounts(t, p); got != [5]int{2, 0, 0, 0, 0} {
		t.Fatal("cancelled guard wrote effects", got)
	}
}

func TestPostgresReportTemplateNativeIndexedIdentityBoundReturnsValidation(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedReportTemplateNative(t, p)
	c := nativeReportTemplateCases()[0]
	largeName := strings.Repeat("n", packageapp.MaxReportTemplateKeyBytes+1)
	body := strings.Replace(c.body, " New definition ", largeName, 1)
	reportTemplateNativeHTTP(t, store, c, "oversized-key", body, 400)
	if got := reportTemplateNativeCounts(t, p); got != [5]int{2, 0, 0, 0, 0} {
		t.Fatal("oversized key reserved replay or wrote effects", got)
	}
}
