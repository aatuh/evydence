package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestReportTemplateWiringPreservesMemoryRepositoryContract(t *testing.T) {
	memory := app.NewMemoryUnitOfWorkFactory()
	if err := app.ExecuteUnitOfWork(t.Context(), memory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_templates", Name: "Templates", CreatedAt: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildReportTemplateCommands(memory)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_templates", KeyID: "key_1", Scopes: []string{"report:read"}}
	template, err := commands.CreateCustomReportTemplate(t.Context(), actor, packageapp.CreateReportTemplateInput{Name: "Metadata", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_id", "generated_at"}, Template: "{{never execute}}"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := commands.RenderCustomReport(t.Context(), actor, packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: "label", SubjectID: "not-a-dereferenced-resource"})
	if err != nil || report.Output["subject_id"] != "not-a-dereferenced-resource" || len(report.Output) != 2 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	state, err := memory.Snapshot()
	if err != nil || state.ReportTemplates[template.ID].Template != template.Template || state.RenderedReports[report.ID].Hash != report.Hash || len(state.AuditEntries[actor.TenantID]) != 2 {
		t.Fatal("memory repository effects differ")
	}
	if _, err := BuildReportTemplateCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
}

func TestReportOutputHasherMatchesLegacyNormalizedJSON(t *testing.T) {
	for _, output := range []map[string]any{{}, {"subject_type": " release ", "subject_id": "<script> & \"quoted\"\n\u00e9", "generated_at": "2026-10-01T00:00:00Z"}} {
		body, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		var normalized any
		if err := json.Unmarshal(body, &normalized); err != nil {
			t.Fatal(err)
		}
		body, err = json.Marshal(normalized)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := (reportOutputHasher{}).HashReportOutput(t.Context(), output)
		if err != nil || actual != fmt.Sprintf("sha256:%x", sha256.Sum256(body)) {
			t.Fatalf("hash=%s err=%v", actual, err)
		}
	}
	if _, err := (reportOutputHasher{}).HashReportOutput(t.Context(), map[string]any{"unsupported": 42}); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("non-string metadata accepted")
	}
}

func TestPostgresReportTemplateCommandsUseDurableDefinitionAndAtomicAudit(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('ten_templates','Templates'),('ten_other','Other')`)
	commands, err := BuildReportTemplateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_templates", UserID: "user_template", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_templates", Scopes: []string{"report:read"}}}}
	input := packageapp.CreateReportTemplateInput{Name: "Metadata", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_id", "secret", "subject_type", "generated_at"}, Template: `{{ .private_key }} <script>never-execute</script>`}
	template, err := commands.CreateCustomReportTemplate(ctx, actor, input)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an external operator's durable definition change. Rendering
	// must select the current committed fields, not a process snapshot.
	exec(`UPDATE report_templates SET allowed_fields=ARRAY['subject_id','generated_at','secret'] WHERE id=$1`, template.ID)
	report, err := commands.RenderCustomReport(ctx, actor, packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "label-only"})
	if err != nil || len(report.Output) != 2 || report.Output["subject_id"] != "label-only" || report.Output["secret"] != nil || report.Output["subject_type"] != nil {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	body, err := json.Marshal(report.Output)
	if err != nil || report.Hash != fmt.Sprintf("sha256:%x", sha256.Sum256(body)) {
		t.Fatal("canonical output hash differs")
	}
	var storedHash, auditHash string
	if err := pool.QueryRow(ctx, `SELECT r.hash,a.payload_hash FROM rendered_reports r JOIN audit_chain_entries a ON a.subject_id=r.id AND a.tenant_id=r.tenant_id WHERE r.id=$1`, report.ID).Scan(&storedHash, &auditHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != report.Hash || auditHash != report.Hash {
		t.Fatal("report/audit hash mismatch")
	}
	denied := actor
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"report:read"}}}
	if _, err := commands.CreateCustomReportTemplate(ctx, denied, input); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := commands.RenderCustomReport(ctx, denied, packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "label"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	foreign := actor
	foreign.TenantID = "ten_other"
	foreign.KeyID = "key_other"
	if _, err := commands.RenderCustomReport(ctx, foreign, packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "label"}); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal(err)
	}
	exec(`CREATE FUNCTION reject_template_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit write failure';END$$`)
	exec(`CREATE TRIGGER reject_template_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_template_audit()`)
	failedInput := input
	failedInput.Name = "Rollback"
	if value, err := commands.CreateCustomReportTemplate(ctx, actor, failedInput); err == nil || value.ID != "" {
		t.Fatalf("creation rollback=%#v err=%v", value, err)
	}
	if value, err := commands.RenderCustomReport(ctx, actor, packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "label"}); err == nil || value.ID != "" {
		t.Fatalf("render rollback=%#v err=%v", value, err)
	}
	var templates, reports, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM report_templates),(SELECT count(*) FROM rendered_reports),(SELECT count(*) FROM audit_chain_entries)`).Scan(&templates, &reports, &audits); err != nil {
		t.Fatal(err)
	}
	if templates != 1 || reports != 1 || audits != 2 {
		t.Fatalf("unexpected effects templates=%d reports=%d audits=%d", templates, reports, audits)
	}
	// The template remains inert and unchanged by report materialization.
	var storedTemplate string
	if err := pool.QueryRow(ctx, `SELECT template FROM report_templates WHERE id=$1`, template.ID).Scan(&storedTemplate); err != nil || storedTemplate != strings.TrimSpace(input.Template) {
		t.Fatal("renderer mutated or executed template text")
	}
}
