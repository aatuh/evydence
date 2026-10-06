package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestLocalReportTemplateGuardsCheckCurrentTenantAndTemplateNotDefinition(t *testing.T) {
	l := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	v, err := l.CreateCustomReportTemplate(t.Context(), a, CreateReportTemplateInput{Name: "Definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id"}})
	if err != nil {
		t.Fatal(err)
	}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("template guard used clock") }
	create := packageapp.CreateReportTemplateInput{Name: "Definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id"}}
	render := packageapp.RenderReportInput{TemplateID: v.ID, SubjectType: "label", SubjectID: "not-a-dereferenced-resource"}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeReportRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{ScopeReportRead}}}}
	if err := l.AuthorizeReportTemplateCreation(t.Context(), human, create); err != nil {
		t.Fatal(err)
	}
	if err := l.AuthorizeReportRendering(t.Context(), human, render); err != nil {
		t.Fatal(err)
	}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: "label", Scopes: []string{ScopeReportRead}}}
	if err := l.AuthorizeReportRendering(t.Context(), human, render); !errors.Is(err, ErrForbidden) {
		t.Fatal("narrow grant retained tenant-wide replay", err)
	}
	v.Template = "private-invalid-definition"
	v.AllowedFields = nil
	l.reportTemplates[v.ID] = v
	if err := l.AuthorizeReportRendering(t.Context(), a, render); err != nil {
		t.Fatal("guard inspected definition", err)
	}
	v.TenantID = "other"
	l.reportTemplates[v.ID] = v
	if err := l.AuthorizeReportRendering(t.Context(), a, render); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign template retained replay", err)
	}
	if len(l.chain[a.TenantID]) != audits || len(l.renderedReports) != 0 {
		t.Fatal("template guard wrote effects")
	}
}
