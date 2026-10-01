package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestTemplateCommandsUseTransactionalTemplateReadAndAtomicAudit(t *testing.T) {
	state := newPackageTestState()
	local := newPackageTestService(t, state)
	commands, err := NewTemplateCommands(TemplateCommandConfig{Transactions: serviceTemplateTransactions{state}, Authorizer: local.authorizer, Hasher: serviceReportOutputHasher{local.canonicalizer}, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	template, err := commands.CreateCustomReportTemplate(t.Context(), packageTestActor(), CreateReportTemplateInput{Name: " Review ", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "generated_at", "secret"}, Template: "{{malicious template}}"})
	if err != nil || template.Name != "Review" || len(state.templates) != 1 || len(state.audit) != 1 {
		t.Fatalf("template=%#v err=%v", template, err)
	}
	report, err := commands.RenderCustomReport(t.Context(), packageTestActor(), RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "rel_1"})
	if err != nil || report.Output["subject_id"] != "rel_1" || report.Output["generated_at"] == "" || len(report.Output) != 2 || report.Output["secret"] != nil || len(state.renderedReports) != 1 || len(state.audit) != 2 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	state.auditErr = errPackageTestFailure
	if report, err := commands.RenderCustomReport(t.Context(), packageTestActor(), RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "rel_1"}); !errors.Is(err, errPackageTestFailure) || report.ID != "" || len(state.renderedReports) != 1 || len(state.audit) != 2 {
		t.Fatalf("rollback=%#v err=%v", report, err)
	}
}

func TestTemplateCommandsAuthorizeBeforeTransactionalRead(t *testing.T) {
	state := newPackageTestState()
	state.authorize = func(request application.AuthorizationRequest) error {
		if request.TenantWide {
			return application.ErrForbidden
		}
		return nil
	}
	local := newPackageTestService(t, state)
	commands, err := NewTemplateCommands(TemplateCommandConfig{Transactions: serviceTemplateTransactions{state}, Authorizer: local.authorizer, Hasher: serviceReportOutputHasher{local.canonicalizer}, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commands.RenderCustomReport(t.Context(), packageTestActor(), RenderReportInput{TemplateID: "missing", SubjectType: "release", SubjectID: "rel_1"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("authorization occurred after template read: %v", err)
	}
	if len(state.renderedReports) != 0 || len(state.audit) != 0 {
		t.Fatal("denial wrote effects")
	}
}
