package app

import (
	"errors"
	"strings"
	"testing"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestReportTemplateCommandsRejectRawBudgetsBeforeWrites(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*CreateReportTemplateInput)
	}{
		{"name", func(in *CreateReportTemplateInput) { in.Name = strings.Repeat(" ", 65537) + "Name" }},
		{"version", func(in *CreateReportTemplateInput) { in.Version = strings.Repeat(" ", 65537) + "1" }},
		{"name-nul", func(in *CreateReportTemplateInput) { in.Name = "bad\x00name" }},
		{"index-key", func(in *CreateReportTemplateInput) { in.Name = strings.Repeat("n", 2305) }},
		{"template-nul", func(in *CreateReportTemplateInput) { in.Template = "bad\x00template" }},
		{"field-count", func(in *CreateReportTemplateInput) {
			in.AllowedFields = make([]string, 1025)
			for n := range in.AllowedFields {
				in.AllowedFields[n] = "subject_id"
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newPackageTestState()
			local := newPackageTestService(t, state)
			c, err := local.templateCommands()
			if err != nil {
				t.Fatal(err)
			}
			in := CreateReportTemplateInput{Name: "Name", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id"}, Template: "inert"}
			tc.change(&in)
			v, err := c.CreateCustomReportTemplate(t.Context(), packageTestActor(), in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || len(state.templates)+len(state.audit) != 0 {
				t.Fatalf("invalid template reached writes: id=%q err=%v templates=%d audits=%d", v.ID, err, len(state.templates), len(state.audit))
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*RenderReportInput)
	}{
		{"template-id", func(in *RenderReportInput) { in.TemplateID = strings.Repeat(" ", 1025) + "template" }},
		{"subject-type", func(in *RenderReportInput) { in.SubjectType = strings.Repeat(" ", 65537) + "label" }},
		{"subject-id", func(in *RenderReportInput) { in.SubjectID = "bad\x00label" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newPackageTestState()
			local := newPackageTestService(t, state)
			state.templates["template"] = packagedomain.CustomReportTemplate{ID: "template", TenantID: packageTestActor().TenantID, AllowedFields: []string{"subject_id"}}
			c, err := local.templateCommands()
			if err != nil {
				t.Fatal(err)
			}
			in := RenderReportInput{TemplateID: "template", SubjectType: "label", SubjectID: "label-only"}
			tc.change(&in)
			v, err := c.RenderCustomReport(t.Context(), packageTestActor(), in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || len(state.renderedReports)+len(state.audit) != 0 {
				t.Fatalf("invalid render reached writes: id=%q err=%v reports=%d audits=%d", v.ID, err, len(state.renderedReports), len(state.audit))
			}
		})
	}
}
