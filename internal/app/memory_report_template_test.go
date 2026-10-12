package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func memoryReportTemplateFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	tx.state.ReportTemplates["template"] = domain.CustomReportTemplate{ID: "template", TenantID: "tenant", Name: "Review", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "generated_at", "subject_id"}, Template: "{{inert-definition}}", SchemaVersion: "report-template.v1.0.0", CreatedAt: fixedNow()}
	return tx
}

func TestMemoryReportTemplatePointReadPreservesDetachedDefinitionAndCurrentScope(t *testing.T) {
	tx := memoryReportTemplateFixture(t)
	r := tx.Repositories().Packages
	want := tx.state.ReportTemplates["template"]
	v, err := r.GetCustomReportTemplate(t.Context(), "tenant", "template")
	if err != nil || !reflect.DeepEqual(v, want) {
		t.Fatal("point read changed frozen template definition", err)
	}
	v.AllowedFields[0] = "caller-mutation"
	if tx.state.ReportTemplates["template"].AllowedFields[0] != "subject_id" {
		t.Fatal("template read aliases stored fields")
	}
	if v, err := r.GetCustomReportTemplate(t.Context(), "foreign", "template"); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, domain.CustomReportTemplate{}) {
		t.Fatal("foreign template returned data", err)
	}
	want.ID = "wrong-stored-identity"
	tx.state.ReportTemplates["template"] = want
	if err := r.(packageapp.ReportTemplateScopeLocker).LockReportTemplateIdentity(t.Context(), "tenant", "template"); !errors.Is(err, ErrNotFound) {
		t.Fatal("replay identity guard accepted wrong stored ID", err)
	}
	if v, err := r.GetCustomReportTemplate(t.Context(), "tenant", "template"); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, domain.CustomReportTemplate{}) {
		t.Fatal("wrong stored identity returned template", err)
	}
}

func TestMemoryReportTemplatePointReadRejectsMalformedOversizedAndClosedViewsWithoutData(t *testing.T) {
	for _, mutate := range []func(*domain.CustomReportTemplate){
		func(v *domain.CustomReportTemplate) { v.AllowedFields = nil },
		func(v *domain.CustomReportTemplate) { v.AllowedFields = []string{" "} },
		func(v *domain.CustomReportTemplate) { v.Name = "" },
		func(v *domain.CustomReportTemplate) { v.SchemaVersion = "" },
		func(v *domain.CustomReportTemplate) {
			v.Template = strings.Repeat("x", packageapp.MaxStoredReportTemplateBytes+1)
		},
	} {
		tx := memoryReportTemplateFixture(t)
		v := tx.state.ReportTemplates["template"]
		mutate(&v)
		tx.state.ReportTemplates[v.ID] = v
		if got, err := tx.Repositories().Packages.GetCustomReportTemplate(t.Context(), "tenant", v.ID); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(got, domain.CustomReportTemplate{}) {
			t.Fatal("invalid selected template returned data", err)
		}
	}
	tx := memoryReportTemplateFixture(t)
	r := tx.Repositories().Packages
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.GetCustomReportTemplate(ctx, "tenant", "template"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, domain.CustomReportTemplate{}) {
		t.Fatal("cancelled reader returned data", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := r.GetCustomReportTemplate(t.Context(), "tenant", "template"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, domain.CustomReportTemplate{}) {
		t.Fatal("closed reader returned data", err)
	}
}
