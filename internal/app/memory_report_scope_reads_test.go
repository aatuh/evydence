package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type memoryReportScopeReader interface {
	ReadEvidenceSummaryScope(context.Context, string, string, string) (packageapp.EvidenceSummaryScope, error)
	ReadQuestionnaireDraftScope(context.Context, string, packageapp.CreateQuestionnaireDraftInput) (packageapp.QuestionnaireDraftScope, error)
}

func TestMemoryReportScopeReadsKeepBoundedOwnedCoordinatesWithoutPrivateText(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.BuildRuns[tenant+"-build"] = domain.BuildRun{ID: tenant + "-build", TenantID: tenant, ProjectID: tenant + "-project", ReleaseID: tenant + "-release"}
		tx.state.Evidence[tenant+"-evidence"] = domain.EvidenceItem{ID: tenant + "-evidence", TenantID: tenant, ProjectID: tenant + "-project", Title: strings.Repeat("x", 65537), PayloadRef: "private-payload"}
		tx.state.QuestionnaireTemplates[tenant+"-template"] = domain.QuestionnaireTemplate{ID: tenant + "-template", TenantID: tenant, Name: strings.Repeat("x", 65537), Questions: []domain.QuestionnaireQuestion{{Prompt: strings.Repeat("x", 65537)}}}
		pkg := tx.state.CustomerPackages[tenant+"-package"]
		pkg.Manifest = map[string]any{"private": strings.Repeat("x", 65537)}
		tx.state.CustomerPackages[pkg.ID] = pkg
	}
	r, ok := tx.Repositories().Future.(memoryReportScopeReader)
	if !ok {
		t.Fatal("memory future repository lacks focused report scopes")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind, id      string
		raw, resolved application.ResourceReferences
	}{
		{"tenant", "tenant", application.ResourceReferences{}, application.ResourceReferences{}},
		{"product", "tenant-product", application.ResourceReferences{ProductID: "tenant-product"}, application.ResourceReferences{ProductID: "tenant-product"}},
		{"release", "tenant-release", application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}, application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}},
		{"evidence", "tenant-evidence", application.ResourceReferences{ProjectID: "tenant-project"}, application.ResourceReferences{ProductID: "tenant-product", ProjectID: "tenant-project"}},
		{"build", "tenant-build", application.ResourceReferences{ProjectID: "tenant-project", ReleaseID: "tenant-release"}, application.ResourceReferences{ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release"}},
		{"customer_package", "tenant-package", application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release", CustomerPackageID: "tenant-package"}, application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release", CustomerPackageID: "tenant-package"}},
	} {
		s, err := r.ReadEvidenceSummaryScope(t.Context(), "tenant", c.kind, c.id)
		if err != nil || s != (packageapp.EvidenceSummaryScope{TenantID: "tenant", SubjectType: c.kind, SubjectID: c.id, Resources: c.resolved, Filter: c.raw}) {
			t.Fatal("summary read lost raw/resolved coordinate distinction", c.kind, s, err)
		}
		if _, err := r.ReadEvidenceSummaryScope(t.Context(), "tenant", c.kind, strings.Replace(c.id, "tenant", "foreign", 1)); !errors.Is(err, ErrNotFound) {
			t.Fatal("summary root crossed tenant", c.kind, err)
		}
	}
	for _, in := range []packageapp.CreateQuestionnaireDraftInput{{TemplateID: "tenant-template"}, {TemplateID: "tenant-template", ProductID: "tenant-product"}, {TemplateID: "tenant-template", ReleaseID: "tenant-release"}, {TemplateID: "tenant-template", ProductID: "tenant-product", ReleaseID: "tenant-release"}} {
		s, err := r.ReadQuestionnaireDraftScope(t.Context(), "tenant", in)
		product := in.ProductID
		if in.ReleaseID != "" {
			product = "tenant-product"
		}
		if err != nil || s != (packageapp.QuestionnaireDraftScope{TenantID: "tenant", TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Resources: application.ResourceReferences{ProductID: product, ReleaseID: in.ReleaseID}}) {
			t.Fatal("draft read widened raw filters or read private questions", s, err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("report scope reads changed repository state")
	}
	for _, in := range []packageapp.CreateQuestionnaireDraftInput{{TemplateID: "foreign-template"}, {TemplateID: "tenant-template", ProductID: "foreign-product"}, {TemplateID: "tenant-template", ReleaseID: "foreign-release"}, {TemplateID: "tenant-template", ProductID: "foreign-product", ReleaseID: "tenant-release"}} {
		if _, err := r.ReadQuestionnaireDraftScope(t.Context(), "tenant", in); !errors.Is(err, ErrNotFound) {
			t.Fatal("draft read accepted foreign or inconsistent coordinates", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadEvidenceSummaryScope(ctx, "tenant", "tenant", "tenant"); !errors.Is(err, context.Canceled) {
		t.Fatal("summary scope ignored cancellation", err)
	}
	if _, err := r.ReadQuestionnaireDraftScope(ctx, "tenant", packageapp.CreateQuestionnaireDraftInput{TemplateID: "tenant-template"}); !errors.Is(err, context.Canceled) {
		t.Fatal("draft scope ignored cancellation", err)
	}
	v := tx.state.Evidence["tenant-evidence"]
	v.ProjectID = strings.Repeat("x", 1025)
	tx.state.Evidence[v.ID] = v
	if _, err := r.ReadEvidenceSummaryScope(t.Context(), "tenant", "evidence", v.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized selected coordinates did not conflict", err)
	}
	v.ProjectID = "foreign-project"
	tx.state.Evidence[v.ID] = v
	if _, err := r.ReadEvidenceSummaryScope(t.Context(), "tenant", "evidence", v.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("corrupt selected parent did not conflict", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadEvidenceSummaryScope(t.Context(), "tenant", "tenant", "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed scope transaction remained readable", err)
	}
}
