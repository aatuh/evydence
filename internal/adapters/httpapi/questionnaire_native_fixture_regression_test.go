package httpapi

import (
	"context"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestQuestionnaireFixturesConsumeRepositoryTemplatesWithoutAggregatePublication(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	scope := seedQuestionnaireFixtureScope(t, ledger, "Native")
	template := scope.template
	template.ID, template.Name, template.Version = "repository-only-template", "Repository only", "2"
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Enterprise.InsertQuestionnaireTemplate(ctx, template)
	}); err != nil {
		t.Fatal(err)
	}
	f := questionnaireFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	d := summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	in := packageapp.CreateQuestionnairePackageInput{TemplateID: template.ID, ProductID: scope.product.ID, ReleaseID: scope.release.ID}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateQuestionnairePackage(t.Context(), scope.actor, in); err != nil {
		t.Fatal("package preflight consulted stale aggregate template cache", err)
	}
	draftIn := packageapp.CreateQuestionnaireDraftInput{TemplateID: template.ID, ProductID: scope.product.ID, ReleaseID: scope.release.ID}
	if err := d.AuthorizeCreateQuestionnaireDraft(t.Context(), scope.actor, draftIn); err != nil {
		t.Fatal(err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("preflight changed repository state", err)
	}
	pkg, err := f.CreateQuestionnairePackage(t.Context(), scope.actor, in)
	if err != nil || pkg.TemplateID != template.ID || len(pkg.Responses) != 1 || pkg.Responses[0].Answer != scope.entry.Answer {
		t.Fatal("package generation consulted aggregate templates", pkg, err)
	}
	draft, err := d.CreateQuestionnaireDraft(t.Context(), scope.actor, draftIn)
	if err != nil || draft.TemplateID != template.ID || !reflect.DeepEqual(draft.Responses, pkg.Responses) || draft.ManifestHash != pkg.ManifestHash {
		t.Fatal("draft generation consulted aggregate templates or changed canonical responses", draft, err)
	}
	saved, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if saved.QuestionnairePackages[pkg.ID].ManifestHash != pkg.ManifestHash || saved.QuestionnaireDrafts[draft.ID].ManifestHash != draft.ManifestHash {
		t.Fatal("native generation was not persisted")
	}
	var packageAudits, draftAudits int
	for _, e := range saved.AuditEntries[scope.actor.TenantID] {
		if e.SubjectID == pkg.ID {
			if e.EntryType != "questionnaire_package.generated" || e.PayloadHash != pkg.ManifestHash {
				t.Fatal("incorrect package audit", e)
			}
			packageAudits++
		}
		if e.SubjectID == draft.ID {
			if e.EntryType != "questionnaire_draft.created" || e.PayloadHash != draft.ManifestHash {
				t.Fatal("incorrect draft audit", e)
			}
			draftAudits++
		}
	}
	if packageAudits != 1 || draftAudits != 1 {
		t.Fatal("native generations lost or duplicated audits", packageAudits, draftAudits)
	}
}
