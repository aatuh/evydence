package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestQuestionnairePackageLocalSelectionRequiresRootGrant(t *testing.T) {
	l := NewLedger(Config{})
	l.products["product"] = domain.Product{ID: "product", TenantID: "tenant"}
	l.products["other-product"] = domain.Product{ID: "other-product", TenantID: "tenant"}
	l.questionTemplates["template"] = domain.QuestionnaireTemplate{ID: "template", TenantID: "tenant", Questions: []domain.QuestionnaireQuestion{{ID: "q", Prompt: "Review?", EvidenceType: "sbom"}}}
	l.customerPackages["package"] = domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "product"}
	l.evidence["outside"] = domain.EvidenceItem{ID: "outside", TenantID: "tenant", ProductID: "other-product", Type: "sbom"}
	a := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{ScopePackageWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopePackageWrite}}}}
	for _, in := range []CreateQuestionnairePackageInput{{TemplateID: "template"}, {TemplateID: "template", PackageID: "package"}, {TemplateID: "template", ProductID: "other-product"}} {
		if v, err := l.CreateQuestionnairePackage(t.Context(), a, in); !errors.Is(err, ErrForbidden) || v.ID != "" || len(l.questionPackages) != 0 {
			t.Fatal("selection grant bypassed", in, v, err)
		}
	}
	if v, err := l.CreateQuestionnairePackage(t.Context(), a, CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "package", ProductID: "product"}); err != nil || len(v.Responses[0].EvidenceIDs) != 0 {
		t.Fatal("association changed evidence filters", err)
	}
}
func TestQuestionnairePackageLocalResultCannotMutateCommittedResponses(t *testing.T) {
	l := NewLedger(Config{})
	l.questionTemplates["template"] = domain.QuestionnaireTemplate{ID: "template", TenantID: "tenant", Questions: []domain.QuestionnaireQuestion{{ID: "q", Prompt: "Review?"}}}
	l.answerLibrary["answer"] = domain.QuestionnaireAnswerLibraryEntry{ID: "answer", TenantID: "tenant", QuestionID: "q", Answer: "Reviewed", EvidenceIDs: []string{"e"}, Limitations: []string{"Human review"}, CreatedAt: time.Unix(1, 0)}
	l.evidence["e"] = domain.EvidenceItem{ID: "e", TenantID: "tenant"}
	v, err := l.CreateQuestionnairePackage(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}, CreateQuestionnairePackageInput{TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	v.Responses[0].EvidenceIDs[0] = "mutated"
	v.Responses[0].Limitations[0] = "mutated"
	if l.questionPackages[v.ID].Responses[0].EvidenceIDs[0] != "e" || l.questionPackages[v.ID].Responses[0].Limitations[0] != "Human review" {
		t.Fatal("result aliases committed package")
	}
}
