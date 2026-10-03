package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestQuestionnaireDraftCannotBypassAnswerLibraryGrant(t *testing.T) {
	l := NewLedger(Config{})
	l.products["product"] = domain.Product{ID: "product", TenantID: "tenant"}
	l.questionTemplates["template"] = domain.QuestionnaireTemplate{ID: "template", TenantID: "tenant", Questions: []domain.QuestionnaireQuestion{{ID: "q", Prompt: "Evidence?"}}}
	l.answerLibrary["global"] = domain.QuestionnaireAnswerLibraryEntry{ID: "global", TenantID: "tenant", QuestionID: "q", Answer: "private global answer"}
	a := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{ScopePackageRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopePackageRead}}}}
	v, err := l.CreateQuestionnaireDraft(t.Context(), a, CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product"})
	if err != nil || len(v.Responses) != 1 || strings.Contains(v.Responses[0].Answer, "private global answer") {
		t.Fatal("draft bypasses global answer authorization", err)
	}
	a.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopePackageRead}}
	v, err = l.CreateQuestionnaireDraft(t.Context(), a, CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product"})
	if err != nil || v.Responses[0].Answer != "private global answer" {
		t.Fatal("tenant authority lost global answer", err)
	}
}

func TestQuestionnaireDraftCitationsCannotEscapeRequestedScope(t *testing.T) {
	for _, source := range []string{"library", "control"} {
		t.Run(source, func(t *testing.T) {
			l := NewLedger(Config{})
			l.products["product"] = domain.Product{ID: "product", TenantID: "tenant"}
			l.products["other-product"] = domain.Product{ID: "other-product", TenantID: "tenant"}
			l.releases["release"] = domain.Release{ID: "release", TenantID: "tenant", ProductID: "product"}
			l.releases["other-release"] = domain.Release{ID: "other-release", TenantID: "tenant", ProductID: "other-product"}
			l.evidence["outside"] = domain.EvidenceItem{ID: "outside", TenantID: "tenant", ProductID: "other-product", ReleaseID: "other-release"}
			l.questionTemplates["template"] = domain.QuestionnaireTemplate{ID: "template", TenantID: "tenant", Questions: []domain.QuestionnaireQuestion{{ID: "q", ControlID: "control", Prompt: "Review?"}}}
			if source == "library" {
				l.answerLibrary["answer"] = domain.QuestionnaireAnswerLibraryEntry{ID: "answer", TenantID: "tenant", QuestionID: "q", ProductID: "product", ReleaseID: "release", Answer: "Review", EvidenceIDs: []string{"outside"}}
			} else {
				l.controlLinks["link"] = domain.ControlEvidence{ID: "link", TenantID: "tenant", ControlID: "control", ProductID: "product", ReleaseID: "release", SubjectType: "evidence", SubjectID: "outside"}
			}
			v, err := l.CreateQuestionnaireDraft(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageRead}}, CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"})
			if !errors.Is(err, ErrNotFound) || v.ID != "" || len(l.questionDrafts) != 0 {
				t.Fatal("out-of-scope citation published", err)
			}
		})
	}
}
