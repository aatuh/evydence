package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestQuestionnaireAnswerLibraryFiltersEveryEntryForHumanGrant(t *testing.T) {
	ledger := NewLedger(Config{})
	ledger.products["prod_allowed"] = domain.Product{ID: "prod_allowed", TenantID: "ten_1"}
	ledger.answerLibrary = map[string]domain.QuestionnaireAnswerLibraryEntry{
		"allowed": {ID: "allowed", TenantID: "ten_1", ProductID: "prod_allowed", Answer: "allowed draft"},
		"other":   {ID: "other", TenantID: "ten_1", ProductID: "prod_other", Answer: "private draft"},
		"global":  {ID: "global", TenantID: "ten_1", Answer: "tenant-wide draft"},
		"foreign": {ID: "foreign", TenantID: "ten_2", ProductID: "prod_allowed", Answer: "foreign draft"},
	}
	actor := domain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{ScopePackageRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_allowed", Scopes: []string{ScopePackageRead}}}}
	for _, filter := range []ListQuestionnaireAnswerLibraryInput{{}, {ProductID: "prod_allowed"}} {
		entries, err := ledger.ListQuestionnaireAnswerLibrary(t.Context(), actor, filter)
		if err != nil || len(entries) != 1 || entries[0].ID != "allowed" {
			t.Fatalf("filter=%#v entries=%#v error=%v", filter, entries, err)
		}
	}
	actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_2", Scopes: []string{ScopePackageRead}}
	entries, err := ledger.ListQuestionnaireAnswerLibrary(t.Context(), actor, ListQuestionnaireAnswerLibraryInput{})
	if err != nil || len(entries) != 0 {
		t.Fatalf("foreign tenant grant entries=%#v error=%v", entries, err)
	}
	actor.ResourceGrants[0].ResourceID = actor.TenantID
	entries, err = ledger.ListQuestionnaireAnswerLibrary(t.Context(), actor, ListQuestionnaireAnswerLibraryInput{})
	if err != nil || len(entries) != 3 {
		t.Fatalf("tenant grant entries=%#v error=%v", entries, err)
	}
}

func TestQuestionnaireAnswerLibraryGlobalCreateRequiresTenantGrant(t *testing.T) {
	ledger := NewLedger(Config{})
	ledger.tenants["ten_1"] = domain.Tenant{ID: "ten_1"}
	actor := domain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{ScopePackageWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_allowed", Scopes: []string{ScopePackageWrite}}}}
	_, err := ledger.CreateQuestionnaireAnswerLibraryEntry(t.Context(), actor, CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q1", Answer: "tenant-wide draft"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-granted global draft create error=%v", err)
	}
	actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{ScopePackageWrite}}
	if _, err := ledger.CreateQuestionnaireAnswerLibraryEntry(t.Context(), actor, CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q1", Answer: "tenant-wide draft"}); err != nil {
		t.Fatalf("tenant-granted global draft create error=%v", err)
	}
}
