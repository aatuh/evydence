package app

import (
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestAnswerLibraryLocalListCannotMutateStoredDraft(t *testing.T) {
	l := NewLedger(Config{})
	l.answerLibrary["answer"] = domain.QuestionnaireAnswerLibraryEntry{ID: "answer", TenantID: "tenant", Answer: "Draft", EvidenceIDs: []string{"evidence"}, Limitations: []string{"Review"}}
	items, err := l.ListQuestionnaireAnswerLibrary(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageRead}}, ListQuestionnaireAnswerLibraryInput{})
	if err != nil || len(items) != 1 {
		t.Fatal("list failed", err)
	}
	items[0].EvidenceIDs[0], items[0].Limitations[0] = "mutated", "mutated"
	if l.answerLibrary["answer"].EvidenceIDs[0] != "evidence" || l.answerLibrary["answer"].Limitations[0] != "Review" {
		t.Fatal("listed slices mutated immutable library entry")
	}
}
