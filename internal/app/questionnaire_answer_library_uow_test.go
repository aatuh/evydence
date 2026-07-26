package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingQuestionnaireAnswerLibraryRepository struct{ EnterpriseRepository }

func (failingQuestionnaireAnswerLibraryRepository) InsertQuestionnaireAnswerLibraryEntry(context.Context, domain.QuestionnaireAnswerLibraryEntry) error {
	return errInjectedRepositoryFailure
}

func TestQuestionnaireAnswerLibraryUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "sbom", Title: "SBOM", PayloadHash: sampleDigest("answer-evidence")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	entry, err := ledger.CreateQuestionnaireAnswerLibraryEntry(ctx, actor, CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q1", EvidenceType: "sbom", ProductID: product.ID, ReleaseID: release.ID, Answer: "An SBOM evidence record is available.", EvidenceIDs: []string{evidence.ID}})
	if err != nil {
		t.Fatalf("create questionnaire answer library entry: %v", err)
	}
	if ledger.answerLibrary[entry.ID].ID != entry.ID || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("questionnaire answer library entry was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Enterprise = failingQuestionnaireAnswerLibraryRepository{EnterpriseRepository: repositories.Enterprise}
		return repositories
	}}
	beforeEntries, beforeChain := len(ledger.answerLibrary), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateQuestionnaireAnswerLibraryEntry(ctx, actor, CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q2", EvidenceType: "sbom", ProductID: product.ID, ReleaseID: release.ID, Answer: "Another answer.", EvidenceIDs: []string{evidence.ID}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed questionnaire answer library entry err=%v, want injected repository failure", err)
	}
	if len(ledger.answerLibrary) != beforeEntries || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed questionnaire answer library entry published cached state")
	}
}
