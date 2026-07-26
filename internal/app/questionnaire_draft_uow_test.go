package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingQuestionnaireDraftRepository struct{ FutureExtensionsRepository }

func (failingQuestionnaireDraftRepository) InsertQuestionnaireDraft(context.Context, domain.QuestionnaireDraft) error {
	return errInjectedRepositoryFailure
}

func TestQuestionnaireDraftUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
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
	template, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "Customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Is evidence recorded?"}}})
	if err != nil {
		t.Fatalf("create questionnaire template: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	draft, err := ledger.CreateQuestionnaireDraft(ctx, actor, CreateQuestionnaireDraftInput{TemplateID: template.ID, ProductID: product.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("create questionnaire draft: %v", err)
	}
	if _, ok := ledger.questionDrafts[draft.ID]; !ok || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("questionnaire draft was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingQuestionnaireDraftRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeDrafts, beforeChain := len(ledger.questionDrafts), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateQuestionnaireDraft(ctx, actor, CreateQuestionnaireDraftInput{TemplateID: template.ID, ProductID: product.ID, ReleaseID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed questionnaire draft err=%v, want injected repository failure", err)
	}
	if len(ledger.questionDrafts) != beforeDrafts || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed questionnaire draft published cached state")
	}
}
