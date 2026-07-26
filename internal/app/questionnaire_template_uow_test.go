package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingQuestionnaireTemplateRepository struct{ EnterpriseRepository }

func (failingQuestionnaireTemplateRepository) InsertQuestionnaireTemplate(context.Context, domain.QuestionnaireTemplate) error {
	return errInjectedRepositoryFailure
}

func TestQuestionnaireTemplateUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	template, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "Customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Is evidence available?"}}})
	if err != nil {
		t.Fatalf("create questionnaire template: %v", err)
	}
	if ledger.questionTemplates[template.ID].ID != template.ID || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("questionnaire template was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Enterprise = failingQuestionnaireTemplateRepository{EnterpriseRepository: repositories.Enterprise}
		return repositories
	}}
	beforeTemplates, beforeChain := len(ledger.questionTemplates), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "Other", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Is other evidence available?"}}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed questionnaire template err=%v, want injected repository failure", err)
	}
	if len(ledger.questionTemplates) != beforeTemplates || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed questionnaire template published cached state")
	}
}
