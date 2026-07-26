package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingQuestionnairePackageRepository struct{ EnterpriseRepository }

func (failingQuestionnairePackageRepository) InsertQuestionnairePackage(context.Context, domain.QuestionnairePackage) error {
	return errInjectedRepositoryFailure
}

func TestQuestionnairePackageUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
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
	template, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "Customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Is evidence available?"}}})
	if err != nil {
		t.Fatalf("create questionnaire template: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	pkg, err := ledger.CreateQuestionnairePackage(ctx, actor, CreateQuestionnairePackageInput{TemplateID: template.ID, ProductID: product.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("create questionnaire package: %v", err)
	}
	if ledger.questionPackages[pkg.ID].ID != pkg.ID || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("questionnaire package was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Enterprise = failingQuestionnairePackageRepository{EnterpriseRepository: repositories.Enterprise}
		return repositories
	}}
	beforePackages, beforeChain := len(ledger.questionPackages), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateQuestionnairePackage(ctx, actor, CreateQuestionnairePackageInput{TemplateID: template.ID, ProductID: product.ID, ReleaseID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed questionnaire package err=%v, want injected repository failure", err)
	}
	if len(ledger.questionPackages) != beforePackages || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed questionnaire package published cached state")
	}

	uow, err := memory.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin package validation unit of work: %v", err)
	}
	defer func() { _ = uow.Rollback(context.Background()) }()
	repositories := uow.Repositories()
	missingTemplate := pkg
	missingTemplate.ID = "questionnaire_package_missing_template"
	missingTemplate.TemplateID = "missing-template"
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, missingTemplate); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing questionnaire template err=%v, want not found", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, pkg); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate questionnaire package err=%v, want conflict", err)
	}
	unexpectedQuestion := pkg
	unexpectedQuestion.ID = "questionnaire_package_unexpected_question"
	unexpectedQuestion.Responses = []domain.QuestionnaireResponse{{QuestionID: "q2", Answer: "Unexpected question."}}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, unexpectedQuestion); !errors.Is(err, ErrValidation) {
		t.Fatalf("unexpected questionnaire response err=%v, want validation", err)
	}
	missingEvidence := pkg
	missingEvidence.ID = "questionnaire_package_missing_evidence"
	missingEvidence.Responses = []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Missing evidence.", EvidenceIDs: []string{"missing-evidence"}}}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, missingEvidence); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing questionnaire evidence err=%v, want not found", err)
	}
}
