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
	template.Questions[0].Prompt = "mutated"
	if ledger.questionTemplates[template.ID].Questions[0].Prompt == "mutated" {
		t.Fatal("returned template can edit historical state")
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

func TestQuestionnaireTemplateRejectsDuplicateQuestionsAndForeignControls(t *testing.T) {
	for _, kind := range []string{"duplicate", "missing control", "foreign control"} {
		t.Run(kind, func(t *testing.T) {
			ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
			in := CreateQuestionnaireTemplateInput{Name: "Customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q", Prompt: "Review?"}}}
			want := ErrNotFound
			switch kind {
			case "duplicate":
				in.Questions = append(in.Questions, domain.QuestionnaireQuestion{ID: " q ", Prompt: "Other?"})
				want = ErrValidation
			case "missing control":
				in.Questions[0].ControlID = "missing"
			case "foreign control":
				ledger.controls["foreign"] = domain.SecurityControl{ID: "foreign", TenantID: "other"}
				in.Questions[0].ControlID = "foreign"
			}
			beforeTemplates, beforeChain := len(ledger.questionTemplates), len(ledger.chain[actor.TenantID])
			if _, err := ledger.CreateQuestionnaireTemplate(t.Context(), actor, in); !errors.Is(err, want) {
				t.Fatalf("unsafe template accepted: %v; want %v", err, want)
			}
			if len(ledger.questionTemplates) != beforeTemplates || len(ledger.chain[actor.TenantID]) != beforeChain {
				t.Fatal("invalid template published state")
			}
		})
	}
}

func TestQuestionnaireTemplateRequiresTenantWideHumanAuthority(t *testing.T) {
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	actor.KeyID, actor.UserID = "", "human"
	actor.Scopes = []string{ScopePackageWrite}
	actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopePackageWrite}}}
	in := CreateQuestionnaireTemplateInput{Name: "Customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q", Prompt: "Review?"}}}
	if _, err := ledger.CreateQuestionnaireTemplate(t.Context(), actor, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("scoped human created a tenant-wide template: %v", err)
	}
}

func TestQuestionnaireTemplateLocalGuardRechecksControlAndFrameworkOwnership(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	l.frameworks["framework"] = domain.ControlFramework{ID: "framework", TenantID: a.TenantID}
	l.controls["control"] = domain.SecurityControl{ID: "control", TenantID: a.TenantID, FrameworkID: "framework"}
	if err := l.AuthorizeQuestionnaireTemplateCreate(t.Context(), a, []string{"control"}); err != nil {
		t.Fatal(err)
	}
	l.frameworks["framework"] = domain.ControlFramework{ID: "framework", TenantID: "other"}
	if err := l.AuthorizeQuestionnaireTemplateCreate(t.Context(), a, []string{"control"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign framework replayed", err)
	}
	l.frameworks["framework"] = domain.ControlFramework{ID: "framework", TenantID: a.TenantID}
	l.controls["control"] = domain.SecurityControl{ID: "control", TenantID: "other", FrameworkID: "framework"}
	if err := l.AuthorizeQuestionnaireTemplateCreate(t.Context(), a, []string{"control"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign control replayed", err)
	}
	delete(l.controls, "control")
	if err := l.AuthorizeQuestionnaireTemplateCreate(t.Context(), a, []string{"control"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing control replayed", err)
	}
}
