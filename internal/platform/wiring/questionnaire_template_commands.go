package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildQuestionnaireTemplateCommands(factory app.UnitOfWorkFactory) (*packageapp.QuestionnaireTemplateCommands, error) {
	if factory == nil {
		return nil, errors.New("questionnaire template transactions are required")
	}
	return packageapp.NewQuestionnaireTemplateCommands(packageapp.QuestionnaireTemplateCommandConfig{Transactions: qTemplateTransactions{factory}, Authorizer: packagequery.NewQuestionnaireTemplateAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type qTemplateRepository interface {
	ValidateQuestionnaireTemplateScope(context.Context, string, []string) error
	InsertFocusedQuestionnaireTemplate(context.Context, packagedomain.QuestionnaireTemplate) error
}
type qTemplateTransactions struct{ factory app.UnitOfWorkFactory }

func (t qTemplateTransactions) ExecuteQuestionnaireTemplate(ctx context.Context, tenant string, fn func(context.Context, packageapp.QuestionnaireTemplateTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Enterprise.(qTemplateRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, qTemplateTransaction{r, repos.Audit})
	}))
}

type qTemplateTransaction struct {
	qTemplateRepository
	audit app.AuditRepository
}

func (t qTemplateTransaction) InsertQuestionnaireTemplate(ctx context.Context, v packagedomain.QuestionnaireTemplate) error {
	return mapPackageAccessWriteError(t.InsertFocusedQuestionnaireTemplate(ctx, v))
}
func (t qTemplateTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
