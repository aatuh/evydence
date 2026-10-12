package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildQuestionnairePackageCommands(factory app.UnitOfWorkFactory) (*packageapp.QuestionnairePackageCommands, error) {
	if factory == nil {
		return nil, errors.New("questionnaire package transactions are required")
	}
	return packageapp.NewQuestionnairePackageCommands(packageapp.QuestionnairePackageCommandConfig{Transactions: questionnairePackageTransactions{factory}, Authorizer: packagequery.NewQuestionnairePackageAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type questionnairePackageRepository interface {
	packageapp.QuestionnairePackageReader
	InsertFocusedQuestionnairePackage(context.Context, packagedomain.QuestionnairePackage) error
}
type questionnairePackageTransactions struct{ factory app.UnitOfWorkFactory }

func (t questionnairePackageTransactions) ExecuteQuestionnairePackage(ctx context.Context, tenant string, fn func(context.Context, packageapp.QuestionnairePackageTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Enterprise.(questionnairePackageRepository)
		responses, canRead := repos.Future.(packageapp.QuestionnaireResponseReader)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canRead || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, questionnairePackageTransaction{questionnairePackageRepository: r, QuestionnaireResponseReader: responses, audit: repos.Audit})
	}))
}

type questionnairePackageTransaction struct {
	questionnairePackageRepository
	packageapp.QuestionnaireResponseReader
	audit app.AuditRepository
}

func (t questionnairePackageTransaction) InsertQuestionnairePackage(ctx context.Context, v packagedomain.QuestionnairePackage) error {
	return mapPackageAccessWriteError(t.InsertFocusedQuestionnairePackage(ctx, v))
}
func (t questionnairePackageTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewQuestionnairePackageAuthorizer().Authorize(ctx, a, r)
}
func (t questionnairePackageTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
