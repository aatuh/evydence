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

func BuildAnswerLibraryCommands(factory app.UnitOfWorkFactory) (*packageapp.AnswerLibraryCommands, error) {
	if factory == nil {
		return nil, errors.New("answer library transactions are required")
	}
	return packageapp.NewAnswerLibraryCommands(packageapp.AnswerLibraryCommandConfig{Transactions: answerLibraryTransactions{factory}, Authorizer: packagequery.NewAnswerLibraryAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type answerLibraryRepository interface {
	packageapp.AnswerLibraryReader
	InsertFocusedAnswerLibraryEntry(context.Context, packagedomain.QuestionnaireAnswerLibraryEntry) error
}
type answerLibraryTransactions struct{ factory app.UnitOfWorkFactory }

func (t answerLibraryTransactions) ExecuteAnswerLibrary(ctx context.Context, tenant string, fn func(context.Context, packageapp.AnswerLibraryTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Enterprise.(answerLibraryRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, answerLibraryTransaction{r, repos.Audit})
	}))
}

type answerLibraryTransaction struct {
	repository answerLibraryRepository
	audit      app.AuditRepository
}

func (t answerLibraryTransaction) ReadAnswerLibraryScope(ctx context.Context, tenant, product, release string) (packageapp.AnswerLibraryScope, error) {
	v, err := t.repository.ReadAnswerLibraryScope(ctx, tenant, product, release)
	return v, mapPackageAccessWriteError(err)
}
func (t answerLibraryTransaction) ValidateAnswerLibraryReferences(ctx context.Context, s packageapp.AnswerLibraryScope, c string, ids []string) error {
	return mapPackageAccessWriteError(t.repository.ValidateAnswerLibraryReferences(ctx, s, c, ids))
}
func (t answerLibraryTransaction) InsertAnswerLibraryEntry(ctx context.Context, v packagedomain.QuestionnaireAnswerLibraryEntry) error {
	return mapPackageAccessWriteError(t.repository.InsertFocusedAnswerLibraryEntry(ctx, v))
}
func (t answerLibraryTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewAnswerLibraryAuthorizer().Authorize(ctx, a, r)
}
func (t answerLibraryTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
