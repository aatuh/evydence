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

func BuildQuestionnaireDraftCommands(factory app.UnitOfWorkFactory) (*packageapp.QuestionnaireDraftCommands, error) {
	if factory == nil {
		return nil, errors.New("questionnaire draft transactions are required")
	}
	return packageapp.NewQuestionnaireDraftCommands(packageapp.QuestionnaireDraftCommandConfig{Transactions: draftTransactions{factory}, Authorizer: packagequery.NewQuestionnaireDraftAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type draftRepository interface {
	packageapp.QuestionnaireDraftReader
	InsertFocusedQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error
}
type draftTransactions struct{ factory app.UnitOfWorkFactory }

func (t draftTransactions) ExecuteQuestionnaireDraft(ctx context.Context, tenant string, fn func(context.Context, packageapp.QuestionnaireDraftTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(draftRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, draftTransaction{r, repos.Audit})
	}))
}

type draftTransaction struct {
	draftRepository
	audit app.AuditRepository
}

func (t draftTransaction) InsertQuestionnaireDraft(ctx context.Context, v packagedomain.QuestionnaireDraft) error {
	return mapPackageAccessWriteError(t.InsertFocusedQuestionnaireDraft(ctx, v))
}
func (t draftTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewQuestionnaireDraftAuthorizer().Authorize(ctx, a, r)
}
func (t draftTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
