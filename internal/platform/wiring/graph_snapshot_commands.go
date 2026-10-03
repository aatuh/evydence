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

func BuildGraphSnapshotCommands(factory app.UnitOfWorkFactory) (*packageapp.GraphSnapshotCommands, error) {
	if factory == nil {
		return nil, errors.New("graph snapshot transactions are required")
	}
	return packageapp.NewGraphSnapshotCommands(packageapp.GraphSnapshotCommandConfig{Transactions: graphTransactions{factory}, Authorizer: packagequery.NewGraphSnapshotAuthorizer(), Hasher: verificationCanonicalHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type graphSnapshotRepository interface {
	packageapp.GraphSnapshotReader
	InsertFocusedGraphSnapshot(context.Context, packagedomain.EvidenceGraphSnapshot) error
}
type graphTransactions struct{ factory app.UnitOfWorkFactory }

func (t graphTransactions) ExecuteGraphSnapshot(ctx context.Context, tenant string, fn func(context.Context, packageapp.GraphSnapshotTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(graphSnapshotRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, graphTransaction{r, repos.Audit})
	}))
}

type graphTransaction struct {
	graphSnapshotRepository
	audit app.AuditRepository
}

func (t graphTransaction) InsertGraphSnapshot(ctx context.Context, v packagedomain.EvidenceGraphSnapshot) error {
	return mapPackageAccessWriteError(t.InsertFocusedGraphSnapshot(ctx, v))
}
func (t graphTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewGraphSnapshotAuthorizer().Authorize(ctx, a, r)
}
func (t graphTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
