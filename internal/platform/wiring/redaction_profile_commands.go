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

func BuildRedactionProfileCommands(factory app.UnitOfWorkFactory) (*packageapp.RedactionProfileCommands, error) {
	if factory == nil {
		return nil, errors.New("redaction profile transactions are required")
	}
	return packageapp.NewRedactionProfileCommands(packageapp.RedactionProfileCommandConfig{Transactions: redactionProfileTransactions{factory}, Authorizer: packagequery.NewRedactionProfileAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type redactionProfileWriter interface {
	InsertFocusedRedactionProfile(context.Context, packagedomain.RedactionProfile) error
}
type redactionProfileTransactions struct{ factory app.UnitOfWorkFactory }

func (t redactionProfileTransactions) ExecuteRedactionProfile(ctx context.Context, tenant string, fn func(context.Context, packageapp.RedactionProfileTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		writer, ok := repos.Packages.(redactionProfileWriter)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		// Join durable replay's active transaction. The common tenant writer
		// fence precedes tenant/audit locks and survives until outer commit.
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, redactionProfileTransaction{writer, repos.Audit})
	}))
}

type redactionProfileTransaction struct {
	writer redactionProfileWriter
	audit  app.AuditRepository
}

func (t redactionProfileTransaction) InsertRedactionProfile(ctx context.Context, v packagedomain.RedactionProfile) error {
	return mapPackageAccessWriteError(t.writer.InsertFocusedRedactionProfile(ctx, v))
}
func (t redactionProfileTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
