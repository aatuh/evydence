package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type redactionProfileFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type redactionProfileFixtureWriter interface {
	InsertFocusedRedactionProfile(context.Context, packagedomain.RedactionProfile) error
}
type redactionProfileFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type redactionProfileFixtureTransaction struct {
	writer   redactionProfileFixtureWriter
	audit    app.AuditRepository
	readOnly bool
}

func (f redactionProfileFixtureTransactions) ExecuteRedactionProfile(ctx context.Context, tenant string, run func(context.Context, packageapp.RedactionProfileTransaction) error) error {
	if ctx == nil || run == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		writer, ok := r.Packages.(redactionProfileFixtureWriter)
		fence, canFence := r.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || r.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return run(ctx, redactionProfileFixtureTransaction{writer: writer, audit: r.Audit, readOnly: f.readOnly})
	}))
}
func (t redactionProfileFixtureTransaction) InsertRedactionProfile(ctx context.Context, v packagedomain.RedactionProfile) error {
	if t.readOnly {
		panic("redaction preflight inserted policy")
	}
	return portalFixtureError(t.writer.InsertFocusedRedactionProfile(ctx, v))
}
func (t redactionProfileFixtureTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("redaction preflight appended audit")
	}
	receipt, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, v)
	return receipt, portalFixtureError(err)
}
func (f redactionProfileFixtureCommands) commands(readOnly bool) (*packageapp.RedactionProfileCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewRedactionProfileCommands(packageapp.RedactionProfileCommandConfig{Transactions: redactionProfileFixtureTransactions{catalogFixtureCommands: f.catalogFixtureCommands, readOnly: readOnly}, Authorizer: packagequery.NewRedactionProfileAuthorizer(), Clock: clock, IDs: ids})
}
func (f redactionProfileFixtureCommands) AuthorizeCreateRedactionProfile(ctx context.Context, a domain.Actor, in packageapp.CreateRedactionProfileInput) error {
	c, err := f.commands(true)
	if err != nil {
		return err
	}
	return portalFixtureError(c.AuthorizeCreateRedactionProfile(ctx, a, in))
}
func (f redactionProfileFixtureCommands) CreateRedactionProfile(ctx context.Context, a domain.Actor, in packageapp.CreateRedactionProfileInput) (packagedomain.RedactionProfile, error) {
	c, err := f.commands(false)
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	v, err := c.CreateRedactionProfile(ctx, a, in)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}

var _ RedactionProfileCommands = redactionProfileFixtureCommands{}

func createRedactionProfileFixture(ctx context.Context, ledger *repositoryFixture, a domain.Actor, in packageapp.CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	v, err := (redactionProfileFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateRedactionProfile(ctx, a, in)
	return domain.RedactionProfile(v), err
}
