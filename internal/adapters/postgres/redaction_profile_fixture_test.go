package postgres

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type postgresRedactionFixture struct{ store *Store }
type postgresRedactionFixtureWriter interface {
	InsertFocusedRedactionProfile(context.Context, packagedomain.RedactionProfile) error
}
type postgresRedactionFixtureTransaction struct {
	writer postgresRedactionFixtureWriter
	audit  app.AuditRepository
}

// This outer test composition avoids the runtime wiring's PostgreSQL import
// cycle and never creates a Ledger or publishes redaction policy into its maps.
func newRedactionProfileFixture(store *Store) (*packageapp.RedactionProfileCommands, error) {
	if store == nil {
		return nil, app.ErrValidation
	}
	return packageapp.NewRedactionProfileCommands(packageapp.RedactionProfileCommandConfig{Transactions: postgresRedactionFixture{store}, Authorizer: packagequery.NewRedactionProfileAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}
func (f postgresRedactionFixture) ExecuteRedactionProfile(ctx context.Context, tenant string, run func(context.Context, packageapp.RedactionProfileTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		writer, ok := r.Packages.(postgresRedactionFixtureWriter)
		fence, canFence := r.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || r.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return run(ctx, postgresRedactionFixtureTransaction{writer, r.Audit})
	})
}
func (t postgresRedactionFixtureTransaction) InsertRedactionProfile(ctx context.Context, v packagedomain.RedactionProfile) error {
	return t.writer.InsertFocusedRedactionProfile(ctx, v)
}
func (t postgresRedactionFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := t.audit.Append(ctx, domain.AuditChainEntry{ID: e.ID, TenantID: e.TenantID, EntryType: e.EntryType, SubjectType: e.SubjectType, SubjectID: e.SubjectID, ActorType: e.ActorType, ActorID: e.ActorID, OccurredAt: e.OccurredAt, PayloadHash: e.PayloadHash, SignatureRef: e.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	if err != nil {
		return application.AuditReceipt{}, err
	}
	return application.AuditReceipt{ID: v.ID}, nil
}
