package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildTransparencyCheckpointCommands(factory app.UnitOfWorkFactory) (*verificationapp.TransparencyCheckpointCommands, error) {
	if factory == nil {
		return nil, errors.New("transparency checkpoint transactions are required")
	}
	return verificationapp.NewTransparencyCheckpointCommands(verificationapp.TransparencyCheckpointConfig{Transactions: transparencyCheckpointTransactions{factory}, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Hasher: verificationCanonicalHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type transparencyCheckpointTransactions struct{ factory app.UnitOfWorkFactory }

func (t transparencyCheckpointTransactions) ExecuteTransparencyCheckpoint(ctx context.Context, fn func(context.Context, verificationapp.TransparencyCheckpointTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Integrity.(verificationapp.TransparencyCheckpointReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, transparencyCheckpointTransaction{reader, repos.Integrity, repos.Audit})
	}))
}

type transparencyCheckpointTransaction struct {
	reader    verificationapp.TransparencyCheckpointReader
	integrity app.IntegrityRepository
	audit     app.AuditRepository
}

func (t transparencyCheckpointTransaction) ReadTransparencyCheckpointSource(ctx context.Context, tenant, id string) (verificationapp.TransparencyCheckpointSource, error) {
	s, err := t.reader.ReadTransparencyCheckpointSource(ctx, tenant, id)
	return s, mapSigningKeyWriteError(err)
}
func (t transparencyCheckpointTransaction) InsertTransparencyCheckpoint(ctx context.Context, c verificationdomain.TransparencyCheckpoint) error {
	return mapSigningKeyWriteError(t.integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint{ID: c.ID, TenantID: c.TenantID, BatchID: c.BatchID, Provider: c.Provider, ExternalURL: c.ExternalURL, ExternalID: c.ExternalID, TimestampHash: c.TimestampHash, State: c.State, SchemaVersion: c.SchemaVersion, CreatedAt: c.CreatedAt}))
}
func (t transparencyCheckpointTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, a, r)
}
func (t transparencyCheckpointTransaction) AppendAudit(ctx context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, a)
	return r, mapSigningKeyWriteError(err)
}
