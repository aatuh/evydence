package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// BuildControlEvidenceCommands requires only transaction-scoped repositories,
// not a pool reader, Ledger, or preloaded tenant catalog.
func BuildControlEvidenceCommands(factory app.UnitOfWorkFactory) (*riskapp.ControlEvidenceCommands, error) {
	if factory == nil {
		return nil, errors.New("control evidence transactions are required")
	}
	auth, err := riskapp.NewControlEvidenceWriteAuthorizer(controlArtifactGrantReads{factory})
	if err != nil {
		return nil, err
	}
	return riskapp.NewControlEvidenceCommands(riskapp.ControlEvidenceCommandConfig{Authorizer: auth, Transactions: controlEvidenceTransactions{factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type controlEvidenceStorageReader interface {
	riskapp.ControlEvidenceReader
	riskapp.ControlEvidenceArtifactGrantReader
}
type controlArtifactGrantReads struct{ factory app.UnitOfWorkFactory }

func (r controlArtifactGrantReads) ControlEvidenceArtifactVisible(ctx context.Context, request riskapp.ControlEvidenceArtifactGrantRequest) (bool, error) {
	var v bool
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Controls.(riskapp.ControlEvidenceArtifactGrantReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		v, err = reader.ControlEvidenceArtifactVisible(ctx, request)
		return err
	})
	return v, mapControlWriteError(err)
}

type controlEvidenceTransactions struct{ factory app.UnitOfWorkFactory }

func (t controlEvidenceTransactions) ExecuteControlEvidence(ctx context.Context, fn func(context.Context, riskapp.ControlEvidenceTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Controls.(controlEvidenceStorageReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		auth, err := riskapp.NewControlEvidenceWriteAuthorizer(reader)
		if err != nil {
			return err
		}
		return fn(ctx, controlEvidenceTransaction{reader: reader, writer: repos.Controls, audit: repos.Audit, authorizer: auth})
	}))
}

type controlEvidenceTransaction struct {
	reader     controlEvidenceStorageReader
	writer     app.ControlRepository
	audit      app.AuditRepository
	authorizer application.Authorizer
}

func (t controlEvidenceTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return mapControlWriteError(t.authorizer.Authorize(ctx, a, r))
}
func (t controlEvidenceTransaction) ControlEvidenceControlExists(ctx context.Context, tenant, id string) (bool, error) {
	v, err := t.reader.ControlEvidenceControlExists(ctx, tenant, id)
	return v, mapControlWriteError(err)
}

func (t controlEvidenceTransaction) LockControlEvidenceTenant(ctx context.Context, tenant string) error {
	return mapControlWriteError(t.reader.LockControlEvidenceTenant(ctx, tenant))
}
func (t controlEvidenceTransaction) ReadControlEvidenceSubject(ctx context.Context, tenant string, key riskapp.ControlEvidenceSubjectKey) (riskapp.ControlEvidenceSubjectCoordinates, error) {
	v, err := t.reader.ReadControlEvidenceSubject(ctx, tenant, key)
	return v, mapControlWriteError(err)
}
func (t controlEvidenceTransaction) ReadControlEvidenceLink(ctx context.Context, tenant string, key riskapp.ControlEvidenceLinkKey) (riskdomain.ControlEvidence, bool, error) {
	v, found, err := t.reader.ReadControlEvidenceLink(ctx, tenant, key)
	return v, found, mapControlWriteError(err)
}
func (t controlEvidenceTransaction) InsertControlEvidence(ctx context.Context, v riskdomain.ControlEvidence) error {
	return mapControlWriteError(t.writer.InsertControlEvidence(ctx, domain.ControlEvidence{ID: v.ID, TenantID: v.TenantID, ControlID: v.ControlID, EvidenceType: v.EvidenceType, SubjectType: v.SubjectType, SubjectID: v.SubjectID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Confidence: v.Confidence, Notes: v.Notes, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t controlEvidenceTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return (controlTransaction{audit: t.audit}).AppendAudit(ctx, v)
}
