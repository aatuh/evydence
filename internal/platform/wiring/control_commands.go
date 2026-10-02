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

// BuildControlCommands composes manual framework/control creation on the active
// unit of work only. No pool reader, broad inventory, or Ledger is required.
func BuildControlCommands(factory app.UnitOfWorkFactory) (*riskapp.ControlCommands, error) {
	if factory == nil {
		return nil, errors.New("control transactions are required")
	}
	return riskapp.NewControlCommands(riskapp.ControlCommandConfig{Authorizer: riskapp.NewControlAdminAuthorizer(), Transactions: controlTransactions{factory: factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type controlTransactions struct{ factory app.UnitOfWorkFactory }

func (t controlTransactions) ExecuteControls(ctx context.Context, command func(context.Context, riskapp.ControlTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Controls.(riskapp.ControlCreationReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, controlTransaction{reader: reader, writer: repos.Controls, audit: repos.Audit})
	}))
}

type controlTransaction struct {
	reader riskapp.ControlCreationReader
	writer app.ControlRepository
	audit  app.AuditRepository
}

func (t controlTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return riskapp.NewControlAdminAuthorizer().Authorize(ctx, actor, request)
}
func (t controlTransaction) FrameworkVersionExists(ctx context.Context, tenant, slug, version string) (bool, error) {
	v, err := t.reader.FrameworkVersionExists(ctx, tenant, slug, version)
	return v, mapControlWriteError(err)
}
func (t controlTransaction) ControlFrameworkExists(ctx context.Context, tenant, id string) (bool, error) {
	v, err := t.reader.ControlFrameworkExists(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t controlTransaction) SecurityControlCodeExists(ctx context.Context, tenant, framework, code string) (bool, error) {
	v, err := t.reader.SecurityControlCodeExists(ctx, tenant, framework, code)
	return v, mapControlWriteError(err)
}
func (t controlTransaction) InsertControlFramework(ctx context.Context, v riskdomain.ControlFramework) error {
	return mapControlWriteError(t.writer.InsertControlFramework(ctx, domain.ControlFramework{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Slug: v.Slug, Version: v.Version, Description: v.Description, Status: v.Status, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t controlTransaction) InsertSecurityControl(ctx context.Context, v riskdomain.SecurityControl) error {
	reqs := make([]domain.ControlEvidenceRequirement, 0, len(v.EvidenceRequirements))
	for _, r := range v.EvidenceRequirements {
		reqs = append(reqs, domain.ControlEvidenceRequirement{Type: r.Type, FreshnessDays: r.FreshnessDays, Required: r.Required})
	}
	return mapControlWriteError(t.writer.InsertSecurityControl(ctx, domain.SecurityControl{ID: v.ID, TenantID: v.TenantID, FrameworkID: v.FrameworkID, Code: v.Code, Title: v.Title, Objective: v.Objective, EvidenceRequirements: reqs, Applicability: v.Applicability, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t controlTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	entry, err := t.audit.Append(ctx, domain.AuditChainEntry{ID: v.ID, TenantID: v.TenantID, EntryType: v.EntryType, SubjectType: v.SubjectType, SubjectID: v.SubjectID, ActorType: v.ActorType, ActorID: v.ActorID, OccurredAt: v.OccurredAt, PayloadHash: v.PayloadHash, SignatureRef: v.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	if err != nil {
		return application.AuditReceipt{}, mapControlWriteError(err)
	}
	return application.AuditReceipt{ID: entry.ID}, nil
}
func mapControlWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return riskapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return riskapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return riskapp.ErrConflict
	default:
		return err
	}
}
