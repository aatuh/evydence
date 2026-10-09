package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func BuildIncidentCommands(factory app.UnitOfWorkFactory) (*operationsapp.IncidentCommands, error) {
	if factory == nil {
		return nil, errors.New("incident transactions are required")
	}
	return operationsapp.NewIncidentCommands(operationsapp.IncidentCommandConfig{Transactions: incidentTransactions{factory}, Authorizer: operationsapp.NewIncidentWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

// This legacy persistence bridge exposes only the three Operations-owned
// appends. No policy, vulnerability, webhook, or security-document API escapes.
type incidentRepository interface {
	InsertIncident(context.Context, domain.Incident) error
	InsertIncidentTimelineEvent(context.Context, domain.IncidentTimelineEvent) error
	InsertRemediationTask(context.Context, domain.RemediationTask) error
}
type incidentTransactions struct{ factory app.UnitOfWorkFactory }

func (t incidentTransactions) ExecuteIncident(ctx context.Context, fn func(context.Context, operationsapp.IncidentTransaction) error) error {
	return mapEnvironmentWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Risk.(operationsapp.IncidentReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, incidentTransaction{reader, repos.Risk, repos.Audit})
	}))
}

type incidentTransaction struct {
	reader    operationsapp.IncidentReader
	incidents incidentRepository
	audit     app.AuditRepository
}

func (t incidentTransaction) ReadIncidentSubject(ctx context.Context, tenant, kind, id string) (operationsapp.IncidentSubject, error) {
	v, err := t.reader.ReadIncidentSubject(ctx, tenant, kind, id)
	return v, mapEnvironmentWriteError(err)
}
func (t incidentTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return operationsapp.NewIncidentWriteAuthorizer().Authorize(ctx, a, r)
}
func (t incidentTransaction) InsertIncident(ctx context.Context, v operationsdomain.Incident) error {
	return mapEnvironmentWriteError(t.incidents.InsertIncident(ctx, domain.IncidentFromContextModel(v)))
}
func (t incidentTransaction) InsertIncidentTimelineEvent(ctx context.Context, v operationsdomain.IncidentTimelineEvent) error {
	return mapEnvironmentWriteError(t.incidents.InsertIncidentTimelineEvent(ctx, domain.IncidentTimelineEvent(v)))
}
func (t incidentTransaction) InsertRemediationTask(ctx context.Context, v operationsdomain.RemediationTask) error {
	return mapEnvironmentWriteError(t.incidents.InsertRemediationTask(ctx, domain.RemediationTask(v)))
}
func (t incidentTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, v)
	return receipt, mapEnvironmentWriteError(err)
}
