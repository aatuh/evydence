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

func BuildIncidentWebhookCommands(factory app.UnitOfWorkFactory) (*operationsapp.IncidentWebhookCommands, error) {
	if factory == nil {
		return nil, errors.New("incident webhook transactions are required")
	}
	t := incidentWebhookTransactions{factory}
	return operationsapp.NewIncidentWebhookCommands(operationsapp.IncidentWebhookCommandConfig{Transactions: t, Routing: t, Authorizer: operationsapp.NewIncidentWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type incidentWebhookRepository interface {
	InsertIncidentWebhookReceiver(context.Context, domain.IncidentWebhookReceiver) error
	InsertIncidentWebhookEvent(context.Context, domain.IncidentWebhookEvent, domain.IncidentTimelineEvent) error
}
type incidentWebhookTransactions struct{ factory app.UnitOfWorkFactory }

func (t incidentWebhookTransactions) LookupIncidentWebhookTenant(ctx context.Context, id string) (string, error) {
	var tenant string
	err := app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Risk.(operationsapp.IncidentWebhookRouting)
		if !ok {
			return app.ErrValidation
		}
		var err error
		tenant, err = reader.LookupIncidentWebhookTenant(ctx, id)
		return err
	})
	return tenant, mapEnvironmentWriteError(err)
}
func (t incidentWebhookTransactions) ExecuteIncidentWebhook(ctx context.Context, fn func(context.Context, operationsapp.IncidentWebhookTransaction) error) error {
	return mapEnvironmentWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		incidents, ok := repos.Risk.(operationsapp.IncidentReader)
		if !ok {
			return app.ErrValidation
		}
		webhooks, ok := repos.Risk.(operationsapp.IncidentWebhookReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, incidentWebhookTransaction{incidents, webhooks, repos.Risk, repos.Audit})
	}))
}

type incidentWebhookTransaction struct {
	incidents operationsapp.IncidentReader
	webhooks  operationsapp.IncidentWebhookReader
	writes    incidentWebhookRepository
	audit     app.AuditRepository
}

func (t incidentWebhookTransaction) ReadIncidentSubject(ctx context.Context, tenant, kind, id string) (operationsapp.IncidentSubject, error) {
	v, err := t.incidents.ReadIncidentSubject(ctx, tenant, kind, id)
	return v, mapEnvironmentWriteError(err)
}
func (t incidentWebhookTransaction) ReadIncidentWebhookReceiver(ctx context.Context, tenant, id string) (operationsdomain.IncidentWebhookReceiver, error) {
	v, err := t.webhooks.ReadIncidentWebhookReceiver(ctx, tenant, id)
	return v, mapEnvironmentWriteError(err)
}
func (t incidentWebhookTransaction) ReadIncidentWebhookReplay(ctx context.Context, tenant, receiver, event string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	v, e, err := t.webhooks.ReadIncidentWebhookReplay(ctx, tenant, receiver, event)
	return v, e, mapEnvironmentWriteError(err)
}
func (t incidentWebhookTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return operationsapp.NewIncidentWriteAuthorizer().Authorize(ctx, a, r)
}
func (t incidentWebhookTransaction) InsertIncidentWebhookReceiver(ctx context.Context, v operationsdomain.IncidentWebhookReceiver) error {
	return mapEnvironmentWriteError(t.writes.InsertIncidentWebhookReceiver(ctx, domain.IncidentWebhookReceiver(v)))
}
func (t incidentWebhookTransaction) InsertIncidentWebhookEvent(ctx context.Context, v operationsdomain.IncidentWebhookEvent, e operationsdomain.IncidentTimelineEvent) error {
	return mapEnvironmentWriteError(t.writes.InsertIncidentWebhookEvent(ctx, domain.IncidentWebhookEvent(v), domain.IncidentTimelineEvent(e)))
}
func (t incidentWebhookTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapEnvironmentWriteError(err)
}
