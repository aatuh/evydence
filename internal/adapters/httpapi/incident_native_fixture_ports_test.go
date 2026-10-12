package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type incidentFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type incidentFixtureTransaction struct {
	reader   operationsapp.IncidentReader
	webhooks operationsapp.IncidentWebhookReader
	repos    app.Repositories
	readOnly bool
}

func (f incidentFixtureTransactions) ExecuteIncident(ctx context.Context, run func(context.Context, operationsapp.IncidentTransaction) error) error {
	if ctx == nil || run == nil {
		return operationsapp.ErrValidation
	}
	return deploymentFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Risk.(operationsapp.IncidentReader)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, incidentFixtureTransaction{reader: reader, repos: r, readOnly: f.readOnly})
	}))
}
func (f incidentFixtureTransactions) ExecuteIncidentWebhook(ctx context.Context, run func(context.Context, operationsapp.IncidentWebhookTransaction) error) error {
	if ctx == nil || run == nil {
		return operationsapp.ErrValidation
	}
	return deploymentFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Risk.(operationsapp.IncidentReader)
		webhooks, hasWebhook := r.Risk.(operationsapp.IncidentWebhookReader)
		if !ok || !hasWebhook || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, incidentFixtureTransaction{reader: reader, webhooks: webhooks, repos: r, readOnly: f.readOnly})
	}))
}
func (f incidentFixtureTransactions) LookupIncidentWebhookTenant(ctx context.Context, id string) (string, error) {
	if f.readOnly {
		panic("receiver preflight routed a callback")
	}
	if ctx == nil {
		return "", operationsapp.ErrValidation
	}
	var tenant string
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Risk.(operationsapp.IncidentWebhookRouting)
		if !ok {
			return app.ErrValidation
		}
		var err error
		tenant, err = reader.LookupIncidentWebhookTenant(ctx, id)
		return err
	})
	if err != nil {
		return "", deploymentFixtureCoreError(err)
	}
	return tenant, nil
}
func (t incidentFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return operationsapp.NewIncidentWriteAuthorizer().Authorize(ctx, a, r)
}
func (t incidentFixtureTransaction) ReadIncidentSubject(ctx context.Context, tenant, kind, id string) (operationsapp.IncidentSubject, error) {
	v, err := t.reader.ReadIncidentSubject(ctx, tenant, kind, id)
	return v, deploymentFixtureCoreError(err)
}
func (t incidentFixtureTransaction) ReadIncidentWebhookReceiver(ctx context.Context, tenant, id string) (operationsdomain.IncidentWebhookReceiver, error) {
	if t.readOnly {
		panic("receiver preflight read private authority")
	}
	v, err := t.webhooks.ReadIncidentWebhookReceiver(ctx, tenant, id)
	return v, deploymentFixtureCoreError(err)
}
func (t incidentFixtureTransaction) ReadIncidentWebhookReplay(ctx context.Context, tenant, receiver, event string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	if t.readOnly {
		panic("receiver preflight read business replay")
	}
	v, e, err := t.webhooks.ReadIncidentWebhookReplay(ctx, tenant, receiver, event)
	return v, e, deploymentFixtureCoreError(err)
}
func (t incidentFixtureTransaction) InsertIncident(ctx context.Context, v operationsdomain.Incident) error {
	if t.readOnly || t.webhooks != nil {
		panic("incident preflight or webhook inserted incident")
	}
	return deploymentFixtureCoreError(t.repos.Risk.InsertIncident(ctx, domain.IncidentFromContextModel(v)))
}
func (t incidentFixtureTransaction) InsertIncidentTimelineEvent(ctx context.Context, v operationsdomain.IncidentTimelineEvent) error {
	if t.readOnly || t.webhooks != nil {
		panic("incident preflight or webhook inserted timeline directly")
	}
	return deploymentFixtureCoreError(t.repos.Risk.InsertIncidentTimelineEvent(ctx, domain.IncidentTimelineEvent(v)))
}
func (t incidentFixtureTransaction) InsertRemediationTask(ctx context.Context, v operationsdomain.RemediationTask) error {
	if t.readOnly || t.webhooks != nil {
		panic("incident preflight or webhook inserted task")
	}
	return deploymentFixtureCoreError(t.repos.Risk.InsertRemediationTask(ctx, domain.RemediationTask(v)))
}
func (t incidentFixtureTransaction) InsertIncidentWebhookReceiver(ctx context.Context, v operationsdomain.IncidentWebhookReceiver) error {
	if t.readOnly || t.webhooks == nil {
		panic("incident preflight or command inserted receiver")
	}
	return deploymentFixtureCoreError(t.repos.Risk.InsertIncidentWebhookReceiver(ctx, domain.IncidentWebhookReceiver(v)))
}
func (t incidentFixtureTransaction) InsertIncidentWebhookEvent(ctx context.Context, v operationsdomain.IncidentWebhookEvent, e operationsdomain.IncidentTimelineEvent) error {
	if t.readOnly || t.webhooks == nil {
		panic("incident preflight or command inserted callback")
	}
	return deploymentFixtureCoreError(t.repos.Risk.InsertIncidentWebhookEvent(ctx, domain.IncidentWebhookEvent(v), domain.IncidentTimelineEvent(e)))
}
func (t incidentFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("incident preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, deploymentFixtureCoreError(err)
}
func (f operationsFixtureCommands) nativeIncident(readOnly bool) (*operationsapp.IncidentCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return operationsapp.NewIncidentCommands(operationsapp.IncidentCommandConfig{Transactions: incidentFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: operationsapp.NewIncidentWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f operationsFixtureCommands) nativeIncidentWebhook(readOnly bool) (*operationsapp.IncidentWebhookCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	transactions := incidentFixtureTransactions{f.catalogFixtureCommands, readOnly}
	return operationsapp.NewIncidentWebhookCommands(operationsapp.IncidentWebhookCommandConfig{Transactions: transactions, Routing: transactions, Authorizer: operationsapp.NewIncidentWriteAuthorizer(), Clock: clock, IDs: ids})
}
