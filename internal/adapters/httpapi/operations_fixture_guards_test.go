package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

// Only test binaries use this bridge. Native guard algorithms read actual
// focused transaction-owned repositories. Effect and private webhook-reader
// capabilities fail loudly; this is not proof of PostgreSQL row locks.
type operationsFixtureTransactions struct{ catalogFixtureCommands }
type operationsFixtureGuard struct {
	operationsapp.IncidentReader
	operationsapp.RetentionMarkerScopeLocker
}

func (f operationsFixtureTransactions) execute(ctx context.Context, run func(context.Context, operationsFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		incidents, ok := repos.Risk.(operationsapp.IncidentReader)
		if !ok {
			return app.ErrValidation
		}
		retention, ok := repos.Governance.(operationsapp.RetentionMarkerScopeLocker)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, operationsFixtureGuard{IncidentReader: incidents, RetentionMarkerScopeLocker: retention})
	})
}
func (f operationsFixtureTransactions) ExecuteIncident(ctx context.Context, run func(context.Context, operationsapp.IncidentTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx operationsFixtureGuard) error { return run(ctx, tx) })
}
func (f operationsFixtureTransactions) ExecuteIncidentWebhook(ctx context.Context, run func(context.Context, operationsapp.IncidentWebhookTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx operationsFixtureGuard) error { return run(ctx, tx) })
}
func (f operationsFixtureTransactions) ExecuteRetentionMarker(ctx context.Context, run func(context.Context, operationsapp.RetentionMarkerTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx operationsFixtureGuard) error { return run(ctx, tx) })
}
func (operationsFixtureGuard) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if r.Scope == "admin" {
		return operationsapp.NewRetentionMarkerAuthorizer().Authorize(ctx, a, r)
	}
	return operationsapp.NewIncidentWriteAuthorizer().Authorize(ctx, a, r)
}
func (operationsFixtureGuard) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("operations guard appended audit")
}
func (operationsFixtureGuard) InsertIncident(context.Context, operationsdomain.Incident) error {
	panic("operations guard inserted incident")
}
func (operationsFixtureGuard) InsertIncidentTimelineEvent(context.Context, operationsdomain.IncidentTimelineEvent) error {
	panic("operations guard inserted timeline")
}
func (operationsFixtureGuard) InsertRemediationTask(context.Context, operationsdomain.RemediationTask) error {
	panic("operations guard inserted task")
}
func (operationsFixtureGuard) InsertIncidentWebhookReceiver(context.Context, operationsdomain.IncidentWebhookReceiver) error {
	panic("operations guard inserted receiver")
}
func (operationsFixtureGuard) InsertIncidentWebhookEvent(context.Context, operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent) error {
	panic("operations guard inserted webhook")
}
func (operationsFixtureGuard) InsertLegalHold(context.Context, operationsdomain.LegalHold) error {
	panic("operations guard inserted hold")
}
func (operationsFixtureGuard) InsertRetentionOverride(context.Context, operationsdomain.RetentionOverride) error {
	panic("operations guard inserted override")
}
func (operationsFixtureGuard) ReadIncidentWebhookReceiver(context.Context, string, string) (operationsdomain.IncidentWebhookReceiver, error) {
	panic("receiver creation guard read webhook private metadata")
}
func (operationsFixtureGuard) ReadIncidentWebhookReplay(context.Context, string, string, string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	panic("receiver creation guard read webhook replay")
}
func (operationsFixtureGuard) LookupIncidentWebhookTenant(context.Context, string) (string, error) {
	panic("receiver creation guard routed callback")
}
func operationsFixtureGuardClock() time.Time { panic("operations guard read clock") }
func operationsFixtureGuardID(string) string { panic("operations guard allocated ID") }

func (f operationsFixtureCommands) incidentGuard() (*operationsapp.IncidentCommands, error) {
	return operationsapp.NewIncidentCommands(operationsapp.IncidentCommandConfig{Transactions: operationsFixtureTransactions(f), Authorizer: operationsapp.NewIncidentWriteAuthorizer(), Clock: application.ClockFunc(operationsFixtureGuardClock), IDs: application.IDGeneratorFunc(operationsFixtureGuardID)})
}
func (f operationsFixtureCommands) webhookGuard() (*operationsapp.IncidentWebhookCommands, error) {
	return operationsapp.NewIncidentWebhookCommands(operationsapp.IncidentWebhookCommandConfig{Transactions: operationsFixtureTransactions(f), Routing: operationsFixtureGuard{}, Authorizer: operationsapp.NewIncidentWriteAuthorizer(), Clock: application.ClockFunc(operationsFixtureGuardClock), IDs: application.IDGeneratorFunc(operationsFixtureGuardID)})
}
func (f operationsFixtureCommands) retentionGuard() (*operationsapp.RetentionMarkerCommands, error) {
	return operationsapp.NewRetentionMarkerCommands(operationsapp.RetentionMarkerConfig{Transactions: operationsFixtureTransactions(f), Authorizer: operationsapp.NewRetentionMarkerAuthorizer(), Clock: application.ClockFunc(operationsFixtureGuardClock), IDs: application.IDGeneratorFunc(operationsFixtureGuardID)})
}
func (f operationsFixtureCommands) AuthorizeCreateIncident(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentInput) error {
	guard, err := f.incidentGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateIncident(ctx, a, in)
}
func (f operationsFixtureCommands) AuthorizeRecordIncidentTimelineEvent(ctx context.Context, a domain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) error {
	guard, err := f.incidentGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeRecordIncidentTimelineEvent(ctx, a, id, in)
}
func (f operationsFixtureCommands) AuthorizeCreateRemediationTask(ctx context.Context, a domain.Actor, in operationsapp.CreateRemediationTaskInput) error {
	guard, err := f.incidentGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateRemediationTask(ctx, a, in)
}
func (f operationsFixtureCommands) AuthorizeCreateIncidentWebhookReceiver(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) error {
	guard, err := f.webhookGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateIncidentWebhookReceiver(ctx, a, in)
}
func (f operationsFixtureCommands) AuthorizeRetentionMarker(ctx context.Context, a domain.Actor, kind, id string) error {
	guard, err := f.retentionGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeRetentionMarker(ctx, a, kind, id)
}
