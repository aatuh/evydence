package httpapi

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

// Guards use native focused readers. Fresh historical fixture commands retain
// actual business validation and writes on the isolated command Ledger only.
type operationsFixtureCommands struct{ catalogFixtureCommands }

func operationsTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server.bindRepositoryIngestionFixtureScope()
	return server, secret
}
func (f operationsFixtureCommands) CreateIncident(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentInput) (operationsdomain.Incident, error) {
	v, err := f.commandLedger(ctx).CreateIncident(ctx, a, app.CreateIncidentInput(in))
	if err != nil {
		return operationsdomain.Incident{}, err
	}
	return domain.IncidentToContextModel(v)
}
func (f operationsFixtureCommands) RecordIncidentTimelineEvent(ctx context.Context, a domain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) (operationsdomain.IncidentTimelineEvent, error) {
	v, err := f.commandLedger(ctx).RecordIncidentTimelineEvent(ctx, a, id, app.RecordIncidentTimelineInput(in))
	return operationsdomain.IncidentTimelineEvent(v), err
}
func (f operationsFixtureCommands) CreateRemediationTask(ctx context.Context, a domain.Actor, in operationsapp.CreateRemediationTaskInput) (operationsdomain.RemediationTask, error) {
	v, err := f.commandLedger(ctx).CreateRemediationTask(ctx, a, app.CreateRemediationTaskInput{IncidentID: in.IncidentID, ReleaseID: in.ReleaseID, Title: in.Title, Owner: in.Owner, DueAt: in.DueAt, EvidenceID: in.EvidenceID})
	model := operationsdomain.RemediationTask(v)
	if v.DueAt != nil {
		at := *v.DueAt
		model.DueAt = &at
	}
	return model, err
}
func (f operationsFixtureCommands) CreateIncidentWebhookReceiver(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) (operationsdomain.IncidentWebhookReceiver, error) {
	v, err := f.commandLedger(ctx).CreateIncidentWebhookReceiver(ctx, a, app.CreateIncidentWebhookReceiverInput(in))
	return operationsdomain.IncidentWebhookReceiver(v), err
}

// The signed public callback has its own real atomic business replay protocol,
// not bearer/HTTP idempotency. Keep that historical fixture algorithm intact.
func (f operationsFixtureCommands) HandleIncidentWebhook(ctx context.Context, in operationsapp.HandleIncidentWebhookInput) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	v, event, err := f.commandLedger(ctx).HandleIncidentWebhook(ctx, app.HandleIncidentWebhookInput{ReceiverID: in.ReceiverID, EventID: in.EventID, Timestamp: in.Timestamp, Signature: in.Signature, Body: in.Body})
	return operationsdomain.IncidentWebhookEvent(v), operationsdomain.IncidentTimelineEvent(event), err
}
func (f operationsFixtureCommands) CreateLegalHold(ctx context.Context, a domain.Actor, in operationsapp.RetentionMarkerInput) (operationsdomain.LegalHold, error) {
	v, err := f.commandLedger(ctx).CreateLegalHold(ctx, a, app.CreateLegalHoldInput(in))
	model := operationsdomain.LegalHold(v)
	if v.ReleasedAt != nil {
		at := *v.ReleasedAt
		model.ReleasedAt = &at
	}
	return model, err
}
func (f operationsFixtureCommands) CreateRetentionOverride(ctx context.Context, a domain.Actor, in operationsapp.RetentionOverrideInput) (operationsdomain.RetentionOverride, error) {
	v, err := f.commandLedger(ctx).CreateRetentionOverride(ctx, a, app.CreateRetentionOverrideInput{ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner, RetentionUntil: in.RetentionUntil})
	return operationsdomain.RetentionOverride(v), err
}
func (s *Server) bindOperationsFixtureCommands(ledger *app.Ledger) {
	f := operationsFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.incidentCommands.(operationsFixtureCommands); s.incidentCommands == nil || fixture {
		s.incidentCommands = f
	}
	if _, fixture := s.incidentWebhookCommands.(operationsFixtureCommands); s.incidentWebhookCommands == nil || fixture {
		s.incidentWebhookCommands = f
	}
	if _, fixture := s.retentionMarkerCommands.(operationsFixtureCommands); s.retentionMarkerCommands == nil || fixture {
		s.retentionMarkerCommands = f
	}
}

var (
	_ IncidentCommands        = operationsFixtureCommands{}
	_ IncidentWebhookCommands = operationsFixtureCommands{}
	_ RetentionMarkerCommands = operationsFixtureCommands{}
)
