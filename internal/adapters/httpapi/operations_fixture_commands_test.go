package httpapi

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

// Commands and guards compose actual focused services over the ambient typed
// repositories; they never call the historical Ledger incident algorithms.
type operationsFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}

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
	return server, secret
}
func (f operationsFixtureCommands) CreateIncident(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentInput) (operationsdomain.Incident, error) {
	c, err := f.nativeIncident(false)
	if err != nil {
		return operationsdomain.Incident{}, err
	}
	v, err := c.CreateIncident(ctx, a, in)
	return v, mapDeploymentCommandError(err)
}
func (f operationsFixtureCommands) RecordIncidentTimelineEvent(ctx context.Context, a domain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) (operationsdomain.IncidentTimelineEvent, error) {
	c, err := f.nativeIncident(false)
	if err != nil {
		return operationsdomain.IncidentTimelineEvent{}, err
	}
	v, err := c.RecordIncidentTimelineEvent(ctx, a, id, in)
	return v, mapDeploymentCommandError(err)
}
func (f operationsFixtureCommands) CreateRemediationTask(ctx context.Context, a domain.Actor, in operationsapp.CreateRemediationTaskInput) (operationsdomain.RemediationTask, error) {
	c, err := f.nativeIncident(false)
	if err != nil {
		return operationsdomain.RemediationTask{}, err
	}
	v, err := c.CreateRemediationTask(ctx, a, in)
	return v, mapDeploymentCommandError(err)
}
func (f operationsFixtureCommands) CreateIncidentWebhookReceiver(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) (operationsdomain.IncidentWebhookReceiver, error) {
	c, err := f.nativeIncidentWebhook(false)
	if err != nil {
		return operationsdomain.IncidentWebhookReceiver{}, err
	}
	v, err := c.CreateIncidentWebhookReceiver(ctx, a, in)
	return v, mapDeploymentCommandError(err)
}

func (f operationsFixtureCommands) HandleIncidentWebhook(ctx context.Context, in operationsapp.HandleIncidentWebhookInput) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	c, err := f.nativeIncidentWebhook(false)
	if err != nil {
		return operationsdomain.IncidentWebhookEvent{}, operationsdomain.IncidentTimelineEvent{}, err
	}
	v, event, err := c.HandleIncidentWebhook(ctx, in)
	return v, event, mapDeploymentCommandError(err)
}
func (f operationsFixtureCommands) CreateLegalHold(ctx context.Context, a domain.Actor, in operationsapp.RetentionMarkerInput) (operationsdomain.LegalHold, error) {
	c, err := f.nativeRetention(false)
	if err != nil {
		return operationsdomain.LegalHold{}, err
	}
	v, err := c.CreateLegalHold(ctx, a, in)
	return v, mapDeploymentCommandError(err)
}
func (f operationsFixtureCommands) CreateRetentionOverride(ctx context.Context, a domain.Actor, in operationsapp.RetentionOverrideInput) (operationsdomain.RetentionOverride, error) {
	c, err := f.nativeRetention(false)
	if err != nil {
		return operationsdomain.RetentionOverride{}, err
	}
	v, err := c.CreateRetentionOverride(ctx, a, in)
	return v, mapDeploymentCommandError(err)
}
func (s *Server) bindOperationsFixtureCommands(ledger *app.Ledger) {
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.incidentCommands.(operationsFixtureCommands); fixture {
		old.ledger = ledger
		s.incidentCommands = old
	} else if s.incidentCommands == nil {
		s.incidentCommands = f
	}
	if old, fixture := s.incidentWebhookCommands.(operationsFixtureCommands); fixture {
		old.ledger = ledger
		s.incidentWebhookCommands = old
	} else if s.incidentWebhookCommands == nil {
		s.incidentWebhookCommands = f
	}
	if old, fixture := s.retentionMarkerCommands.(operationsFixtureCommands); fixture {
		old.ledger = ledger
		s.retentionMarkerCommands = old
	} else if s.retentionMarkerCommands == nil {
		s.retentionMarkerCommands = f
	}
}

var (
	_ IncidentCommands        = operationsFixtureCommands{}
	_ IncidentWebhookCommands = operationsFixtureCommands{}
	_ RetentionMarkerCommands = operationsFixtureCommands{}
)
