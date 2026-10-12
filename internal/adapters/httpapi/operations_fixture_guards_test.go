package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

// Actual focused preflights use current repositories and fail-loud read-only
// transactions. They never use Ledger ownership maps, clocks or ID allocation.
func (f operationsFixtureCommands) AuthorizeCreateIncident(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentInput) error {
	c, err := f.nativeIncident(true)
	if err != nil {
		return err
	}
	return mapDeploymentCommandError(c.AuthorizeCreateIncident(ctx, a, in))
}
func (f operationsFixtureCommands) AuthorizeRecordIncidentTimelineEvent(ctx context.Context, a domain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) error {
	c, err := f.nativeIncident(true)
	if err != nil {
		return err
	}
	return mapDeploymentCommandError(c.AuthorizeRecordIncidentTimelineEvent(ctx, a, id, in))
}
func (f operationsFixtureCommands) AuthorizeCreateRemediationTask(ctx context.Context, a domain.Actor, in operationsapp.CreateRemediationTaskInput) error {
	c, err := f.nativeIncident(true)
	if err != nil {
		return err
	}
	return mapDeploymentCommandError(c.AuthorizeCreateRemediationTask(ctx, a, in))
}
func (f operationsFixtureCommands) AuthorizeCreateIncidentWebhookReceiver(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) error {
	c, err := f.nativeIncidentWebhook(true)
	if err != nil {
		return err
	}
	return mapDeploymentCommandError(c.AuthorizeCreateIncidentWebhookReceiver(ctx, a, in))
}
func (f operationsFixtureCommands) AuthorizeRetentionMarker(ctx context.Context, a domain.Actor, kind, id string) error {
	c, err := f.nativeRetention(true)
	if err != nil {
		return err
	}
	return mapDeploymentCommandError(c.AuthorizeRetentionMarker(ctx, a, kind, id))
}
