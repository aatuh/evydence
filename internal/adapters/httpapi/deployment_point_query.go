package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func deploymentEventFromQuery(event operationsdomain.DeploymentEvent) domain.DeploymentEvent {
	return domain.DeploymentEvent{
		ID: event.ID, TenantID: event.TenantID, EnvironmentID: event.EnvironmentID,
		ReleaseID: event.ReleaseID, ArtifactIDs: event.ArtifactIDs, Status: event.Status,
		StartedAt: event.StartedAt, FinishedAt: event.FinishedAt, RollbackOf: event.RollbackOf,
		EvidenceID: event.EvidenceID, SchemaVersion: event.SchemaVersion, CreatedAt: event.CreatedAt,
	}
}

func mapDeploymentPointQueryError(err error) error {
	switch {
	case errors.Is(err, operationsquery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, operationsquery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
