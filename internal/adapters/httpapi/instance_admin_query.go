package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func instanceAdminSnapshotFromQuery(snapshot operationsdomain.InstanceAdminSnapshot) domain.InstanceAdminSnapshot {
	return domain.InstanceAdminSnapshot{
		ReportType: snapshot.ReportType, TenantCount: snapshot.TenantCount,
		ResourceCounts: snapshot.ResourceCounts, Limitations: snapshot.Limitations,
		GeneratedAt: snapshot.GeneratedAt,
	}
}

func mapInstanceAdminQueryError(err error) error {
	switch {
	case errors.Is(err, operationsquery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, operationsquery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
