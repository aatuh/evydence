package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func collectorFromQuery(value integrationdomain.Collector) domain.Collector {
	return domain.Collector{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name,
		Type: value.Type, Version: value.Version, APIKeyID: value.APIKeyID,
		Status: value.Status.String(), AllowedScopes: value.AllowedScopes,
		LastSeenAt: value.LastSeenAt, SchemaVersion: value.SchemaVersion,
		CreatedAt: value.CreatedAt,
	}
}
