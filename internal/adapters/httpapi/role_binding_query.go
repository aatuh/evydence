package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func roleBindingFromQuery(binding identitydomain.RoleBinding) domain.RoleBinding {
	return domain.RoleBinding{
		ID: binding.ID, TenantID: binding.TenantID, SubjectType: binding.SubjectType,
		SubjectID: binding.SubjectID, Role: binding.Role, ResourceType: binding.ResourceType,
		ResourceID: binding.ResourceID, SchemaVersion: binding.SchemaVersion, CreatedAt: binding.CreatedAt,
	}
}
