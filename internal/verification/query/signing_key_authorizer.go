package query

import (
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
)

func NewSigningKeyAdminAuthorizer() application.Authorizer {
	return tenantAdministrationAuthorizer{action: authz.ActionSigningKeysManage}
}
func NewTrustConfigurationAuthorizer() application.Authorizer {
	return tenantAdministrationAuthorizer{action: authz.ActionTrustConfigurationsManage}
}
func NewSigningOperationAuthorizer() application.Authorizer {
	return tenantAdministrationAuthorizer{action: authz.ActionSigningOperationsCreate}
}
func NewMerkleCreationAuthorizer() application.Authorizer {
	return tenantAdministrationAuthorizer{action: authz.ActionMerkleBatchesCreate}
}
func NewTransparencyCheckpointAuthorizer() application.Authorizer {
	return tenantAdministrationAuthorizer{action: authz.ActionTransparencyCheckpointsRecord}
}
