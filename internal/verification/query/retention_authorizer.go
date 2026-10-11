package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewRetentionAuthorizer() application.Authorizer { return retentionAuthorizer{} }
func NewBackupGenerationAuthorizer() application.Authorizer {
	return tenantAdministrationAuthorizer{action: authz.ActionBackupGenerate}
}

type retentionAuthorizer struct{}

func (retentionAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	switch request.Action {
	case authz.ActionRetentionPoliciesManage, authz.ActionRetentionPoliciesRead:
		return (tenantAdministrationAuthorizer{action: request.Action}).Authorize(ctx, actor, request)
	default:
		return application.ErrForbidden
	}
}
