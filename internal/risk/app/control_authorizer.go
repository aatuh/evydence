package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewControlAdminAuthorizer accepts only tenant-wide control administration.
// Human sessions need a current tenant grant, not a product/release grant.
func NewControlAdminAuthorizer() application.Authorizer { return controlAdminAuthorizer{} }

type controlAdminAuthorizer struct{}

func (controlAdminAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request != controlAdminRequest() {
		return application.ErrForbidden
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionControlsManage})
}
