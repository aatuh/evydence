package query

import (
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
)

func NewPortalAccessWriteAuthorizer() application.Authorizer {
	return packageCommandAuthorizer{action: authz.ActionPortalAccessManage}
}
