package query

import "github.com/aatuh/evydence/internal/application"

func NewPortalAccessWriteAuthorizer() application.Authorizer {
	return packageAccessAuthorizer{scope: "package:write"}
}
