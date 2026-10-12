package query

import (
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
)

func NewEvidenceSummaryAuthorizer() application.Authorizer {
	return packageCommandAuthorizer{action: authz.ActionEvidenceSummariesCreate}
}
