package query

import (
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
)

// NewReportAuthorizer binds HTML generation to central product/release policy.
func NewReportAuthorizer() application.Authorizer {
	return packageCommandAuthorizer{action: authz.ActionCRAReadinessHTMLGenerate}
}
