package query

import "github.com/aatuh/evydence/internal/application"

func NewPDFReportAuthorizer() application.Authorizer {
	return questionnaireScopeAuthorizer{scope: "report:read"}
}
