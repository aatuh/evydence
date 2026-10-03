package query

import "github.com/aatuh/evydence/internal/application"

func NewGraphSnapshotAuthorizer() application.Authorizer {
	return questionnaireScopeAuthorizer{scope: "evidence:read"}
}
