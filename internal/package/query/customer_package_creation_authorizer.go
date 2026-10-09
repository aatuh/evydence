package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewCustomerPackageCreationAuthorizer() application.Authorizer {
	return customerCreationAuthorizer{}
}

type customerCreationAuthorizer struct{}

func (customerCreationAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if !r.ScopeOnly && (r.TenantWide || r.Resources.ProductID == "") {
		return application.ErrForbidden
	}
	return (questionnaireScopeAuthorizer{scope: "package:write"}).Authorize(ctx, a, r)
}
