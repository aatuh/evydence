package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

var _ identityapp.SSOIdentityLinkWriteReader = identity{}

func (r identity) LockSSOIdentityLinkWrites(ctx context.Context, tenant string) error {
	return r.LockAPIKeyCreation(ctx, tenant)
}
func (r identity) ValidateSSOIdentityLinkTargets(ctx context.Context, tenant, user, provider, email string) error {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(user, 1024) || !validMembershipQueryText(provider, 1024) || !validMembershipQueryText(email, identityapp.MaxMembershipKeyBytes) {
		return app.ErrValidation
	}
	// One point query transfers only an existence marker. Target lifecycle,
	// display names, provider JWKS/certificates and credentials are not read.
	// Inactive targets remain linkable administrative metadata, not login grants.
	return requireRow(ctx, r.tx, `SELECT 1 FROM human_users u JOIN sso_providers p ON p.tenant_id=u.tenant_id
		WHERE u.tenant_id=$1 AND u.id=$2 AND p.id=$3 AND u.email=$4 FOR SHARE OF u,p`, tenant, user, provider, email)
}
