package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

var _ identityapp.SSOSessionWriteReader = identity{}

func (r identity) LockSSOSessionWrites(ctx context.Context, tenant string) error {
	return r.LockAPIKeyCreation(ctx, tenant)
}
func (r identity) ValidateSSOSessionTargets(ctx context.Context, tenant, user, provider string) error {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(user, 1024) || !validMembershipQueryText(provider, 1024) {
		return app.ErrValidation
	}
	// Administrative issuance requires an active user but preserves the existing
	// provider-existence policy. No names, mailboxes, trust material or credentials
	// are selected; current ownership and lifecycle remain held through commit.
	return requireRow(ctx, r.tx, `SELECT 1 FROM human_users u JOIN sso_providers p ON p.tenant_id=u.tenant_id
		WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active' AND p.id=$3 FOR SHARE OF u,p`, tenant, user, provider)
}
