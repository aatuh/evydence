package repositories

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var _ identityapp.SSOExchangeReader = identity{}

func (r identity) SSOProviderByID(ctx context.Context, id string) (identitydomain.SSOProvider, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(id, 1024) {
		return identitydomain.SSOProvider{}, app.ErrValidation
	}
	var tenant string
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(tenant_id)<=1024 THEN tenant_id ELSE '' END,octet_length(tenant_id)>1024 FROM sso_providers WHERE id=$1 FOR SHARE`, id).Scan(&tenant, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.SSOProvider{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.SSOProvider{}, writeError("read public SSO provider coordinate", err)
	}
	if oversized || tenant == "" {
		return identitydomain.SSOProvider{}, app.ErrConflict
	}
	return r.ReadOwnedSSOProvider(ctx, tenant, id)
}
func (r identity) IdentityLink(ctx context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(provider, 1024) || !validMembershipQueryText(subject, 65536) {
		return identitydomain.UserIdentityLink{}, false, app.ErrValidation
	}
	v, found, err := readSSOExchangeLink(ctx, r.tx, tenant, provider, subject)
	return identitydomain.UserIdentityLink(v), found, err
}
func (r identity) User(ctx context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return identitydomain.HumanUser{}, app.ErrValidation
	}
	v, found, err := readSSOExchangeUser(ctx, r.tx, tenant, id)
	if err == nil && !found {
		err = app.ErrNotFound
	}
	return identitydomain.HumanUser(v), err
}
func (r identity) UserGrants(ctx context.Context, tenant, id string) ([]identitydomain.ResourceGrant, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return nil, app.ErrValidation
	}
	bindings, err := readSSOExchangeRoleBindings(ctx, r.tx, tenant, id)
	if err != nil {
		return nil, err
	}
	grants := make([]identitydomain.ResourceGrant, 0, len(bindings))
	for _, b := range bindings {
		if scopes := identityapp.RoleScopes(b.Role); len(scopes) > 0 {
			grants = append(grants, identitydomain.ResourceGrant{Role: b.Role, ResourceType: b.ResourceType, ResourceID: b.ResourceID, Scopes: scopes})
		}
	}
	return grants, nil
}
