package app

import (
	"context"
	"encoding/json"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func (r memoryIdentityRepository) LockSSOProviderCreation(ctx context.Context, tenant string) error {
	return r.LockMembershipWrites(ctx, tenant)
}

// Match the focused provider projection's complete-or-conflict policy. This
// is a detached memory transaction read, not a SQL row-lock implementation.
func (r memoryIdentityRepository) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	var out identitydomain.SSOProvider
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		p, ok := state.SSOProviders[id]
		if !ok || p.ID != id || p.TenantID != tenant {
			return ErrNotFound
		}
		for _, field := range []string{p.Name, p.Issuer, p.ClientID, p.GroupsClaim} {
			if !memoryMembershipText(field, 65536) {
				return ErrConflict
			}
		}
		if !memoryMembershipText(p.Type, 128) || !memoryMembershipText(p.Status, 128) || !memoryMembershipText(p.SchemaVersion, 1024) {
			return ErrConflict
		}
		for _, field := range []any{p.RoleMapping, p.JWKS, p.SAMLSigningCertificates} {
			encoded, err := json.Marshal(field)
			if err != nil || len(encoded) > 131072 {
				return ErrConflict
			}
		}
		cloned, err := cloneMemoryJSON(p)
		if err != nil {
			return ErrConflict
		}
		out = identitydomain.SSOProvider(cloned)
		if len(out.RoleMapping) == 0 {
			out.RoleMapping = nil
		}
		if len(out.JWKS) == 0 {
			out.JWKS = nil
		}
		if len(out.SAMLSigningCertificates) == 0 {
			out.SAMLSigningCertificates = nil
		}
		out.CreatedAt = out.CreatedAt.UTC()
		if out.TrustMaterialUpdatedAt != nil {
			at := out.TrustMaterialUpdatedAt.UTC()
			out.TrustMaterialUpdatedAt = &at
		}
		return nil
	})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return out, nil
}

func (r memoryIdentityRepository) LockSSOIdentityLinkWrites(ctx context.Context, tenant string) error {
	return r.LockMembershipWrites(ctx, tenant)
}

// Linking is administrative metadata, not authentication: target lifecycle,
// user display names, organization parents and provider trust are irrelevant.
func (r memoryIdentityRepository) ValidateSSOIdentityLinkTargets(ctx context.Context, tenant, user, provider, email string) error {
	if !memoryMembershipQueryText(user, 1024) || !memoryMembershipQueryText(provider, 1024) || !memoryMembershipQueryText(email, identityapp.MaxMembershipKeyBytes) {
		return ErrValidation
	}
	return r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		u, ok := state.Users[user]
		if !ok || u.ID != user || u.TenantID != tenant || u.Email != email {
			return ErrNotFound
		}
		p, ok := state.SSOProviders[provider]
		if !ok || p.ID != provider || p.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}

var (
	_ identityapp.SSOProviderWriteReader     = memoryIdentityRepository{}
	_ identityapp.SSOIdentityLinkWriteReader = memoryIdentityRepository{}
)
