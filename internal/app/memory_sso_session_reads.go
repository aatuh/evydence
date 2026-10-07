package app

import (
	"context"
	"encoding/json"
	"slices"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func (r memoryIdentityRepository) LockSSOSessionWrites(ctx context.Context, tenant string) error {
	return r.LockMembershipWrites(ctx, tenant)
}

// Issuance checks current active-user and provider ownership only, never user
// PII, provider trust or credentials. Memory uses optimistic transaction state.
func (r memoryIdentityRepository) ValidateSSOSessionTargets(ctx context.Context, tenant, user, provider string) error {
	if !memoryMembershipQueryText(user, 1024) || !memoryMembershipQueryText(provider, 1024) {
		return ErrValidation
	}
	return r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		u, ok := state.Users[user]
		if !ok || u.ID != user || u.TenantID != tenant || u.Status != "active" {
			return ErrNotFound
		}
		p, ok := state.SSOProviders[provider]
		if !ok || p.ID != provider || p.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}

// Revocation reads immutable session coordinates and lifecycle metadata, not
// credential hashes or login parents. Expired/revoked sessions remain readable.
func (r memoryIdentityRepository) ReadSSOSessionForRevocation(ctx context.Context, tenant, id string) (identitydomain.SSOSession, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return identitydomain.SSOSession{}, ErrValidation
	}
	var out identitydomain.SSOSession
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.SSOSessions[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		for _, field := range []string{v.UserID, v.ProviderID, v.Prefix, v.SchemaVersion} {
			if !memoryMembershipText(field, 1024) {
				return ErrConflict
			}
		}
		groups, err := json.Marshal(v.Groups)
		if err != nil || len(groups) > 131072 {
			return ErrConflict
		}
		for _, group := range v.Groups {
			if !memoryMembershipText(group, 131072) {
				return ErrConflict
			}
		}
		out = identitydomain.SSOSession{ID: id, TenantID: tenant, UserID: v.UserID, ProviderID: v.ProviderID, Prefix: v.Prefix, Groups: slices.Clone(v.Groups), ExpiresAt: v.ExpiresAt.UTC(), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt.UTC()}
		if len(out.Groups) == 0 {
			out.Groups = nil
		}
		if v.RevokedAt != nil {
			at := v.RevokedAt.UTC()
			out.RevokedAt = &at
		}
		return nil
	})
	if err != nil {
		return identitydomain.SSOSession{}, err
	}
	return out, nil
}

var (
	_ identityapp.SSOSessionWriteReader      = memoryIdentityRepository{}
	_ identityapp.SSOSessionRevocationReader = memoryIdentityRepository{}
)
