package app

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"time"

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

// Compare the entire public metadata snapshot under the same transaction lock
// as revocation. The credential hash is neither selected nor overwritten.
func (r memoryIdentityRepository) RevokeSSOSessionMetadata(ctx context.Context, previous identitydomain.SSOSession, now time.Time) error {
	if !memoryMembershipQueryText(previous.ID, 1024) || previous.Hash != "" || previous.RevokedAt != nil || now.IsZero() {
		return ErrValidation
	}
	return r.membershipRead(ctx, previous.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		stored, ok := state.SSOSessions[previous.ID]
		if !ok || stored.ID != previous.ID || stored.TenantID != previous.TenantID || stored.RevokedAt != nil {
			return ErrConflict
		}
		groups := slices.Clone(stored.Groups)
		if len(groups) == 0 {
			groups = nil
		}
		if stored.UserID != previous.UserID || stored.ProviderID != previous.ProviderID || stored.Prefix != previous.Prefix || stored.SchemaVersion != previous.SchemaVersion || !stored.ExpiresAt.Equal(previous.ExpiresAt) || !stored.CreatedAt.Equal(previous.CreatedAt) || !reflect.DeepEqual(groups, previous.Groups) {
			return ErrConflict
		}
		at := now.UTC()
		stored.RevokedAt = &at
		state.SSOSessions[stored.ID] = stored
		return nil
	})
}
