package app

import (
	"context"
	"encoding/json"
	"sort"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// These credential candidates are selected by prefix, never Ledger caches.
// Memory bounds/detachment are not SQL query/transfer/durability evidence.
func (r memoryIdentityRepository) APIKeysByPrefix(ctx context.Context, prefix string) ([]identitydomain.APIKey, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(prefix, 12) {
		return nil, ErrValidation
	}
	out := make([]identitydomain.APIKey, 0)
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		for id, key := range state.APIKeys {
			if key.Prefix != prefix || key.RevokedAt != nil {
				continue
			}
			if key.ID != id || len(out) == 64 || !memoryMembershipQueryText(key.ID, 1024) || !memoryMembershipQueryText(key.TenantID, 1024) || !memoryMembershipText(key.Name, 65536) || !memoryMembershipText(key.Hash, 64) || len(key.Hash) != 64 || len(key.Scopes) > 256 {
				return ErrConflict
			}
			scopes, err := json.Marshal(key.Scopes)
			if err != nil || len(scopes) > 1<<20 {
				return ErrConflict
			}
			for _, scope := range key.Scopes {
				if !memoryMembershipText(scope, 128) {
					return ErrConflict
				}
			}
			out = append(out, identitydomain.APIKey(cloneMemoryAPIKey(key)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (r memoryIdentityRepository) CollectorByAPIKey(ctx context.Context, tenant, key string) (identityapp.CollectorBinding, bool, error) {
	if !memoryMembershipQueryText(key, 1024) {
		return identityapp.CollectorBinding{}, false, ErrValidation
	}
	var out identityapp.CollectorBinding
	found := false
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		for id, c := range state.Collectors {
			if c.TenantID != tenant || c.APIKeyID != key {
				continue
			}
			if found || c.ID != id || !memoryMembershipQueryText(c.ID, 1024) {
				return ErrConflict
			}
			out, found = identityapp.CollectorBinding{ID: c.ID, TenantID: tenant, APIKeyID: key}, true
		}
		return nil
	})
	if err != nil {
		return identityapp.CollectorBinding{}, false, err
	}
	return out, found, nil
}

// Validate both current coordinates before either heartbeat changes, then
// update only lifecycle timestamps under one transaction lock. Metadata and
// credential hashes are preserved; successful outer commit remains required.
func (r memoryIdentityRepository) RecordAPIKeyUse(ctx context.Context, key identitydomain.APIKey, activity identityapp.CollectorActivity) error {
	if !memoryMembershipQueryText(key.ID, 1024) || key.LastUsedAt == nil || key.Hash == "" || key.Prefix == "" {
		return ErrValidation
	}
	return r.membershipRead(ctx, key.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		stored, ok := state.APIKeys[key.ID]
		at := key.LastUsedAt.UTC()
		if !ok || stored.ID != key.ID || stored.TenantID != key.TenantID || stored.Prefix != key.Prefix || !secretHashEqual(stored.Hash, key.Hash) || stored.RevokedAt != nil || stored.ExpiresAt != nil && !stored.ExpiresAt.After(at) {
			return ErrUnauthorized
		}
		if activity.ID != "" {
			c, ok := state.Collectors[activity.ID]
			if !ok || c.ID != activity.ID || activity.TenantID != key.TenantID || c.TenantID != key.TenantID || c.APIKeyID != key.ID || activity.LastSeenAt.IsZero() {
				return ErrUnauthorized
			}
		}
		if stored.LastUsedAt == nil || at.After(stored.LastUsedAt.UTC()) {
			stored.LastUsedAt = &at
		}
		state.APIKeys[key.ID] = stored
		if activity.ID != "" {
			c := state.Collectors[activity.ID]
			at := activity.LastSeenAt.UTC()
			if c.LastSeenAt == nil || at.After(c.LastSeenAt.UTC()) {
				c.LastSeenAt = &at
			}
			state.Collectors[c.ID] = c
		}
		return nil
	})
}

var _ identityapp.AuthenticationReader = memoryIdentityRepository{}
