package app

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Session authentication uses selected current rows, not aggregate caches.
// These memory ports model bounds and detachment, not SQL locking/durability.
func (r memoryIdentityRepository) SessionsByPrefix(ctx context.Context, prefix string) ([]identitydomain.SSOSession, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(prefix, 12) {
		return nil, ErrValidation
	}
	out := make([]identitydomain.SSOSession, 0)
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		for id, v := range state.SSOSessions {
			if v.Prefix != prefix || v.RevokedAt != nil {
				continue
			}
			if v.ID != id || len(out) == 64 {
				return ErrConflict
			}
			for _, text := range []string{v.ID, v.TenantID, v.UserID, v.ProviderID, v.SchemaVersion} {
				if !memoryMembershipQueryText(text, 1024) {
					return ErrConflict
				}
			}
			if !memoryMembershipText(v.Hash, 64) || len(v.Hash) != 64 || len(v.Groups) > 256 {
				return ErrConflict
			}
			groups, err := json.Marshal(v.Groups)
			if err != nil || len(groups) > 1<<20 {
				return ErrConflict
			}
			for _, group := range v.Groups {
				if !memoryMembershipText(group, 1<<20) {
					return ErrConflict
				}
			}
			out = append(out, identitydomain.SSOSession(cloneMemorySSOSession(v)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func memorySessionUserGrants(state *MemoryUnitOfWorkSnapshot, tenant, user string) ([]identitydomain.ResourceGrant, error) {
	bindings := make([]domain.RoleBinding, 0)
	for _, b := range state.RoleBindings {
		if b.TenantID != tenant || b.SubjectType != "user" || b.SubjectID != user {
			continue
		}
		if len(bindings) == 256 || !memoryMembershipText(b.Role, 128) || !memoryMembershipText(b.ResourceType, 1024) || !memoryMembershipText(b.ResourceID, 1024) {
			return nil, ErrConflict
		}
		bindings = append(bindings, b)
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].CreatedAt.Equal(bindings[j].CreatedAt) {
			return bindings[i].ID < bindings[j].ID
		}
		return bindings[i].CreatedAt.Before(bindings[j].CreatedAt)
	})
	out := make([]identitydomain.ResourceGrant, 0, len(bindings))
	for _, b := range bindings {
		if scopes := identityapp.RoleScopes(b.Role); len(scopes) > 0 {
			out = append(out, identitydomain.ResourceGrant{Role: b.Role, ResourceType: b.ResourceType, ResourceID: b.ResourceID, Scopes: scopes})
		}
	}
	return out, nil
}

func (r memoryIdentityRepository) SessionIdentity(ctx context.Context, session identitydomain.SSOSession) (identityapp.SessionIdentity, error) {
	if !memoryMembershipQueryText(session.UserID, 1024) || !memoryMembershipQueryText(session.ProviderID, 1024) || len(session.Groups) > 256 {
		return identityapp.SessionIdentity{}, ErrValidation
	}
	var out identityapp.SessionIdentity
	err := r.membershipRead(ctx, session.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		user, ok := state.Users[session.UserID]
		if !ok || user.ID != session.UserID || user.TenantID != session.TenantID {
			return ErrNotFound
		}
		if !memoryMembershipText(user.Email, 65536) || !memoryMembershipText(user.Status, 128) {
			return ErrConflict
		}
		grants, err := memorySessionUserGrants(state, session.TenantID, user.ID)
		if err != nil {
			return err
		}
		if p, ok := state.SSOProviders[session.ProviderID]; ok && p.ID == session.ProviderID && p.TenantID == session.TenantID {
			mapping, err := json.Marshal(p.RoleMapping)
			if err != nil || len(mapping) > 1<<20 || !memoryMembershipText(p.GroupsClaim, 65536) {
				return ErrConflict
			}
			for group, role := range p.RoleMapping {
				if !memoryMembershipText(group, 65536) || !memoryMembershipText(role, 128) {
					return ErrConflict
				}
			}
			grants = append(grants, identityapp.ProviderGroupGrants(identitydomain.SSOProvider{TenantID: p.TenantID, GroupsClaim: p.GroupsClaim, RoleMapping: p.RoleMapping}, session.Groups)...)
		}
		out = identityapp.SessionIdentity{User: identitydomain.HumanUser{ID: user.ID, TenantID: user.TenantID, Email: user.Email, Status: user.Status}, Grants: grants}
		return nil
	})
	if err != nil {
		return identityapp.SessionIdentity{}, err
	}
	return out, nil
}
