package app

import (
	"context"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// The provider ID is the public login coordinate. Resolve only its bounded
// tenant identity before using the existing complete owned trust projection.
func (r memoryIdentityRepository) SSOProviderByID(ctx context.Context, id string) (identitydomain.SSOProvider, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(id, 1024) {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	var tenant string
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		p, ok := state.SSOProviders[id]
		if !ok || p.ID != id {
			return ErrNotFound
		}
		if !memoryMembershipQueryText(p.TenantID, 1024) {
			return ErrConflict
		}
		tenant = p.TenantID
		return nil
	})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return r.ReadOwnedSSOProvider(ctx, tenant, id)
}

// Login compares the complete selected user snapshot, including historical
// fields larger than current membership-write limits; excess is never truncated.
func (r memoryIdentityRepository) User(ctx context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return identitydomain.HumanUser{}, ErrValidation
	}
	var out identitydomain.HumanUser
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		u, ok := state.Users[id]
		if !ok || u.ID != id || u.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryMembershipText(u.OrganizationID, 1024) || !memoryMembershipText(u.Email, 65536) || !memoryMembershipText(u.DisplayName, 65536) || !memoryMembershipText(u.Status, 128) || !memoryMembershipText(u.SchemaVersion, 1024) {
			return ErrConflict
		}
		out = identitydomain.HumanUser(u)
		out.CreatedAt = out.CreatedAt.UTC()
		if u.DeactivatedAt != nil {
			at := u.DeactivatedAt.UTC()
			out.DeactivatedAt = &at
		}
		return nil
	})
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	return out, nil
}
func (r memoryIdentityRepository) UserGrants(ctx context.Context, tenant, id string) ([]identitydomain.ResourceGrant, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return nil, ErrValidation
	}
	var out []identitydomain.ResourceGrant
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memorySessionUserGrants(state, tenant, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ identityapp.SSOExchangeReader = memoryIdentityRepository{}
