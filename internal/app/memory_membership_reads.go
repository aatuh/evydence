package app

import (
	"context"
	"strings"
	"unicode/utf8"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// These test-adapter reads use the current transaction snapshot, never Ledger
// maps. Memory commits use optimistic conflicts; these are not SQL row locks.
func (r memoryIdentityRepository) membershipRead(ctx context.Context, tenant string, read func(*MemoryUnitOfWorkSnapshot) error) error {
	if ctx == nil || r.uow == nil || read == nil || !memoryMembershipQueryText(tenant, 1024) {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, tenant); err != nil {
			return err
		}
		return read(state)
	})
}

func memoryMembershipText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func memoryMembershipQueryText(value string, limit int) bool {
	return value != "" && strings.TrimSpace(value) == value && memoryMembershipText(value, limit)
}

func (r memoryIdentityRepository) LockMembershipWrites(ctx context.Context, tenant string) error {
	return r.membershipRead(ctx, tenant, func(*MemoryUnitOfWorkSnapshot) error { return nil })
}

func (r memoryIdentityRepository) OrganizationSlugExists(ctx context.Context, tenant, slug string) (bool, error) {
	if !memoryMembershipQueryText(slug, identityapp.MaxMembershipKeyBytes) || len(tenant)+len(slug) > identityapp.MaxMembershipKeyBytes {
		return false, ErrValidation
	}
	var found bool
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		for _, v := range state.Organizations {
			if v.TenantID == tenant && v.Slug == slug {
				found = true
				break
			}
		}
		return nil
	})
	return found, err
}

func (r memoryIdentityRepository) UserEmailExists(ctx context.Context, tenant, email string) (bool, error) {
	if !memoryMembershipQueryText(email, identityapp.MaxMembershipKeyBytes) || len(tenant)+len(email) > identityapp.MaxMembershipKeyBytes {
		return false, ErrValidation
	}
	var found bool
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		for _, v := range state.Users {
			if v.TenantID == tenant && v.Email == email {
				found = true
				break
			}
		}
		return nil
	})
	return found, err
}

func memoryMembershipOrganization(state *MemoryUnitOfWorkSnapshot, tenant, id string) error {
	v, ok := state.Organizations[id]
	if !ok || v.ID != id || v.TenantID != tenant {
		return ErrNotFound
	}
	return nil
}

func (r memoryIdentityRepository) ReadMembershipOrganization(ctx context.Context, tenant, id string) (identityapp.MembershipOrganization, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return identityapp.MembershipOrganization{}, ErrValidation
	}
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error { return memoryMembershipOrganization(state, tenant, id) })
	if err != nil {
		return identityapp.MembershipOrganization{}, err
	}
	return identityapp.MembershipOrganization{ID: id, TenantID: tenant}, nil
}

func (r memoryIdentityRepository) ReadMembershipUser(ctx context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return identitydomain.HumanUser{}, ErrValidation
	}
	var out identitydomain.HumanUser
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.Users[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryMembershipText(v.OrganizationID, 1024) || !memoryMembershipText(v.Email, 2304) || !memoryMembershipText(v.DisplayName, 65536) || !memoryMembershipText(v.Status, 128) || !memoryMembershipText(v.SchemaVersion, 1024) {
			return ErrConflict
		}
		out = identitydomain.HumanUser(v)
		out.CreatedAt = out.CreatedAt.UTC()
		if v.DeactivatedAt != nil {
			at := v.DeactivatedAt.UTC()
			out.DeactivatedAt = &at
		}
		return nil
	})
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	return out, nil
}

var _ identityapp.MembershipWriteReader = memoryIdentityRepository{}
