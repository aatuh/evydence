package app

import (
	"context"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func (r memoryIdentityRepository) LockRoleBindingWrites(ctx context.Context, tenant string) error {
	return r.LockMembershipWrites(ctx, tenant)
}

// Role-target checks project ownership only: no user email/display name,
// provider material, credentials, package manifests or evidence are read.
func (r memoryIdentityRepository) ValidateSubject(ctx context.Context, tenant, kind, id string) error {
	if !memoryMembershipQueryText(id, 1024) {
		return ErrValidation
	}
	return r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		switch kind {
		case "user":
			v, ok := state.Users[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			if !memoryMembershipText(v.OrganizationID, 1024) {
				return ErrConflict
			}
			if v.OrganizationID != "" {
				return memoryMembershipOrganization(state, tenant, v.OrganizationID)
			}
			return nil
		case "collector":
			v, ok := state.Collectors[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			key, ok := state.APIKeys[v.APIKeyID]
			if !ok || key.ID != v.APIKeyID || key.TenantID != tenant {
				return ErrNotFound
			}
			return nil
		default:
			return ErrValidation
		}
	})
}

func memoryRoleProduct(state *MemoryUnitOfWorkSnapshot, tenant, id string) error {
	if !memoryMembershipQueryText(id, 1024) {
		return ErrConflict
	}
	v, ok := state.Products[id]
	if !ok || v.ID != id || v.TenantID != tenant {
		return ErrNotFound
	}
	return nil
}

func memoryRoleRelease(state *MemoryUnitOfWorkSnapshot, tenant, id, product string) error {
	if id == "" {
		return ErrNotFound
	}
	if !memoryMembershipQueryText(id, 1024) {
		return ErrConflict
	}
	v, ok := state.Releases[id]
	if !ok || v.ID != id || v.TenantID != tenant || product != "" && v.ProductID != product {
		return ErrNotFound
	}
	return memoryRoleProduct(state, tenant, v.ProductID)
}

func (r memoryIdentityRepository) ValidateResource(ctx context.Context, tenant, kind, id string) error {
	if id != "" && !memoryMembershipQueryText(id, 1024) {
		return ErrValidation
	}
	return r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		switch kind {
		case "":
			if id != "" {
				return ErrValidation
			}
			return nil
		case "tenant":
			if id != "" && id != tenant {
				return ErrNotFound
			}
			return nil
		case "product":
			if id == "" {
				return ErrNotFound
			}
			return memoryRoleProduct(state, tenant, id)
		case "project":
			if id == "" {
				return ErrNotFound
			}
			v, ok := state.Projects[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			return memoryRoleProduct(state, tenant, v.ProductID)
		case "release":
			return memoryRoleRelease(state, tenant, id, "")
		case "customer_security_package":
			v, ok := state.CustomerPackages[id]
			if id == "" || !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			if !memoryMembershipText(v.ProductID, 1024) || !memoryMembershipText(v.ReleaseID, 1024) {
				return ErrConflict
			}
			if err := memoryRoleProduct(state, tenant, v.ProductID); err != nil {
				return err
			}
			if v.ReleaseID != "" {
				return memoryRoleRelease(state, tenant, v.ReleaseID, v.ProductID)
			}
			return nil
		case "evidence_bundle":
			v, ok := state.EvidenceBundles[id]
			if id == "" || !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			if !memoryMembershipText(v.ReleaseID, 1024) {
				return ErrConflict
			}
			if v.ReleaseID != "" {
				return memoryRoleRelease(state, tenant, v.ReleaseID, "")
			}
			return nil
		default:
			return ErrValidation
		}
	})
}

var _ identityapp.RoleBindingWriteReader = memoryIdentityRepository{}
