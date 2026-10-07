package app

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Focused transaction-snapshot capabilities for tests. No Ledger maps or SQL
// row-lock guarantees are involved; memory commits detect optimistic conflicts.
func memoryPortalScope(state *MemoryUnitOfWorkSnapshot, tenant, id string) (packageapp.PortalPackageScope, error) {
	var empty packageapp.PortalPackageScope
	p, ok := state.CustomerPackages[id]
	if !ok || p.ID != id || p.TenantID != tenant || !memoryMembershipQueryText(p.ProductID, 1024) || !memoryResourceBelongsToTenant(p.ProductID, tenant, state.Products) {
		return empty, ErrNotFound
	}
	if state.Products[p.ProductID].ID != p.ProductID {
		return empty, ErrNotFound
	}
	if p.ReleaseID != "" {
		r, ok := state.Releases[p.ReleaseID]
		if !ok || r.ID != p.ReleaseID || r.TenantID != tenant || r.ProductID != p.ProductID || !memoryMembershipQueryText(r.ID, 1024) {
			return empty, ErrNotFound
		}
	}
	return packageapp.PortalPackageScope{TenantID: tenant, PackageID: id, Resources: application.ResourceReferences{ProductID: p.ProductID, ReleaseID: p.ReleaseID, CustomerPackageID: id}}, nil
}
func (r memoryIdentityRepository) ReadPortalPackageScope(ctx context.Context, tenant, id string) (packageapp.PortalPackageScope, error) {
	var out packageapp.PortalPackageScope
	if !memoryMembershipQueryText(id, 1024) {
		return out, ErrValidation
	}
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryPortalScope(state, tenant, id)
		return err
	})
	return out, err
}
func (r memoryIdentityRepository) readMemoryPortalAccess(ctx context.Context, tenant, id string, credential bool) (packagedomain.CustomerPortalAccess, error) {
	var out packagedomain.CustomerPortalAccess
	if !memoryMembershipQueryText(id, 1024) {
		return out, ErrValidation
	}
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.CustomerPortalAccess[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if credential && !memoryMembershipText(v.Hash, 64) {
			return ErrConflict
		}
		if !credential {
			v.Hash = ""
		}
		out = packageapp.ClonePortalAccess(packagedomain.CustomerPortalAccess(v))
		if err := packageapp.ValidatePortalAccessProjection(out); err != nil {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return packagedomain.CustomerPortalAccess{}, err
	}
	return out, nil
}
func (r memoryIdentityRepository) ReadPortalAccessForRevocation(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	return r.readMemoryPortalAccess(ctx, tenant, id, false)
}
func (r memoryIdentityRepository) ReadPortalAccessForToken(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	return r.readMemoryPortalAccess(ctx, tenant, id, true)
}
func (r memoryIdentityRepository) LookupPortalAccess(ctx context.Context, prefix string) (packageapp.PortalAccessCandidate, error) {
	var out packageapp.PortalAccessCandidate
	if ctx == nil || r.uow == nil {
		return out, ErrValidation
	}
	if len(prefix) != 12 || !strings.HasPrefix(prefix, "evycp_") || !memoryMembershipText(prefix, 12) {
		return out, ErrUnauthorized
	}
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		count := 0
		for id, v := range state.CustomerPortalAccess {
			if v.Prefix != prefix {
				continue
			}
			count++
			if count > 1 || id != v.ID || !memoryMembershipQueryText(v.ID, 1024) || !memoryMembershipQueryText(v.TenantID, 1024) {
				return ErrUnauthorized
			}
			out = packageapp.PortalAccessCandidate{TenantID: v.TenantID, AccessID: v.ID}
		}
		if count != 1 {
			return ErrUnauthorized
		}
		return nil
	})
	if err != nil {
		return packageapp.PortalAccessCandidate{}, err
	}
	return out, nil
}
func (r memoryIdentityRepository) InsertFocusedPortalAccess(ctx context.Context, v packagedomain.CustomerPortalAccess) error {
	if err := packageapp.ValidatePortalAccessCreation(v); err != nil {
		return err
	}
	cloned := domain.CustomerPortalAccess(packageapp.ClonePortalAccess(v))
	return r.membershipRead(ctx, v.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		if _, err := memoryPortalScope(state, v.TenantID, v.PackageID); err != nil {
			return err
		}
		if _, exists := state.CustomerPortalAccess[v.ID]; exists {
			return ErrConflict
		}
		state.CustomerPortalAccess[v.ID] = cloned
		return nil
	})
}
func (r memoryIdentityRepository) RevokeFocusedPortalAccess(ctx context.Context, tenant, id string, at time.Time) error {
	if !memoryMembershipQueryText(id, 1024) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return ErrValidation
	}
	return r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.CustomerPortalAccess[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if v.RevokedAt != nil {
			return ErrConflict
		}
		v.RevokedAt = &at
		state.CustomerPortalAccess[id] = v
		return nil
	})
}
func (r memoryIdentityRepository) UpdateFocusedPortalTokenAccess(ctx context.Context, previous, current packagedomain.CustomerPortalAccess) error {
	if err := packageapp.ValidatePortalTokenTransition(previous, current); err != nil {
		return err
	}
	old := domain.CustomerPortalAccess(packageapp.ClonePortalAccess(previous))
	v := domain.CustomerPortalAccess(packageapp.ClonePortalAccess(current))
	return r.membershipRead(ctx, v.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		stored, ok := state.CustomerPortalAccess[v.ID]
		if !ok || stored.ID != v.ID || stored.TenantID != v.TenantID {
			return ErrNotFound
		}
		if !reflect.DeepEqual(stored, old) {
			return ErrConflict
		}
		state.CustomerPortalAccess[v.ID] = v
		return nil
	})
}
func (r memoryIdentityRepository) PagePortalAccess(ctx context.Context, request packagequery.PortalAccessPageRequest) (appquery.Result[packagequery.PortalAccessPoint], error) {
	var out appquery.Result[packagequery.PortalAccessPoint]
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return out, err
	}
	visible := func(scope packageapp.PortalPackageScope) bool {
		return request.TenantWide || slices.Contains(request.AllowedPackageIDs, scope.PackageID) || slices.Contains(request.AllowedProductIDs, scope.Resources.ProductID) || scope.Resources.ReleaseID != "" && slices.Contains(request.AllowedReleaseIDs, scope.Resources.ReleaseID)
	}
	err := r.membershipRead(ctx, request.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		if request.PackageID != "" {
			scope, err := memoryPortalScope(state, request.TenantID, request.PackageID)
			if err != nil {
				return packagequery.ErrPortalAccessNotFound
			}
			if !visible(scope) {
				return ErrForbidden
			}
		}
		items := []packagequery.PortalAccessPoint{}
		for id, v := range state.CustomerPortalAccess {
			if v.ID != id || v.TenantID != request.TenantID || request.PackageID != "" && v.PackageID != request.PackageID {
				continue
			}
			scope, err := memoryPortalScope(state, request.TenantID, v.PackageID)
			if err != nil || !visible(scope) {
				continue
			}
			v.Hash = ""
			items = append(items, packagequery.PortalAccessPoint{Access: packageapp.ClonePortalAccess(packagedomain.CustomerPortalAccess(v)), ProductID: scope.Resources.ProductID, ReleaseID: scope.Resources.ReleaseID})
		}
		var err error
		out, err = appquery.Page(items, request.Page, request.After, func(v packagequery.PortalAccessPoint, sort appquery.Sort) appquery.SortKey {
			return appquery.RecordSortKey(v.Access.ID, v.Access.CreatedAt, sort)
		})
		return err
	})
	return out, err
}

var (
	_ packageapp.PortalAccessWriteReader = memoryIdentityRepository{}
	_ packageapp.PortalAccessLookup      = memoryIdentityRepository{}
	_ packagequery.PortalAccessReader    = memoryIdentityRepository{}
)
