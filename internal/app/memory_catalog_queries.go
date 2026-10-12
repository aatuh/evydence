package app

import (
	"context"
	"errors"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Focused test-backend readers use current transaction rows, not Ledger.
// Memory scans key fields before selected metadata; it does not confer SQL
// query/transfer bounds or row-lock durability.
func (r memoryReleaseCatalogRepository) catalogQueryRead(ctx context.Context, tenant, id string, read func(*MemoryUnitOfWorkSnapshot) error) error {
	if id != "" && !memoryMembershipQueryText(id, 1024) {
		return releasequery.ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, read)
	if errors.Is(err, ErrNotFound) {
		return releasequery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		return releasequery.ErrValidation
	}
	return err
}

func catalogProductPoint(s *MemoryUnitOfWorkSnapshot, tenant, id string) (domain.Product, error) {
	p, ok := s.Products[id]
	if !ok || p.ID != id || p.TenantID != tenant {
		return domain.Product{}, releasequery.ErrNotFound
	}
	return p, nil
}
func catalogProductMetadata(p domain.Product) (releasedomain.Product, error) {
	if !memoryMembershipQueryText(p.ID, 1024) || !memoryMembershipQueryText(p.TenantID, 1024) || !memoryMembershipText(p.Name, 65536) || !memoryMembershipText(p.Slug, 65536) || p.CreatedAt.IsZero() {
		return releasedomain.Product{}, releasequery.ErrInvalidProjection
	}
	return releasedomain.Product{ID: p.ID, TenantID: p.TenantID, Name: p.Name, Slug: p.Slug, CreatedAt: p.CreatedAt.UTC()}, nil
}

func (r memoryReleaseCatalogRepository) ReadCatalogProduct(ctx context.Context, tenant, id string) (releasedomain.Product, error) {
	var out releasedomain.Product
	err := r.catalogQueryRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		p, err := catalogProductPoint(s, tenant, id)
		if err != nil {
			return err
		}
		out, err = catalogProductMetadata(p)
		return err
	})
	if err != nil {
		return releasedomain.Product{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadCatalogProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	var out releasedomain.Project
	err := r.catalogQueryRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.Projects[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return releasequery.ErrNotFound
		}
		if _, err := catalogProductPoint(s, tenant, v.ProductID); err != nil {
			return err
		}
		if !memoryMembershipQueryText(v.ID, 1024) || !memoryMembershipQueryText(v.ProductID, 1024) || !memoryMembershipText(v.Name, 65536) || v.CreatedAt.IsZero() {
			return releasequery.ErrInvalidProjection
		}
		out = releasedomain.Project{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Name: v.Name, CreatedAt: v.CreatedAt.UTC()}
		return nil
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadCatalogRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	var out releasedomain.Release
	err := r.catalogQueryRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.Releases[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return releasequery.ErrNotFound
		}
		if _, err := catalogProductPoint(s, tenant, v.ProductID); err != nil {
			return err
		}
		if !memoryMembershipQueryText(v.ID, 1024) || !memoryMembershipQueryText(v.ProductID, 1024) || !memoryMembershipText(v.Version, 65536) || v.Revision < 1 || v.CreatedAt.IsZero() {
			return releasequery.ErrInvalidProjection
		}
		state, err := releasedomain.ParseReleaseState(v.State)
		if err != nil {
			return releasequery.ErrInvalidProjection
		}
		out = releasedomain.Release{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Version: v.Version, State: state, Revision: v.Revision, CreatedAt: v.CreatedAt.UTC()}
		if v.FrozenAt != nil {
			at := v.FrozenAt.UTC()
			out.FrozenAt = &at
		}
		if v.ApprovedAt != nil {
			at := v.ApprovedAt.UTC()
			out.ApprovedAt = &at
		}
		return nil
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return out, nil
}

func (r memoryReleaseCatalogRepository) PageProducts(ctx context.Context, req releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error) {
	if req.TenantWide == (len(req.AllowedProductIDs) != 0) {
		return appquery.Result[releasedomain.Product]{}, releasequery.ErrValidation
	}
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	allowed := make(map[string]struct{}, len(req.AllowedProductIDs))
	for _, id := range req.AllowedProductIDs {
		if !memoryMembershipQueryText(id, 1024) {
			return appquery.Result[releasedomain.Product]{}, releasequery.ErrValidation
		}
		allowed[id] = struct{}{}
	}
	type point struct {
		id string
		at time.Time
	}
	var out appquery.Result[releasedomain.Product]
	err := r.catalogQueryRead(ctx, req.TenantID, "", func(s *MemoryUnitOfWorkSnapshot) error {
		points := make([]point, 0)
		for key, p := range s.Products {
			if p.TenantID != req.TenantID {
				continue
			}
			if !req.TenantWide {
				if _, ok := allowed[key]; !ok {
					continue
				}
			}
			if p.ID != key || !memoryMembershipQueryText(p.ID, 1024) || p.CreatedAt.IsZero() {
				return releasequery.ErrInvalidProjection
			}
			points = append(points, point{p.ID, p.CreatedAt.UTC()})
		}
		page, err := appquery.Page(points, req.Page, req.After, func(p point, sort appquery.Sort) appquery.SortKey { return appquery.RecordSortKey(p.id, p.at, sort) })
		if err != nil {
			return err
		}
		out = appquery.Result[releasedomain.Product]{Items: make([]releasedomain.Product, 0, len(page.Items)), Next: page.Next}
		for _, p := range page.Items {
			v, err := catalogProductMetadata(s.Products[p.id])
			if err != nil {
				return err
			}
			out.Items = append(out.Items, v)
		}
		return nil
	})
	if err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	return out, nil
}
