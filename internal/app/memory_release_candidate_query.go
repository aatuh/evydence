package app

import (
	"context"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.ReleaseCandidateReader = memoryReleaseCatalogRepository{}

func memoryCandidateProduct(s *MemoryUnitOfWorkSnapshot, tenant string, v domain.ReleaseCandidate) (string, error) {
	if v.TenantID != tenant || !memoryMembershipQueryText(v.ReleaseID, 1024) {
		return "", releasequery.ErrNotFound
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: v.ReleaseID})
	if err != nil || refs.ProductID == "" {
		return "", releasequery.ErrNotFound
	}
	return refs.ProductID, nil
}

func memoryCandidateMetadata(v domain.ReleaseCandidate) (releasedomain.ReleaseCandidate, error) {
	if !memoryMembershipQueryText(v.ID, 1024) || v.CreatedAt.IsZero() || v.Revision < 1 || !memoryMembershipText(v.Name, 65536) || !memoryMembershipText(v.SnapshotHash, 65536) || !memoryMembershipText(v.SchemaVersion, 65536) ||
		!releaseapp.ValidCandidateReferences(releaseapp.ReleaseCandidateReferences{BuildIDs: v.BuildIDs, ArtifactIDs: v.ArtifactIDs, SBOMIDs: v.SBOMIDs, ScanIDs: v.ScanIDs, VEXIDs: v.VEXIDs, ContractIDs: v.ContractIDs, BundleIDs: v.BundleIDs}) {
		return releasedomain.ReleaseCandidate{}, releasequery.ErrInvalidProjection
	}
	value, err := releaseCandidateToReleaseContext(v)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, releasequery.ErrInvalidProjection
	}
	return value, nil
}

func (r memoryReleaseCatalogRepository) GetReleaseCandidatePoint(ctx context.Context, tenant, id string) (releasequery.ReleaseCandidatePoint, error) {
	var out releasequery.ReleaseCandidatePoint
	err := r.catalogQueryRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ReleaseCandidates[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return releasequery.ErrNotFound
		}
		product, err := memoryCandidateProduct(s, tenant, v)
		if err != nil {
			return err
		}
		value, err := memoryCandidateMetadata(v)
		if err != nil {
			return err
		}
		out = releasequery.ReleaseCandidatePoint{Candidate: value, ProductID: product}
		return nil
	})
	if err != nil {
		return releasequery.ReleaseCandidatePoint{}, err
	}
	return out, nil
}

// Memory filters current parent ownership and grants before keyset selection,
// then copies metadata only for returned rows. This scan is not a SQL budget.
func (r memoryReleaseCatalogRepository) PageReleaseCandidates(ctx context.Context, req releasequery.ReleaseCandidatePageRequest) (appquery.Result[releasequery.ReleaseCandidatePoint], error) {
	if req.TenantWide == (len(req.AllowedProductIDs)+len(req.AllowedReleaseIDs) != 0) || req.ReleaseID != "" && !memoryMembershipQueryText(req.ReleaseID, 1024) {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, releasequery.ErrValidation
	}
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, err
	}
	products, releases := make(map[string]bool), make(map[string]bool)
	for _, group := range []struct {
		ids     []string
		allowed map[string]bool
	}{{req.AllowedProductIDs, products}, {req.AllowedReleaseIDs, releases}} {
		for _, id := range group.ids {
			if !memoryMembershipQueryText(id, 1024) {
				return appquery.Result[releasequery.ReleaseCandidatePoint]{}, releasequery.ErrValidation
			}
			group.allowed[id] = true
		}
	}
	type point struct {
		id, product string
		at          time.Time
	}
	var out appquery.Result[releasequery.ReleaseCandidatePoint]
	err := r.catalogQueryRead(ctx, req.TenantID, "", func(s *MemoryUnitOfWorkSnapshot) error {
		points := make([]point, 0)
		for key, v := range s.ReleaseCandidates {
			if v.TenantID != req.TenantID || req.ReleaseID != "" && v.ReleaseID != req.ReleaseID {
				continue
			}
			product, err := memoryCandidateProduct(s, req.TenantID, v)
			if err != nil || !req.TenantWide && !products[product] && !releases[v.ReleaseID] {
				continue
			}
			if v.ID != key || !memoryMembershipQueryText(v.ID, 1024) || v.CreatedAt.IsZero() {
				return releasequery.ErrInvalidProjection
			}
			points = append(points, point{v.ID, product, v.CreatedAt.UTC()})
		}
		page, err := appquery.Page(points, req.Page, req.After, func(v point, sort appquery.Sort) appquery.SortKey { return appquery.RecordSortKey(v.id, v.at, sort) })
		if err != nil {
			return err
		}
		out = appquery.Result[releasequery.ReleaseCandidatePoint]{Items: make([]releasequery.ReleaseCandidatePoint, 0, len(page.Items)), Next: page.Next}
		for _, p := range page.Items {
			v, err := memoryCandidateMetadata(s.ReleaseCandidates[p.id])
			if err != nil {
				return err
			}
			out.Items = append(out.Items, releasequery.ReleaseCandidatePoint{Candidate: v, ProductID: p.product})
		}
		return nil
	})
	if err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, err
	}
	return out, nil
}
