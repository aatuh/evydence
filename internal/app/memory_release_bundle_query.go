package app

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.ReleaseBundleReader = memoryPackageRepository{}

// Select one current bundle/release/product from the transaction's typed rows.
// This detached memory test model does not establish SQL transfer bounds,
// cryptographic verification, locking or durability.
func (r memoryPackageRepository) GetReleaseBundlePoint(ctx context.Context, tenant, id string) (packagequery.ReleaseBundlePoint, error) {
	if ctx == nil || r.uow == nil || strings.TrimSpace(tenant) == "" {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.ReleaseBundlePoint{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrReleaseBundleNotFound
	}
	var out packagequery.ReleaseBundlePoint
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		b, ok := s.ReleaseBundles[id]
		if !ok || b.ID != id || b.TenantID != tenant {
			return packagequery.ErrReleaseBundleNotFound
		}
		release, ok := s.Releases[b.ReleaseID]
		if !ok || release.ID != b.ReleaseID || release.TenantID != tenant {
			return packagequery.ErrReleaseBundleNotFound
		}
		product, ok := s.Products[release.ProductID]
		if !ok || product.ID != release.ProductID || product.TenantID != tenant {
			return packagequery.ErrReleaseBundleNotFound
		}
		state, err := packagedomain.ParseBundleState(b.State)
		if err != nil || b.Manifest == nil || b.SignatureRefs == nil {
			return packagequery.ErrReleaseBundleProjection
		}
		b, err = cloneMemoryReleaseBundle(b)
		if err != nil {
			return packagequery.ErrReleaseBundleProjection
		}
		out = packagequery.ReleaseBundlePoint{ProductID: product.ID, Bundle: packagedomain.ReleaseBundle{
			ID: b.ID, TenantID: b.TenantID, ReleaseID: b.ReleaseID, State: state,
			Manifest: b.Manifest, ManifestHash: b.ManifestHash, SignatureRefs: b.SignatureRefs,
			CreatedAt: b.CreatedAt, PublishedAt: cloneTimePtr(b.PublishedAt), RevokedAt: cloneTimePtr(b.RevokedAt),
		}}
		return ctx.Err()
	})
	if err != nil {
		return packagequery.ReleaseBundlePoint{}, err
	}
	return out, nil
}

// Signed manifest metadata is schema-free JSON. Never round recorded numbers
// through float64 during insertion, commit, snapshot or point reads.
func cloneMemoryReleaseBundle(b domain.ReleaseBundle) (domain.ReleaseBundle, error) {
	raw, err := json.Marshal(b.Manifest)
	if err != nil {
		return domain.ReleaseBundle{}, err
	}
	var manifest map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil {
		return domain.ReleaseBundle{}, err
	}
	b.Manifest = manifest
	b.SignatureRefs = slices.Clone(b.SignatureRefs)
	b.PublishedAt, b.RevokedAt = cloneTimePtr(b.PublishedAt), cloneTimePtr(b.RevokedAt)
	return b, nil
}
