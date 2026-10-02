package app

import (
	"context"
	"strings"
	"unicode/utf8"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var _ releaseapp.ReleaseStateReader = memoryReleaseCatalogRepository{}

func (r memoryReleaseCatalogRepository) ReadReleaseState(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	for _, v := range []string{tenant, id} {
		if v == "" || len(v) > 1024 || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return releasedomain.Release{}, ErrValidation
		}
	}
	v, err := r.GetReleaseForUpdate(ctx, tenant, id)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if len(v.ID) > 1024 || len(v.TenantID) > 1024 || len(v.ProductID) > 1024 || len(v.Version) > 65536 || len(v.State) > 32 {
		return releasedomain.Release{}, ErrConflict
	}
	state, err := releasedomain.ParseReleaseState(v.State)
	if err != nil || v.Revision < 1 || v.CreatedAt.IsZero() {
		return releasedomain.Release{}, ErrConflict
	}
	return releasedomain.Release{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Version: v.Version, State: state, Revision: v.Revision, CreatedAt: v.CreatedAt.UTC(), FrozenAt: v.FrozenAt, ApprovedAt: v.ApprovedAt}, nil
}
