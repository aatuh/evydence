package app

import (
	"context"

	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ProductCoordinates carries only the parent identity needed by project and
// release creation for ownership, grants, and immutable slug drift detection.
type ProductCoordinates struct {
	ID       string
	TenantID string
	Slug     string
}

type ProductCoordinateReader interface {
	ReadProductCoordinates(context.Context, string, string) (ProductCoordinates, error)
}

// Only the legacy/local service bridge reads full catalog models. Production
// composition supplies the explicit bounded coordinate port directly.
type legacyProductCoordinates struct {
	source interface {
		GetProduct(context.Context, string, string) (releasedomain.Product, error)
	}
}

func (r legacyProductCoordinates) ReadProductCoordinates(ctx context.Context, tenantID, id string) (ProductCoordinates, error) {
	v, err := r.source.GetProduct(ctx, tenantID, id)
	return ProductCoordinates{ID: v.ID, TenantID: v.TenantID, Slug: v.Slug}, err
}
