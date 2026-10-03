package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ProductCommands exposes product creation only, without catalog queries or
// unrelated commands.
type ProductCommands interface {
	CreateProduct(context.Context, identitydomain.Actor, releaseapp.CreateProductInput) (releasedomain.Product, error)
}

func productFromCommand(p releasedomain.Product) domain.Product {
	return domain.Product{ID: p.ID, TenantID: p.TenantID, Name: p.Name, Slug: p.Slug, CreatedAt: p.CreatedAt}
}
