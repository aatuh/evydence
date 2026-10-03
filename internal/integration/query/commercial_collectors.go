package query

import (
	"context"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type CommercialCollectorPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// CommercialCollectorReader must filter tenant and limit rows in SQL.
type CommercialCollectorReader interface {
	PageCommercialCollectors(context.Context, CommercialCollectorPageRequest) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error)
}

type CommercialCollectors struct{ reader CommercialCollectorReader }

func NewCommercialCollectors(reader CommercialCollectorReader) (*CommercialCollectors, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &CommercialCollectors{reader: reader}, nil
}

func (s *CommercialCollectors) ListPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	var empty appquery.Result[integrationdomain.CommercialCollectorDefinition]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, scopeCollectorRead); err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	result, err := s.reader.PageCommercialCollectors(ctx, CommercialCollectorPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return empty, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort)) {
		return empty, ErrInvalidProjection
	}
	items := make([]integrationdomain.CommercialCollectorDefinition, 0, len(result.Items))
	for _, definition := range result.Items {
		if definition.ID == "" || definition.TenantID != actor.TenantID || definition.Name == "" ||
			definition.Provider == "" || definition.Version == "" || definition.ManifestHash == "" ||
			definition.Status == "" || definition.SchemaVersion == "" || definition.CreatedAt.IsZero() {
			return empty, ErrInvalidProjection
		}
		definition.AllowedScopes = append([]string(nil), definition.AllowedScopes...)
		items = append(items, definition)
	}
	return appquery.Result[integrationdomain.CommercialCollectorDefinition]{Items: items, Next: result.Next}, nil
}
