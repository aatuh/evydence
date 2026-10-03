package query

import (
	"context"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

const scopeCollectorRead = "collector:read"

type CollectorPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// CollectorReader must filter by tenant and apply the keyset limit in SQL.
type CollectorReader interface {
	PageCollectors(context.Context, CollectorPageRequest) (appquery.Result[integrationdomain.Collector], error)
}

type Collectors struct{ reader CollectorReader }

func NewCollectors(reader CollectorReader) (*Collectors, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &Collectors{reader: reader}, nil
}

// ListPage exposes tenant inventory only to a tenant-granted human session or
// an issued credential carrying collector:read.
func (s *Collectors) ListPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.Collector], error) {
	if s == nil || ctx == nil {
		return appquery.Result[integrationdomain.Collector]{}, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, scopeCollectorRead); err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[integrationdomain.Collector]{}, ErrValidation
	}
	result, err := s.reader.PageCollectors(ctx, CollectorPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort)) {
		return appquery.Result[integrationdomain.Collector]{}, ErrInvalidProjection
	}
	items := make([]integrationdomain.Collector, 0, len(result.Items))
	for _, collector := range result.Items {
		if collector.ID == "" || collector.TenantID != actor.TenantID || collector.APIKeyID == "" || collector.Status.IsZero() || collector.CreatedAt.IsZero() {
			return appquery.Result[integrationdomain.Collector]{}, ErrInvalidProjection
		}
		collector.AllowedScopes = append([]string(nil), collector.AllowedScopes...)
		items = append(items, collector)
	}
	return appquery.Result[integrationdomain.Collector]{Items: items, Next: result.Next}, nil
}
