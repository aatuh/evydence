package query

import (
	"context"
	"errors"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ReleaseScope struct {
	ID        string
	ProductID string
}

type ExceptionPoint struct {
	Exception riskdomain.Exception
	ProductID string
}

// ExceptionPageRequest carries service-derived visibility for SQL filtering
// before the keyset limit. A filtered release is resolved in the same snapshot.
type ExceptionPageRequest struct {
	TenantID          string
	ReleaseID         string
	TenantWide        bool
	AllowedProductIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type ExceptionPage struct {
	FilterRelease ReleaseScope
	Page          appquery.Result[ExceptionPoint]
}

type ExceptionReader interface {
	PageExceptions(context.Context, ExceptionPageRequest) (ExceptionPage, error)
}

type Exceptions struct{ reader ExceptionReader }

func NewExceptions(reader ExceptionReader) (*Exceptions, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &Exceptions{reader: reader}, nil
}

func (s *Exceptions) ListPage(ctx context.Context, actor identitydomain.Actor, releaseID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.Exception], error) {
	var empty appquery.Result[riskdomain.Exception]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionExceptionsRead)
	if err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	request := ExceptionPageRequest{TenantID: visibility.TenantID, ReleaseID: strings.TrimSpace(releaseID), Page: page, After: after,
		TenantWide: visibility.TenantWide, AllowedProductIDs: visibility.ProductIDs, AllowedReleaseIDs: visibility.ReleaseIDs}
	result, err := s.reader.PageExceptions(ctx, request)
	if errors.Is(err, appquery.ErrInvalidCursor) || errors.Is(err, appquery.ErrInvalidPage) {
		return empty, ErrValidation
	}
	if err != nil {
		return empty, err
	}
	if request.ReleaseID != "" {
		if result.FilterRelease.ID != request.ReleaseID || result.FilterRelease.ProductID == "" {
			return empty, ErrInvalidProjection
		}
		if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionExceptionsRead, Resources: authz.ResourceReferences{ProductID: result.FilterRelease.ProductID, ReleaseID: result.FilterRelease.ID}}); err != nil {
			return empty, err
		}
	}
	if len(result.Page.Items) > page.PageSize {
		return empty, ErrInvalidProjection
	}
	items := make([]riskdomain.Exception, 0, len(result.Page.Items))
	for _, point := range result.Page.Items {
		value := point.Exception
		if value.ID == "" || value.TenantID != actor.TenantID || value.ReleaseID == "" || point.ProductID == "" ||
			request.ReleaseID != "" && value.ReleaseID != request.ReleaseID || value.CreatedAt.IsZero() || value.ExpiresAt.IsZero() {
			return empty, ErrInvalidProjection
		}
		if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionExceptionsRead, Resources: authz.ResourceReferences{TenantID: value.TenantID, ProductID: point.ProductID, ReleaseID: value.ReleaseID}}); err != nil {
			return empty, ErrInvalidProjection
		}
		items = append(items, value)
	}
	if result.Page.Next != nil {
		if len(items) == 0 || *result.Page.Next != appquery.RecordSortKey(items[len(items)-1].ID, items[len(items)-1].CreatedAt, page.Sort) {
			return empty, ErrInvalidProjection
		}
	}
	return appquery.Result[riskdomain.Exception]{Items: items, Next: result.Page.Next}, nil
}
