package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const scopeVerifyRead = "verify:read"

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
	if err := authorizeExceptionScope(actor); err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	request := ExceptionPageRequest{TenantID: actor.TenantID, ReleaseID: strings.TrimSpace(releaseID), Page: page, After: after}
	request.TenantWide, request.AllowedProductIDs, request.AllowedReleaseIDs = exceptionVisibility(actor)
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
		if err := authorizeExceptionRead(actor, result.FilterRelease.ProductID, result.FilterRelease.ID); err != nil {
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
		if err := authorizeExceptionRead(actor, point.ProductID, value.ReleaseID); err != nil {
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

func authorizeExceptionScope(actor identitydomain.Actor) error {
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if !actor.HasScope(scopeVerifyRead) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	return nil
}

func authorizeExceptionRead(actor identitydomain.Actor, productID, releaseID string) error {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if !exceptionGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return nil
			}
		case "product":
			if grant.ResourceID == productID {
				return nil
			}
		case "release":
			if grant.ResourceID == releaseID {
				return nil
			}
		}
	}
	return application.ErrForbidden
}

func exceptionVisibility(actor identitydomain.Actor) (bool, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil
	}
	products, releases := map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		if !exceptionGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil
			}
		case "product":
			if grant.ResourceID != "" {
				products[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releases[grant.ResourceID] = struct{}{}
			}
		}
	}
	allowedProducts := make([]string, 0, len(products))
	for id := range products {
		allowedProducts = append(allowedProducts, id)
	}
	allowedReleases := make([]string, 0, len(releases))
	for id := range releases {
		allowedReleases = append(allowedReleases, id)
	}
	sort.Strings(allowedProducts)
	sort.Strings(allowedReleases)
	return false, allowedProducts, allowedReleases
}

func exceptionGrantHasScope(grant identitydomain.ResourceGrant) bool {
	for _, scope := range grant.Scopes {
		if scope == scopeVerifyRead || scope == "admin" || scope == "*" {
			return true
		}
	}
	return false
}
