// Package query owns bounded, authorized release-catalog reads.
package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const ScopeProductRead = "product:read"

var (
	ErrValidation        = errors.New("invalid product query")
	ErrInvalidProjection = errors.New("invalid product projection")
)

// ProductPageRequest is constructed by the service, not from client-provided
// tenant or grant coordinates. A false TenantWide flag requires a nonempty
// AllowedProductIDs set, which the adapter must apply before LIMIT.
type ProductPageRequest struct {
	TenantID          string
	TenantWide        bool
	AllowedProductIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type ProductPageReader interface {
	PageProducts(context.Context, ProductPageRequest) (appquery.Result[releasedomain.Product], error)
}

type Products struct {
	reader     ProductPageReader
	authorizer application.Authorizer
}

func NewProducts(reader ProductPageReader, authorizer application.Authorizer) (*Products, error) {
	if reader == nil || authorizer == nil {
		return nil, ErrValidation
	}
	return &Products{reader: reader, authorizer: authorizer}, nil
}

func (s *Products) ListProductsPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.Product], error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return appquery.Result[releasedomain.Product]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[releasedomain.Product]{}, ErrValidation
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeProductRead, ScopeOnly: true}); err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	request := ProductPageRequest{TenantID: actor.TenantID, Page: page, After: after}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeProductRead, TenantWide: true}); err == nil {
		request.TenantWide = true
	} else if !errors.Is(err, application.ErrForbidden) {
		return appquery.Result[releasedomain.Product]{}, err
	} else {
		seen := make(map[string]struct{}, len(actor.ResourceGrants))
		for _, grant := range actor.ResourceGrants {
			id := strings.TrimSpace(grant.ResourceID)
			if grant.ResourceType != "product" || id == "" {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeProductRead, Resources: application.ResourceReferences{ProductID: id}}); err != nil {
				if errors.Is(err, application.ErrForbidden) {
					continue
				}
				return appquery.Result[releasedomain.Product]{}, err
			}
			seen[id] = struct{}{}
			request.AllowedProductIDs = append(request.AllowedProductIDs, id)
		}
		if len(request.AllowedProductIDs) == 0 {
			return appquery.Result[releasedomain.Product]{Items: []releasedomain.Product{}}, nil
		}
		sort.Strings(request.AllowedProductIDs)
	}
	result, err := s.reader.PageProducts(ctx, request)
	if err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	if len(result.Items) > page.PageSize {
		return appquery.Result[releasedomain.Product]{}, ErrInvalidProjection
	}
	allowed := make(map[string]struct{}, len(request.AllowedProductIDs))
	for _, id := range request.AllowedProductIDs {
		allowed[id] = struct{}{}
	}
	for _, product := range result.Items {
		if product.TenantID != actor.TenantID || product.ID == "" {
			return appquery.Result[releasedomain.Product]{}, ErrInvalidProjection
		}
		if !request.TenantWide {
			if _, ok := allowed[product.ID]; !ok {
				return appquery.Result[releasedomain.Product]{}, ErrInvalidProjection
			}
		}
		if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeProductRead, Resources: application.ResourceReferences{ProductID: product.ID}}); err != nil {
			return appquery.Result[releasedomain.Product]{}, err
		}
	}
	if result.Next != nil {
		if len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort) {
			return appquery.Result[releasedomain.Product]{}, ErrInvalidProjection
		}
	}
	return result, nil
}
