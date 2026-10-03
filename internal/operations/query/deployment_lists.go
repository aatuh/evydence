package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

var ErrInvalidProjection = errors.New("invalid deployment list projection")

// Visibility is derived from current credential scopes and human grants by
// the service; callers cannot supply tenant or allowed resource IDs.
type EnvironmentPageRequest struct {
	TenantID          string
	ProductID         string
	TenantWide        bool
	AllowedProductIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type DeploymentPageRequest struct {
	TenantID          string
	ReleaseID         string
	EnvironmentID     string
	TenantWide        bool
	AllowedProductIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type DeploymentListReader interface {
	PageDeploymentEnvironments(context.Context, EnvironmentPageRequest) (appquery.Result[operationsdomain.DeploymentEnvironment], error)
	PageDeployments(context.Context, DeploymentPageRequest) (appquery.Result[DeploymentPoint], error)
}

type DeploymentLists struct{ reader DeploymentListReader }

func NewDeploymentLists(reader DeploymentListReader) (*DeploymentLists, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &DeploymentLists{reader: reader}, nil
}

func (s *DeploymentLists) ListEnvironmentsPage(ctx context.Context, actor identitydomain.Actor, productID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, ErrValidation
	}
	if err := authorizeDeploymentRead(actor, "", ""); err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	tenantWide, products, _ := deploymentListVisibility(actor)
	if !tenantWide && len(products) == 0 {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{Items: []operationsdomain.DeploymentEnvironment{}}, nil
	}
	request := EnvironmentPageRequest{TenantID: actor.TenantID, ProductID: productID, TenantWide: tenantWide, AllowedProductIDs: products, Page: page, After: after}
	result, err := s.reader.PageDeploymentEnvironments(ctx, request)
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	if len(result.Items) > page.PageSize || !validNext(result.Next, result.Items, func(item operationsdomain.DeploymentEnvironment) appquery.SortKey {
		return appquery.RecordSortKey(item.ID, item.CreatedAt, page.Sort)
	}) {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, ErrInvalidProjection
	}
	for _, item := range result.Items {
		if item.ID == "" || item.TenantID != actor.TenantID || item.ProductID == "" || productID != "" && item.ProductID != productID || !tenantWide && !contains(products, item.ProductID) {
			return appquery.Result[operationsdomain.DeploymentEnvironment]{}, ErrInvalidProjection
		}
		if err := authorizeDeploymentRead(actor, item.ProductID, ""); err != nil {
			return appquery.Result[operationsdomain.DeploymentEnvironment]{}, ErrInvalidProjection
		}
	}
	return result, nil
}

func (s *DeploymentLists) ListDeploymentsPage(ctx context.Context, actor identitydomain.Actor, releaseID, environmentID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEvent], error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, ErrValidation
	}
	if err := authorizeDeploymentRead(actor, "", ""); err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, err
	}
	tenantWide, products, releases := deploymentListVisibility(actor)
	if !tenantWide && len(products) == 0 && len(releases) == 0 {
		return appquery.Result[operationsdomain.DeploymentEvent]{Items: []operationsdomain.DeploymentEvent{}}, nil
	}
	request := DeploymentPageRequest{TenantID: actor.TenantID, ReleaseID: releaseID, EnvironmentID: environmentID, TenantWide: tenantWide, AllowedProductIDs: products, AllowedReleaseIDs: releases, Page: page, After: after}
	result, err := s.reader.PageDeployments(ctx, request)
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, err
	}
	if len(result.Items) > page.PageSize || !validNext(result.Next, result.Items, func(point DeploymentPoint) appquery.SortKey {
		return appquery.RecordSortKey(point.Deployment.ID, point.Deployment.CreatedAt, page.Sort)
	}) {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, ErrInvalidProjection
	}
	items := make([]operationsdomain.DeploymentEvent, 0, len(result.Items))
	for _, point := range result.Items {
		item := point.Deployment
		if item.ID == "" || item.TenantID != actor.TenantID || point.ProductID == "" || item.ReleaseID == "" || item.EnvironmentID == "" ||
			releaseID != "" && item.ReleaseID != releaseID || environmentID != "" && item.EnvironmentID != environmentID ||
			!tenantWide && !contains(products, point.ProductID) && !contains(releases, item.ReleaseID) {
			return appquery.Result[operationsdomain.DeploymentEvent]{}, ErrInvalidProjection
		}
		if err := authorizeDeploymentRead(actor, point.ProductID, item.ReleaseID); err != nil {
			return appquery.Result[operationsdomain.DeploymentEvent]{}, ErrInvalidProjection
		}
		items = append(items, item)
	}
	return appquery.Result[operationsdomain.DeploymentEvent]{Items: items, Next: result.Next}, nil
}

func deploymentListVisibility(actor identitydomain.Actor) (bool, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil
	}
	productSet := make(map[string]struct{})
	releaseSet := make(map[string]struct{})
	for _, grant := range actor.ResourceGrants {
		if !deploymentGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil
			}
		case "product":
			if grant.ResourceID != "" {
				productSet[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releaseSet[grant.ResourceID] = struct{}{}
			}
		}
	}
	products := make([]string, 0, len(productSet))
	for id := range productSet {
		products = append(products, id)
	}
	sort.Strings(products)
	releases := make([]string, 0, len(releaseSet))
	for id := range releaseSet {
		releases = append(releases, id)
	}
	sort.Strings(releases)
	return false, products, releases
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func validNext[T any](next *appquery.SortKey, items []T, keyOf func(T) appquery.SortKey) bool {
	if next == nil {
		return true
	}
	if len(items) == 0 {
		return false
	}
	return *next == keyOf(items[len(items)-1])
}
