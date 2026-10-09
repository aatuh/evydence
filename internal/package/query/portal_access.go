package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var (
	ErrPortalAccessValidation = errors.New("invalid portal access query")
	ErrPortalAccessNotFound   = errors.New("portal access package not found")
	ErrPortalAccessProjection = errors.New("invalid portal access projection")
)

type PortalAccessPageRequest struct {
	TenantID          string
	PackageID         string
	TenantWide        bool
	AllowedPackageIDs []string
	AllowedProductIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

// PortalAccessPoint carries current package coordinates; token hashes must
// never be selected or projected by the reader.
type PortalAccessPoint struct {
	Access    packagedomain.CustomerPortalAccess
	ProductID string
	ReleaseID string
}

type PortalAccessReader interface {
	PagePortalAccess(context.Context, PortalAccessPageRequest) (appquery.Result[PortalAccessPoint], error)
}

type PortalAccess struct{ reader PortalAccessReader }

func NewPortalAccess(reader PortalAccessReader) (*PortalAccess, error) {
	if reader == nil {
		return nil, ErrPortalAccessValidation
	}
	return &PortalAccess{reader: reader}, nil
}

func (s *PortalAccess) ListPage(ctx context.Context, actor identitydomain.Actor, packageID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.CustomerPortalAccess], error) {
	var empty appquery.Result[packagedomain.CustomerPortalAccess]
	if s == nil || ctx == nil {
		return empty, ErrPortalAccessValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope(scopePackageRead) && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrPortalAccessValidation
	}
	packageID = strings.TrimSpace(packageID)
	tenantWide, packages, products, releases := portalAccessVisibility(actor)
	if !tenantWide && len(packages) == 0 && len(products) == 0 && len(releases) == 0 {
		if packageID != "" {
			return empty, application.ErrForbidden
		}
		return appquery.Result[packagedomain.CustomerPortalAccess]{Items: []packagedomain.CustomerPortalAccess{}}, nil
	}
	request := PortalAccessPageRequest{TenantID: actor.TenantID, PackageID: packageID, TenantWide: tenantWide,
		AllowedPackageIDs: packages, AllowedProductIDs: products, AllowedReleaseIDs: releases, Page: page, After: after}
	result, err := s.reader.PagePortalAccess(ctx, request)
	if err != nil {
		return empty, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].Access.ID, result.Items[len(result.Items)-1].Access.CreatedAt, page.Sort)) {
		return empty, ErrPortalAccessProjection
	}
	items := make([]packagedomain.CustomerPortalAccess, 0, len(result.Items))
	for _, point := range result.Items {
		access := point.Access
		if access.ID == "" || access.TenantID != actor.TenantID || access.PackageID == "" || point.ProductID == "" ||
			access.Hash != "" || access.CustomerName == "" || access.Prefix == "" || access.ExpiresAt.IsZero() ||
			access.SchemaVersion == "" || access.CreatedAt.IsZero() ||
			packageID != "" && access.PackageID != packageID ||
			!tenantWide && !contains(packages, access.PackageID) && !contains(products, point.ProductID) && !contains(releases, point.ReleaseID) {
			return empty, ErrPortalAccessProjection
		}
		items = append(items, access)
	}
	return appquery.Result[packagedomain.CustomerPortalAccess]{Items: items, Next: result.Next}, nil
}

func portalAccessVisibility(actor identitydomain.Actor) (bool, []string, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil, nil
	}
	packages, products, releases := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		if !answerLibraryGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil, nil
			}
		case "customer_security_package":
			if grant.ResourceID != "" {
				packages[grant.ResourceID] = struct{}{}
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
	return false, sortedPortalGrantIDs(packages), sortedPortalGrantIDs(products), sortedPortalGrantIDs(releases)
}

func sortedPortalGrantIDs(values map[string]struct{}) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
