package query

import (
	"context"
	"errors"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
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
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionPortalAccessRead)
	if err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrPortalAccessValidation
	}
	packageID = strings.TrimSpace(packageID)
	tenantWide, packages, products, releases := visibility.TenantWide, visibility.CustomerPackageIDs, visibility.ProductIDs, visibility.ReleaseIDs
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
	if err := ctx.Err(); err != nil {
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
			packageID != "" && access.PackageID != packageID {
			return empty, ErrPortalAccessProjection
		}
		if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionPortalAccessRead, Resources: authz.ResourceReferences{ProductID: point.ProductID, ReleaseID: point.ReleaseID, CustomerPackageID: access.PackageID}}); err != nil {
			if errors.Is(err, authz.ErrForbidden) {
				return empty, ErrPortalAccessProjection
			}
			return empty, err
		}
		items = append(items, access)
	}
	return appquery.Result[packagedomain.CustomerPortalAccess]{Items: items, Next: result.Next}, nil
}
