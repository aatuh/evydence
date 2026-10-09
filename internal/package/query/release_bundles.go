package query

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var (
	ErrReleaseBundleNotFound   = errors.New("release bundle not found")
	ErrReleaseBundleProjection = errors.New("invalid release bundle projection")
)

// ReleaseBundlePoint carries the product resolved from the current,
// tenant-owned release so the query service can enforce human grants.
type ReleaseBundlePoint struct {
	Bundle    packagedomain.ReleaseBundle
	ProductID string
}

type ReleaseBundleReader interface {
	GetReleaseBundlePoint(context.Context, string, string) (ReleaseBundlePoint, error)
}

type ReleaseBundles struct{ reader ReleaseBundleReader }

func NewReleaseBundles(reader ReleaseBundleReader) (*ReleaseBundles, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &ReleaseBundles{reader: reader}, nil
}

func (s *ReleaseBundles) GetReleaseBundle(ctx context.Context, actor identitydomain.Actor, id string) (packagedomain.ReleaseBundle, error) {
	if s == nil || ctx == nil {
		return packagedomain.ReleaseBundle{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return packagedomain.ReleaseBundle{}, application.ErrUnauthorized
	}
	if !actor.HasScope("bundle:read") && !actor.HasScope("admin") {
		return packagedomain.ReleaseBundle{}, application.ErrForbidden
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return packagedomain.ReleaseBundle{}, ErrReleaseBundleNotFound
	}
	point, err := s.reader.GetReleaseBundlePoint(ctx, actor.TenantID, id)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	bundle := point.Bundle
	if bundle.ID != id || bundle.TenantID != actor.TenantID || bundle.ReleaseID == "" || point.ProductID == "" ||
		bundle.State.IsZero() || bundle.Manifest == nil || bundle.ManifestHash == "" || bundle.CreatedAt.IsZero() {
		return packagedomain.ReleaseBundle{}, ErrReleaseBundleProjection
	}
	if !releaseBundleAllowed(actor, point.ProductID, bundle.ReleaseID) {
		return packagedomain.ReleaseBundle{}, application.ErrForbidden
	}
	return bundle, nil
}

func releaseBundleAllowed(actor identitydomain.Actor, productID, releaseID string) bool {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		if !releaseBundleGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true
			}
		case "product":
			if grant.ResourceID == productID {
				return true
			}
		case "release":
			if grant.ResourceID == releaseID {
				return true
			}
		}
	}
	return false
}

func releaseBundleGrantHasScope(grant identitydomain.ResourceGrant) bool {
	for _, scope := range grant.Scopes {
		if scope == "bundle:read" || scope == "admin" || scope == "*" {
			return true
		}
	}
	return false
}
