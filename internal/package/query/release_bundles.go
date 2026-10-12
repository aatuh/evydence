package query

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/authz"
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
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionReleaseBundlesRead, Evaluation: authz.ScopeEvaluation}); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return packagedomain.ReleaseBundle{}, ErrReleaseBundleNotFound
	}
	point, err := s.reader.GetReleaseBundlePoint(ctx, actor.TenantID, id)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	if err := ctx.Err(); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	bundle := point.Bundle
	if bundle.ID != id || bundle.TenantID != actor.TenantID || bundle.ReleaseID == "" || point.ProductID == "" ||
		bundle.State.IsZero() || bundle.Manifest == nil || bundle.ManifestHash == "" || bundle.CreatedAt.IsZero() {
		return packagedomain.ReleaseBundle{}, ErrReleaseBundleProjection
	}
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionReleaseBundlesRead, Resources: authz.ResourceReferences{ProductID: point.ProductID, ReleaseID: bundle.ReleaseID}}); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	return bundle, nil
}
