package query

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const (
	scopeProjectRead = "project:read"
	scopeReleaseRead = "release:read"
)

// CatalogPointReader must scope every lookup by tenant and join its product
// under that same tenant. The service validates the returned coordinates too.
type CatalogPointReader interface {
	GetProject(context.Context, string, string) (releasedomain.Project, error)
	GetRelease(context.Context, string, string) (releasedomain.Release, error)
}

// CatalogPoints owns authorized project and release point reads without
// reconstructing a tenant-wide state snapshot.
type CatalogPoints struct {
	reader     CatalogPointReader
	authorizer application.Authorizer
}

func NewCatalogPoints(reader CatalogPointReader, authorizer application.Authorizer) (*CatalogPoints, error) {
	if reader == nil || authorizer == nil {
		return nil, ErrValidation
	}
	return &CatalogPoints{reader: reader, authorizer: authorizer}, nil
}

func (s *CatalogPoints) GetProject(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Project, error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return releasedomain.Project{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasedomain.Project{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeProjectRead, ScopeOnly: true}); err != nil {
		return releasedomain.Project{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Project{}, ErrNotFound
	}
	project, err := s.reader.GetProject(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Project{}, err
	}
	if project.ID != id || project.TenantID != actor.TenantID || strings.TrimSpace(project.ProductID) == "" {
		return releasedomain.Project{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: scopeProjectRead,
		Resources: application.ResourceReferences{
			ProductID: project.ProductID,
			ProjectID: project.ID,
		},
	}); err != nil {
		return releasedomain.Project{}, err
	}
	return project, nil
}

func (s *CatalogPoints) GetRelease(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Release, error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return releasedomain.Release{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasedomain.Release{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, ScopeOnly: true}); err != nil {
		return releasedomain.Release{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if release.ID != id || release.TenantID != actor.TenantID || strings.TrimSpace(release.ProductID) == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: scopeReleaseRead,
		Resources: application.ResourceReferences{
			ProductID: release.ProductID,
			ReleaseID: release.ID,
		},
	}); err != nil {
		return releasedomain.Release{}, err
	}
	return release, nil
}
