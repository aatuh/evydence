// Package query owns bounded, authorized integration read services.
package query

import (
	"context"
	"errors"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

var (
	ErrValidation        = errors.New("invalid source repository query")
	ErrInvalidProjection = errors.New("invalid source repository projection")
)

// SourceRepositoryPoint contains the current tenant-verified product parent
// when a repository has a project. Detached legacy repositories have neither
// project nor product and are visible only to tenant-wide actors: scoped
// credentials or human sessions with a current tenant grant.
type SourceRepositoryPoint struct {
	Repository integrationdomain.SourceRepository
	ProductID  string
}

type SourceRepositoryPageRequest struct {
	TenantID          string
	ProjectID         string
	TenantWide        bool
	AllowedProductIDs []string
	AllowedProjectIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type SourceRepositoryReader interface {
	PageSourceRepositories(context.Context, SourceRepositoryPageRequest) (appquery.Result[SourceRepositoryPoint], error)
}

type SourceRepositories struct{ reader SourceRepositoryReader }

func NewSourceRepositories(reader SourceRepositoryReader) (*SourceRepositories, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &SourceRepositories{reader: reader}, nil
}

func (s *SourceRepositories) ListPage(ctx context.Context, actor identitydomain.Actor, projectID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.SourceRepository], error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return appquery.Result[integrationdomain.SourceRepository]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, ErrValidation
	}
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionSourceRepositoriesRead)
	if err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, err
	}
	tenantWide, products, projects := visibility.TenantWide, visibility.ProductIDs, visibility.ProjectIDs
	if !tenantWide && len(products) == 0 && len(projects) == 0 {
		return appquery.Result[integrationdomain.SourceRepository]{Items: []integrationdomain.SourceRepository{}}, nil
	}
	request := SourceRepositoryPageRequest{TenantID: actor.TenantID, ProjectID: projectID, TenantWide: tenantWide, AllowedProductIDs: products, AllowedProjectIDs: projects, Page: page, After: after}
	result, err := s.reader.PageSourceRepositories(ctx, request)
	if err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, err
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].Repository.ID, result.Items[len(result.Items)-1].Repository.CreatedAt, page.Sort)) {
		return appquery.Result[integrationdomain.SourceRepository]{}, ErrInvalidProjection
	}
	items := make([]integrationdomain.SourceRepository, 0, len(result.Items))
	for _, point := range result.Items {
		repository := point.Repository
		if repository.ID == "" || repository.TenantID != actor.TenantID ||
			projectID != "" && repository.ProjectID != projectID ||
			repository.ProjectID == "" && point.ProductID != "" ||
			repository.ProjectID != "" && point.ProductID == "" ||
			!tenantWide && !sourceAllowed(products, point.ProductID) && !sourceAllowed(projects, repository.ProjectID) {
			return appquery.Result[integrationdomain.SourceRepository]{}, ErrInvalidProjection
		}
		if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionSourceRepositoriesRead, Resources: authz.ResourceReferences{ProductID: point.ProductID, ProjectID: repository.ProjectID}}); err != nil {
			return appquery.Result[integrationdomain.SourceRepository]{}, ErrInvalidProjection
		}
		items = append(items, repository)
	}
	return appquery.Result[integrationdomain.SourceRepository]{Items: items, Next: result.Next}, nil
}

func sourceAllowed(ids []string, id string) bool {
	if id == "" {
		return false
	}
	for _, allowed := range ids {
		if allowed == id {
			return true
		}
	}
	return false
}
