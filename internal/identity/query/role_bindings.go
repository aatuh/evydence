package query

import (
	"context"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type RoleBindingPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// RoleBindingReader must apply tenant ownership, keyset, and limit in storage.
type RoleBindingReader interface {
	PageRoleBindings(context.Context, RoleBindingPageRequest) (appquery.Result[identitydomain.RoleBinding], error)
}

type RoleBindings struct{ reader RoleBindingReader }

func NewRoleBindings(reader RoleBindingReader) (*RoleBindings, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &RoleBindings{reader: reader}, nil
}

func (s *RoleBindings) ListPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[identitydomain.RoleBinding], error) {
	if s == nil || ctx == nil {
		return appquery.Result[identitydomain.RoleBinding]{}, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, "identity:admin"); err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, ErrValidation
	}
	result, err := s.reader.PageRoleBindings(ctx, RoleBindingPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	if len(result.Items) > page.PageSize {
		return appquery.Result[identitydomain.RoleBinding]{}, ErrInvalidProjection
	}
	for _, binding := range result.Items {
		if binding.ID == "" || binding.TenantID != actor.TenantID || binding.SubjectType == "" || binding.SubjectID == "" || binding.Role == "" || binding.SchemaVersion == "" || binding.CreatedAt.IsZero() {
			return appquery.Result[identitydomain.RoleBinding]{}, ErrInvalidProjection
		}
	}
	if result.Next != nil {
		if len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort) {
			return appquery.Result[identitydomain.RoleBinding]{}, ErrInvalidProjection
		}
	}
	return result, nil
}
