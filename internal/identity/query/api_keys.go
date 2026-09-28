// Package query owns bounded identity and access read services.
package query

import (
	"context"
	"errors"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var (
	ErrValidation        = errors.New("invalid identity query")
	ErrInvalidProjection = errors.New("invalid identity projection")
)

type APIKeyPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// APIKeyReader must enforce the tenant and limit in SQL and omit stored hashes.
type APIKeyReader interface {
	PageAPIKeys(context.Context, APIKeyPageRequest) (appquery.Result[identitydomain.APIKey], error)
}

type APIKeys struct{ reader APIKeyReader }

func NewAPIKeys(reader APIKeyReader) (*APIKeys, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &APIKeys{reader: reader}, nil
}

func (s *APIKeys) ListPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[identitydomain.APIKey], error) {
	if s == nil || ctx == nil {
		return appquery.Result[identitydomain.APIKey]{}, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, "admin"); err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[identitydomain.APIKey]{}, ErrValidation
	}
	result, err := s.reader.PageAPIKeys(ctx, APIKeyPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	if len(result.Items) > page.PageSize {
		return appquery.Result[identitydomain.APIKey]{}, ErrInvalidProjection
	}
	for index, key := range result.Items {
		if key.ID == "" || key.TenantID != actor.TenantID || key.CreatedAt.IsZero() || key.Prefix == "" {
			return appquery.Result[identitydomain.APIKey]{}, ErrInvalidProjection
		}
		key.Hash = ""
		key.Scopes = append([]string(nil), key.Scopes...)
		result.Items[index] = key
	}
	if result.Next != nil {
		if len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort) {
			return appquery.Result[identitydomain.APIKey]{}, ErrInvalidProjection
		}
	}
	return result, nil
}
