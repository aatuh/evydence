// Package query owns bounded, authorized governance reads.
package query

import (
	"context"
	"errors"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const scopeControlsRead = "controls:read"

var (
	ErrValidation        = errors.New("invalid controls query")
	ErrNotFound          = errors.New("control not found")
	ErrInvalidProjection = errors.New("invalid controls projection")
)

type FrameworkPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// ControlsReader scopes both lookups by tenant. GetControl must resolve its
// parent framework under the same tenant in one database statement.
type ControlsReader interface {
	PageFrameworks(context.Context, FrameworkPageRequest) (appquery.Result[riskdomain.ControlFramework], error)
	GetControl(context.Context, string, string) (riskdomain.SecurityControl, error)
}

type Controls struct{ reader ControlsReader }

func NewControls(reader ControlsReader) (*Controls, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &Controls{reader: reader}, nil
}

func (s *Controls) ListFrameworksPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.ControlFramework], error) {
	if s == nil || ctx == nil {
		return appquery.Result[riskdomain.ControlFramework]{}, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, scopeControlsRead); err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, ErrValidation
	}
	result, err := s.reader.PageFrameworks(ctx, FrameworkPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort)) {
		return appquery.Result[riskdomain.ControlFramework]{}, ErrInvalidProjection
	}
	for _, framework := range result.Items {
		if framework.ID == "" || framework.TenantID != actor.TenantID || framework.Name == "" || framework.Slug == "" || framework.Version == "" || framework.Status == "" || framework.CreatedAt.IsZero() {
			return appquery.Result[riskdomain.ControlFramework]{}, ErrInvalidProjection
		}
	}
	return result, nil
}

func (s *Controls) GetSecurityControl(ctx context.Context, actor identitydomain.Actor, id string) (riskdomain.SecurityControl, error) {
	if s == nil || ctx == nil {
		return riskdomain.SecurityControl{}, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, scopeControlsRead); err != nil {
		return riskdomain.SecurityControl{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return riskdomain.SecurityControl{}, ErrNotFound
	}
	control, err := s.reader.GetControl(ctx, actor.TenantID, id)
	if err != nil {
		return riskdomain.SecurityControl{}, err
	}
	if control.ID != id || control.TenantID != actor.TenantID || control.FrameworkID == "" {
		return riskdomain.SecurityControl{}, ErrNotFound
	}
	if control.Code == "" || control.Title == "" || control.CreatedAt.IsZero() {
		return riskdomain.SecurityControl{}, ErrInvalidProjection
	}
	return control, nil
}
