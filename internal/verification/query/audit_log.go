// Package query contains bounded, authorized verification read services.
package query

import (
	"context"
	"errors"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var (
	ErrValidation        = errors.New("invalid audit log query")
	ErrInvalidProjection = errors.New("invalid audit log projection")
)

type AuditFilter struct {
	SubjectType string
	SubjectID   string
	Since       *time.Time
}

type AuditPageRequest struct {
	TenantID string
	Filter   AuditFilter
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// AuditLogReader must apply the tenant, filters, keyset position, and limit in
// one database query. It must never fetch a tenant-wide chain into memory.
type AuditLogReader interface {
	PageAuditLog(context.Context, AuditPageRequest) (appquery.Result[verificationdomain.AuditChainEntry], error)
}

type AuditLog struct{ reader AuditLogReader }

func NewAuditLog(reader AuditLogReader) (*AuditLog, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &AuditLog{reader: reader}, nil
}

func (s *AuditLog) ListPage(ctx context.Context, actor identitydomain.Actor, filter AuditFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	if s == nil || ctx == nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, application.ErrUnauthorized
	}
	if !actor.HasScope("admin") {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, application.ErrForbidden
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, ErrValidation
	}
	filter.SubjectType = strings.TrimSpace(filter.SubjectType)
	filter.SubjectID = strings.TrimSpace(filter.SubjectID)
	if filter.Since != nil {
		since := filter.Since.UTC()
		filter.Since = &since
	}
	result, err := s.reader.PageAuditLog(ctx, AuditPageRequest{TenantID: actor.TenantID, Filter: filter, Page: page, After: after})
	if err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	if len(result.Items) > page.PageSize {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, ErrInvalidProjection
	}
	for _, entry := range result.Items {
		if entry.ID == "" || entry.TenantID != actor.TenantID || filter.SubjectType != "" && entry.SubjectType != filter.SubjectType || filter.SubjectID != "" && entry.SubjectID != filter.SubjectID || filter.Since != nil && entry.OccurredAt.Before(*filter.Since) {
			return appquery.Result[verificationdomain.AuditChainEntry]{}, ErrInvalidProjection
		}
	}
	if result.Next != nil {
		if len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].OccurredAt, page.Sort) {
			return appquery.Result[verificationdomain.AuditChainEntry]{}, ErrInvalidProjection
		}
	}
	return result, nil
}
