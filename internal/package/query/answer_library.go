// Package query owns bounded package and report reads.
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
	ErrValidation        = errors.New("invalid answer library query")
	ErrNotFound          = errors.New("answer library scope not found")
	ErrInvalidProjection = errors.New("invalid answer library projection")
)

type AnswerLibraryFilter struct {
	QuestionID string
	ProductID  string
	ReleaseID  string
}

type AnswerLibraryPageRequest struct {
	TenantID          string
	Filter            AnswerLibraryFilter
	TenantWide        bool
	AllowedProductIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

// AnswerLibraryPoint includes the product resolved from the current release
// parent, so the service can reject a widened or inconsistent SQL projection.
type AnswerLibraryPoint struct {
	Entry              packagedomain.QuestionnaireAnswerLibraryEntry
	EffectiveProductID string
}

type AnswerLibraryReader interface {
	PageAnswerLibrary(context.Context, AnswerLibraryPageRequest) (appquery.Result[AnswerLibraryPoint], error)
}

type AnswerLibrary struct{ reader AnswerLibraryReader }

func NewAnswerLibrary(reader AnswerLibraryReader) (*AnswerLibrary, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &AnswerLibrary{reader: reader}, nil
}

func (s *AnswerLibrary) ListPage(ctx context.Context, actor identitydomain.Actor, filter AnswerLibraryFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry], error) {
	if s == nil || ctx == nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionAnswerLibraryEntriesRead)
	if err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrValidation
	}
	filter.QuestionID = strings.TrimSpace(filter.QuestionID)
	filter.ProductID = strings.TrimSpace(filter.ProductID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	tenantWide, products, releases := visibility.TenantWide, visibility.ProductIDs, visibility.ReleaseIDs
	if !tenantWide && len(products) == 0 && len(releases) == 0 {
		if filter.ProductID != "" || filter.ReleaseID != "" {
			return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, application.ErrForbidden
		}
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{Items: []packagedomain.QuestionnaireAnswerLibraryEntry{}}, nil
	}
	request := AnswerLibraryPageRequest{TenantID: actor.TenantID, Filter: filter, TenantWide: tenantWide, AllowedProductIDs: products, AllowedReleaseIDs: releases, Page: page, After: after}
	result, err := s.reader.PageAnswerLibrary(ctx, request)
	if err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].Entry.ID, result.Items[len(result.Items)-1].Entry.CreatedAt, page.Sort)) {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrInvalidProjection
	}
	items := make([]packagedomain.QuestionnaireAnswerLibraryEntry, 0, len(result.Items))
	for _, point := range result.Items {
		entry := point.Entry
		if entry.ID == "" || entry.TenantID != actor.TenantID || entry.Answer == "" || entry.SchemaVersion == "" || entry.CreatedAt.IsZero() ||
			entry.ProductID != "" && entry.ProductID != point.EffectiveProductID || entry.ReleaseID != "" && point.EffectiveProductID == "" ||
			entry.ProductID == "" && entry.ReleaseID == "" && point.EffectiveProductID != "" ||
			filter.QuestionID != "" && entry.QuestionID != filter.QuestionID ||
			filter.ProductID != "" && entry.ProductID != "" && entry.ProductID != filter.ProductID ||
			filter.ReleaseID != "" && entry.ReleaseID != "" && entry.ReleaseID != filter.ReleaseID {
			return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrInvalidProjection
		}
		row := authz.Request{Action: authz.ActionAnswerLibraryEntriesRead, Resources: authz.ResourceReferences{ProductID: point.EffectiveProductID, ReleaseID: entry.ReleaseID}}
		if row.Resources == (authz.ResourceReferences{}) {
			row.Evaluation = authz.TenantEvaluation
		}
		if err := authz.Authorize(ctx, actor, row); err != nil {
			if errors.Is(err, authz.ErrForbidden) {
				return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrInvalidProjection
			}
			return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
		}
		entry.EvidenceIDs = append([]string(nil), entry.EvidenceIDs...)
		entry.Limitations = append([]string(nil), entry.Limitations...)
		items = append(items, entry)
	}
	return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{Items: items, Next: result.Next}, nil
}
