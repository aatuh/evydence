// Package query owns bounded package and report reads.
package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const scopePackageRead = "package:read"

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
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, application.ErrUnauthorized
	}
	if !actor.HasScope(scopePackageRead) && !actor.HasScope("admin") {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, application.ErrForbidden
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrValidation
	}
	filter.QuestionID = strings.TrimSpace(filter.QuestionID)
	filter.ProductID = strings.TrimSpace(filter.ProductID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	tenantWide, products, releases := answerLibraryVisibility(actor)
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
			filter.ReleaseID != "" && entry.ReleaseID != "" && entry.ReleaseID != filter.ReleaseID ||
			!tenantWide && !contains(products, point.EffectiveProductID) && !contains(releases, entry.ReleaseID) {
			return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, ErrInvalidProjection
		}
		entry.EvidenceIDs = append([]string(nil), entry.EvidenceIDs...)
		entry.Limitations = append([]string(nil), entry.Limitations...)
		items = append(items, entry)
	}
	return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{Items: items, Next: result.Next}, nil
}

func answerLibraryVisibility(actor identitydomain.Actor) (bool, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil
	}
	productSet := map[string]struct{}{}
	releaseSet := map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		if !answerLibraryGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil
			}
		case "product":
			if grant.ResourceID != "" {
				productSet[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releaseSet[grant.ResourceID] = struct{}{}
			}
		}
	}
	products := make([]string, 0, len(productSet))
	for id := range productSet {
		products = append(products, id)
	}
	sort.Strings(products)
	releases := make([]string, 0, len(releaseSet))
	for id := range releaseSet {
		releases = append(releases, id)
	}
	sort.Strings(releases)
	return false, products, releases
}

func answerLibraryGrantHasScope(grant identitydomain.ResourceGrant) bool {
	for _, scope := range grant.Scopes {
		if scope == scopePackageRead || scope == "admin" || scope == "*" {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
