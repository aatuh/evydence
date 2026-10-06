package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxEvidencePageBytes = 16 << 20

type EvidencePageFilter struct {
	ProductID, ProjectID, ReleaseID, BuildID, DeploymentID       string
	Type, Subtype, SourceSystem, CollectorID, VerificationStatus string
	SubjectType, SubjectID, Tag                                  string
	CreatedAfter, CreatedBefore                                  time.Time
}

type EvidencePageRequest struct {
	TenantID                                                string
	Filter                                                  EvidencePageFilter
	Page                                                    appquery.PageRequest
	After                                                   *appquery.SortKey
	TenantWide                                              bool
	AllowedProductIDs, AllowedProjectIDs, AllowedReleaseIDs []string
}

// PageEvidence applies SQL-side candidate visibility before LIMIT and then
// validates selected ownership/provenance in one stable snapshot. The guard
// runs before loading each candidate's metadata. It must not consult a cache.
type EvidencePageReader interface {
	PageEvidence(context.Context, EvidencePageRequest, EvidenceReadGuard) (appquery.Result[EvidencePoint], error)
}

type EvidencePages struct{ reader EvidencePageReader }

func NewEvidencePages(reader EvidencePageReader) (*EvidencePages, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &EvidencePages{reader}, nil
}

func (s *EvidencePages) ListPage(ctx context.Context, a identitydomain.Actor, filter EvidencePageFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceItem], error) {
	var empty appquery.Result[evidencedomain.EvidenceItem]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := authorizeEvidenceRead(a, EvidencePoint{}, true); err != nil {
		return empty, err
	}
	if !validEvidenceReadID(a.TenantID) || strings.TrimSpace(a.TenantID) != a.TenantID || !validEvidencePageFilter(filter) {
		return empty, ErrValidation
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	if after != nil && !validEvidencePageKey(*after, page.Sort) {
		return empty, ErrValidation
	}
	tenantWide, products, projects, releases := sbomComponentVisibility(a)
	if !tenantWide && len(products)+len(projects)+len(releases) == 0 {
		return appquery.Result[evidencedomain.EvidenceItem]{Items: []evidencedomain.EvidenceItem{}}, nil
	}
	for _, ids := range [][]string{products, projects, releases} {
		for _, id := range ids {
			if !validEvidenceReadID(id) {
				return empty, ErrValidation
			}
		}
	}
	result, err := s.reader.PageEvidence(ctx, EvidencePageRequest{TenantID: a.TenantID, Filter: filter, Page: page, After: after, TenantWide: tenantWide, AllowedProductIDs: products, AllowedProjectIDs: projects, AllowedReleaseIDs: releases}, evidenceReadGuard(ctx, a))
	if err != nil {
		if errors.Is(err, appquery.ErrInvalidPage) || errors.Is(err, appquery.ErrInvalidCursor) {
			return empty, ErrValidation
		}
		return empty, err
	}
	if len(result.Items) > page.PageSize {
		return empty, ErrConflict
	}
	items := make([]evidencedomain.EvidenceItem, 0, len(result.Items))
	previous := after
	encodedBytes := 0
	for _, point := range result.Items {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		item := point.Item
		if !validEvidencePoint(point, a.TenantID, item.ID) || !matchesEvidencePageFilter(item, filter) {
			return empty, ErrConflict
		}
		if err := authorizeEvidenceRead(a, point, false); err != nil {
			return empty, ErrConflict
		}
		key := appquery.RecordSortKey(item.ID, item.CreatedAt, page.Sort)
		if !validEvidencePageKey(key, page.Sort) || previous != nil && !evidencePageKeyAfter(key, *previous, page) {
			return empty, ErrConflict
		}
		raw, err := json.Marshal(item)
		if err != nil || len(raw) > MaxEvidencePageBytes-encodedBytes {
			return empty, ErrConflict
		}
		encodedBytes += len(raw)
		previous = &key
		items = append(items, item)
	}
	if result.Next != nil && (previous == nil || len(items) == 0 || *result.Next != *previous) {
		return empty, ErrConflict
	}
	return appquery.Result[evidencedomain.EvidenceItem]{Items: items, Next: result.Next}, nil
}

func validEvidencePageFilter(f EvidencePageFilter) bool {
	for _, v := range []string{f.ProductID, f.ProjectID, f.ReleaseID, f.BuildID, f.DeploymentID, f.Type, f.Subtype, f.SourceSystem, f.CollectorID, f.VerificationStatus, f.SubjectType, f.SubjectID, f.Tag} {
		if len(v) > 1024 || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return false
		}
	}
	for _, v := range []time.Time{f.CreatedAfter, f.CreatedBefore} {
		if !v.IsZero() && (v.UTC().Year() < 1 || v.UTC().Year() > 9999) {
			return false
		}
	}
	return true
}
func validEvidencePageKey(k appquery.SortKey, sort appquery.Sort) bool {
	if !validEvidenceReadID(k.ID) {
		return false
	}
	if sort == appquery.SortID {
		return k.Value == k.ID
	}
	v, err := time.Parse(time.RFC3339Nano, k.Value)
	return err == nil && v.UTC().Year() >= 1 && v.UTC().Year() <= 9999 && v.UTC().Format(time.RFC3339Nano) == k.Value
}
func evidencePageKeyAfter(next, previous appquery.SortKey, page appquery.PageRequest) bool {
	comparison := strings.Compare(next.ID, previous.ID)
	if page.Sort == appquery.SortCreatedAt {
		a, ea := time.Parse(time.RFC3339Nano, next.Value)
		b, eb := time.Parse(time.RFC3339Nano, previous.Value)
		if ea != nil || eb != nil {
			return false
		}
		if !a.Equal(b) {
			comparison = a.Compare(b)
		}
	}
	return page.Direction == appquery.Ascending && comparison > 0 || page.Direction == appquery.Descending && comparison < 0
}
func matchesEvidencePageFilter(item evidencedomain.EvidenceItem, f EvidencePageFilter) bool {
	for _, pair := range [][2]string{{f.ProductID, item.ProductID}, {f.ProjectID, item.ProjectID}, {f.ReleaseID, item.ReleaseID}, {f.BuildID, item.BuildID}, {f.DeploymentID, item.DeploymentID}, {f.Type, item.Type}, {f.Subtype, item.Subtype}, {f.SourceSystem, item.SourceSystem}, {f.CollectorID, item.CollectorID}, {f.VerificationStatus, item.VerificationStatus}} {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	if !f.CreatedAfter.IsZero() && item.CreatedAt.Before(f.CreatedAfter) || !f.CreatedBefore.IsZero() && item.CreatedAt.After(f.CreatedBefore) {
		return false
	}
	if f.Tag != "" {
		found := false
		for _, tag := range item.Tags {
			found = found || tag == f.Tag
		}
		if !found {
			return false
		}
	}
	if f.SubjectType != "" || f.SubjectID != "" {
		for _, ref := range item.SubjectRefs {
			if (f.SubjectType == "" || ref.Type == f.SubjectType) && (f.SubjectID == "" || ref.ID == f.SubjectID || ref.Digest == f.SubjectID) {
				return true
			}
		}
		return false
	}
	return true
}
