package query

import (
	"context"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ControlEvidenceFilter struct {
	ControlID string
	ProductID string
	ReleaseID string
}

// ControlEvidencePoint carries subject-derived current coordinates from a
// tenant-verified SQL snapshot; a link's stored scope is not itself authority.
type ControlEvidencePoint struct {
	Link       riskdomain.ControlEvidence
	ProductID  string
	ProjectID  string
	ReleaseID  string
	ObservedAt time.Time
}

type ControlEvidencePageRequest struct {
	TenantID          string
	Filter            ControlEvidenceFilter
	TenantWide        bool
	AllowedProductIDs []string
	AllowedProjectIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type ControlEvidenceReader interface {
	PageControlEvidence(context.Context, ControlEvidencePageRequest) (appquery.Result[ControlEvidencePoint], error)
}

type ControlEvidence struct{ reader ControlEvidenceReader }

func NewControlEvidence(reader ControlEvidenceReader) (*ControlEvidence, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &ControlEvidence{reader: reader}, nil
}

func (s *ControlEvidence) ListPage(ctx context.Context, actor identitydomain.Actor, filter ControlEvidenceFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.ControlEvidence], error) {
	var empty appquery.Result[riskdomain.ControlEvidence]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope(scopeControlsRead) && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	filter.ControlID = strings.TrimSpace(filter.ControlID)
	filter.ProductID = strings.TrimSpace(filter.ProductID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	tenantWide, products, projects, releases := controlEvidenceVisibility(actor)
	if !tenantWide && len(products) == 0 && len(projects) == 0 && len(releases) == 0 {
		return appquery.Result[riskdomain.ControlEvidence]{Items: []riskdomain.ControlEvidence{}}, nil
	}
	request := ControlEvidencePageRequest{TenantID: actor.TenantID, Filter: filter, TenantWide: tenantWide,
		AllowedProductIDs: products, AllowedProjectIDs: projects, AllowedReleaseIDs: releases, Page: page, After: after}
	result, err := s.reader.PageControlEvidence(ctx, request)
	if err != nil {
		return empty, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].Link.ID, result.Items[len(result.Items)-1].Link.CreatedAt, page.Sort)) {
		return empty, ErrInvalidProjection
	}
	links := make([]riskdomain.ControlEvidence, 0, len(result.Items))
	for _, point := range result.Items {
		link := point.Link
		if link.ID == "" || link.TenantID != actor.TenantID || link.ControlID == "" || link.SubjectType == "" || link.SubjectID == "" ||
			link.EvidenceType == "" || link.Confidence == "" || link.SchemaVersion == "" || link.CreatedAt.IsZero() ||
			filter.ControlID != "" && link.ControlID != filter.ControlID ||
			filter.ProductID != "" && link.ProductID != filter.ProductID ||
			filter.ReleaseID != "" && link.ReleaseID != filter.ReleaseID ||
			link.ProductID != "" && link.ProductID != point.ProductID ||
			link.ReleaseID != "" && link.ReleaseID != point.ReleaseID ||
			!tenantWide && !controlEvidenceContains(products, point.ProductID) && !controlEvidenceContains(projects, point.ProjectID) && !controlEvidenceContains(releases, point.ReleaseID) {
			return empty, ErrInvalidProjection
		}
		links = append(links, link)
	}
	return appquery.Result[riskdomain.ControlEvidence]{Items: links, Next: result.Next}, nil
}

func controlEvidenceVisibility(actor identitydomain.Actor) (bool, []string, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil, nil
	}
	products, projects, releases := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		allowed := false
		for _, scope := range grant.Scopes {
			if scope == scopeControlsRead || scope == "admin" || scope == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil, nil
			}
		case "product":
			if grant.ResourceID != "" {
				products[grant.ResourceID] = struct{}{}
			}
		case "project":
			if grant.ResourceID != "" {
				projects[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releases[grant.ResourceID] = struct{}{}
			}
		}
	}
	return false, sortedControlEvidenceIDs(products), sortedControlEvidenceIDs(projects), sortedControlEvidenceIDs(releases)
}

func sortedControlEvidenceIDs(values map[string]struct{}) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func controlEvidenceContains(ids []string, id string) bool {
	if id == "" {
		return false
	}
	index := sort.SearchStrings(ids, id)
	return index < len(ids) && ids[index] == id
}
