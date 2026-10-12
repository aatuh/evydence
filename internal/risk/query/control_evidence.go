package query

import (
	"context"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/authz"
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
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionControlEvidenceRead)
	if err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	filter.ControlID = strings.TrimSpace(filter.ControlID)
	filter.ProductID = strings.TrimSpace(filter.ProductID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	tenantWide, products, projects, releases := visibility.TenantWide, visibility.ProductIDs, visibility.ProjectIDs, visibility.ReleaseIDs
	if !tenantWide && len(products) == 0 && len(projects) == 0 && len(releases) == 0 {
		return appquery.Result[riskdomain.ControlEvidence]{Items: []riskdomain.ControlEvidence{}}, nil
	}
	request := ControlEvidencePageRequest{TenantID: visibility.TenantID, Filter: filter, TenantWide: tenantWide,
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
			link.ReleaseID != "" && link.ReleaseID != point.ReleaseID {
			return empty, ErrInvalidProjection
		}
		if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionControlEvidenceRead, Resources: authz.ResourceReferences{TenantID: link.TenantID, ProductID: point.ProductID, ProjectID: point.ProjectID, ReleaseID: point.ReleaseID}}); err != nil {
			return empty, ErrInvalidProjection
		}
		links = append(links, link)
	}
	return appquery.Result[riskdomain.ControlEvidence]{Items: links, Next: result.Next}, nil
}
