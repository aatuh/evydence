package query

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SBOMComponentFilter struct {
	SBOMID, ReleaseID, ArtifactID, Query, PURL string
}

// The reader applies tenant ownership and current grants before LIMIT. A point
// carries the association that justified a scoped human read for rechecking.
type SBOMComponentPageRequest struct {
	TenantID          string
	Filter            SBOMComponentFilter
	TenantWide        bool
	AllowedProductIDs []string
	AllowedProjectIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type SBOMComponentPoint struct {
	Record    evidencedomain.SBOMComponentRecord
	TenantID  string
	ProductID string
	ProjectID string
	ReleaseID string
}

type SBOMComponentReader interface {
	PageSBOMComponents(context.Context, SBOMComponentPageRequest) (appquery.Result[SBOMComponentPoint], error)
}

type SBOMComponents struct{ reader SBOMComponentReader }

func NewSBOMComponents(reader SBOMComponentReader) (*SBOMComponents, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &SBOMComponents{reader: reader}, nil
}

func (s *SBOMComponents) ListPage(ctx context.Context, actor identitydomain.Actor, filter SBOMComponentFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.SBOMComponentRecord], error) {
	var empty appquery.Result[evidencedomain.SBOMComponentRecord]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil || page.Sort != appquery.SortID || after != nil && after.Value != after.ID {
		return empty, ErrValidation
	}
	filter.SBOMID = strings.TrimSpace(filter.SBOMID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	filter.ArtifactID = strings.TrimSpace(filter.ArtifactID)
	filter.Query = strings.ToLower(strings.TrimSpace(filter.Query))
	filter.PURL = strings.TrimSpace(filter.PURL)
	tenantWide, products, projects, releases := sbomComponentVisibility(actor)
	if !tenantWide && len(products) == 0 && len(projects) == 0 && len(releases) == 0 {
		return empty, application.ErrForbidden
	}
	result, err := s.reader.PageSBOMComponents(ctx, SBOMComponentPageRequest{
		TenantID: actor.TenantID, Filter: filter, TenantWide: tenantWide,
		AllowedProductIDs: products, AllowedProjectIDs: projects, AllowedReleaseIDs: releases,
		Page: page, After: after,
	})
	if err != nil {
		if errors.Is(err, appquery.ErrInvalidCursor) || errors.Is(err, appquery.ErrInvalidPage) {
			return empty, ErrValidation
		}
		return empty, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || result.Next.Value != result.Items[len(result.Items)-1].Record.ID || result.Next.ID != result.Items[len(result.Items)-1].Record.ID) {
		return empty, ErrConflict
	}
	items := make([]evidencedomain.SBOMComponentRecord, 0, len(result.Items))
	for _, point := range result.Items {
		if !validSBOMComponentPoint(point, actor.TenantID, filter) {
			return empty, ErrConflict
		}
		if err := authorizeEvidenceRead(actor, EvidencePoint{ProductID: point.ProductID, ProjectID: point.ProjectID, ReleaseID: point.ReleaseID}, false); err != nil {
			return empty, ErrConflict
		}
		items = append(items, point.Record)
	}
	return appquery.Result[evidencedomain.SBOMComponentRecord]{Items: items, Next: result.Next}, nil
}

func validSBOMComponentPoint(point SBOMComponentPoint, tenantID string, filter SBOMComponentFilter) bool {
	record := point.Record
	index := strings.LastIndexByte(record.ID, ':')
	if point.TenantID != tenantID || record.SBOMID == "" || index < 0 || record.ID[:index] != record.SBOMID || record.Format == "" || record.SpecVersion == "" || strings.TrimSpace(record.Component.Name) == "" ||
		filter.SBOMID != "" && record.SBOMID != filter.SBOMID || filter.ReleaseID != "" && record.ReleaseID != filter.ReleaseID ||
		filter.ArtifactID != "" && record.ArtifactID != filter.ArtifactID || record.ReleaseID != "" && point.ReleaseID != "" && record.ReleaseID != point.ReleaseID ||
		filter.PURL != "" && record.Component.PURL != filter.PURL {
		return false
	}
	number, err := strconv.Atoi(record.ID[index+1:])
	if err != nil || number < 0 || strconv.Itoa(number) != record.ID[index+1:] {
		return false
	}
	if filter.Query != "" && !strings.Contains(strings.ToLower(record.Component.Name+"\n"+record.Component.Version+"\n"+record.Component.PURL), filter.Query) {
		return false
	}
	return true
}

func sbomComponentVisibility(actor identitydomain.Actor) (bool, []string, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil, nil
	}
	products, projects, releases := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		if !evidenceGrantHasScope(grant) {
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
	return false, sortedSBOMGrantIDs(products), sortedSBOMGrantIDs(projects), sortedSBOMGrantIDs(releases)
}

func sortedSBOMGrantIDs(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
