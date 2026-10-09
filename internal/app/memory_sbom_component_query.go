package app

import (
	"context"
	"sort"
	"strconv"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.SBOMComponentReader = memoryEvidenceRepository{}

// This test-backend page uses current typed rows and native query policy,
// not aggregate caches. Bounded selection is not proof of SQL work or locks.
func (r memoryEvidenceRepository) PageSBOMComponents(ctx context.Context, request evidencequery.SBOMComponentPageRequest) (appquery.Result[evidencequery.SBOMComponentPoint], error) {
	var empty appquery.Result[evidencequery.SBOMComponentPoint]
	if ctx == nil || r.uow == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide == (len(request.AllowedProductIDs)+len(request.AllowedProjectIDs)+len(request.AllowedReleaseIDs) != 0) {
		return empty, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := appquery.Validate(request.Page, request.After); err != nil || request.Page.Sort != appquery.SortID || request.After != nil && request.After.Value != request.After.ID {
		return empty, evidencequery.ErrValidation
	}
	filter := request.Filter
	filter.SBOMID = strings.TrimSpace(filter.SBOMID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	filter.ArtifactID = strings.TrimSpace(filter.ArtifactID)
	filter.Query = strings.ToLower(strings.TrimSpace(filter.Query))
	filter.PURL = strings.TrimSpace(filter.PURL)
	points := make([]evidencequery.SBOMComponentPoint, 0, request.Page.PageSize+1)
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		rootVisible := filter.SBOMID == ""
		for id := range s.SBOMs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if filter.SBOMID != "" && id != filter.SBOMID {
				continue
			}
			b, product, err := memoryOwnedSBOM(s, request.TenantID, id)
			if err != nil {
				continue
			}
			association, visible, err := memorySBOMComponentVisibility(ctx, s, b, product, request)
			if err != nil {
				return err
			}
			if !visible {
				continue
			}
			rootVisible = true
			if filter.ReleaseID != "" && filter.ReleaseID != b.ReleaseID || filter.ArtifactID != "" && filter.ArtifactID != b.ArtifactID {
				continue
			}
			for i, component := range b.Components {
				if err := ctx.Err(); err != nil {
					return err
				}
				if filter.PURL != "" && filter.PURL != component.PURL || filter.Query != "" && !strings.Contains(strings.ToLower(component.Name+"\n"+component.Version+"\n"+component.PURL), filter.Query) {
					continue
				}
				key := b.ID + ":" + strconv.Itoa(i)
				if request.After != nil && (request.Page.Direction == appquery.Ascending && key <= request.After.ID || request.Page.Direction == appquery.Descending && key >= request.After.ID) {
					continue
				}
				point := evidencequery.SBOMComponentPoint{TenantID: b.TenantID, ProductID: association.ProductID, ProjectID: association.ProjectID, ReleaseID: association.ReleaseID,
					Record: evidencedomain.SBOMComponentRecord{ID: key, SBOMID: b.ID, ReleaseID: b.ReleaseID, ArtifactID: b.ArtifactID, Format: b.Format, SpecVersion: b.SpecVersion, Component: evidencedomain.SBOMComponent(component)}}
				// Retain only the best PageSize+1 keys, independent of map order.
				position := sort.Search(len(points), func(i int) bool {
					if request.Page.Direction == appquery.Descending {
						return points[i].Record.ID < key
					}
					return points[i].Record.ID > key
				})
				if position >= request.Page.PageSize+1 {
					continue
				}
				if len(points) < request.Page.PageSize+1 {
					points = append(points, evidencequery.SBOMComponentPoint{})
				}
				copy(points[position+1:], points[position:])
				points[position] = point
			}
		}
		if !rootVisible {
			return evidencequery.ErrNotFound
		}
		return ctx.Err()
	})
	if err != nil {
		return empty, err
	}
	result := appquery.Result[evidencequery.SBOMComponentPoint]{Items: points}
	if len(points) > request.Page.PageSize {
		result.Items = points[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Record.ID
		result.Next = &appquery.SortKey{ID: last, Value: last}
	}
	return result, nil
}
