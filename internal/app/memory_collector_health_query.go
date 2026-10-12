package app

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.CollectorHealthReader = memoryBuildRepository{}

// Select one collector and at most latest/pinned public releases. This typed
// model mirrors snapshot selection, not SQL transfer/work or durability.
func (r memoryBuildRepository) GetCollectorHealthPoint(ctx context.Context, tenant, id string) (integrationquery.CollectorHealthPoint, error) {
	var out integrationquery.CollectorHealthPoint
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		c, ok := s.Collectors[id]
		if !ok || c.ID != id || c.TenantID != tenant {
			return integrationquery.ErrNotFound
		}
		// Allowed scopes are credential metadata absent from the native SELECT.
		c.AllowedScopes = nil
		model, err := domain.CollectorToContextModel(c)
		if err != nil {
			return integrationquery.ErrInvalidProjection
		}
		var latest, pinned *domain.CollectorRelease
		newer := func(a domain.CollectorRelease, b *domain.CollectorRelease) bool {
			return b == nil || a.CreatedAt.After(b.CreatedAt) || a.CreatedAt.Equal(b.CreatedAt) && a.ID > b.ID
		}
		for _, v := range s.CollectorReleases {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || v.CollectorID != id {
				continue
			}
			if newer(v, latest) {
				copy := v
				latest = &copy
			}
			if v.Pinned && newer(v, pinned) {
				copy := v
				pinned = &copy
			}
		}
		project := func(v *domain.CollectorRelease) *integrationdomain.CollectorRelease {
			if v == nil {
				return nil
			}
			m := integrationdomain.CollectorRelease(*v)
			m.Limitations = slices.Clone(v.Limitations)
			return &m
		}
		out = integrationquery.CollectorHealthPoint{Collector: model, LatestRelease: project(latest), PinnedRelease: project(pinned)}
		return nil
	})
	if err != nil {
		return integrationquery.CollectorHealthPoint{}, err
	}
	return out, nil
}
