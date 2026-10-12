package postgres

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.ArtifactPointReader = (*Store)(nil)

// GetArtifactPoint reads one tenant-owned artifact and its current grant
// visibility in the same statement. Association rows never leave PostgreSQL.
func (s *Store) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	if s == nil || s.pool == nil {
		return releasequery.ArtifactPoint{}, releasequery.ErrValidation
	}
	return repositories.ReadArtifactPoint(ctx, s.pool, request)
}
