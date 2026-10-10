package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func artifactFixtureModel(value domain.Artifact) releasedomain.Artifact {
	return releasedomain.Artifact{ID: value.ID, TenantID: value.TenantID, Name: value.Name, MediaType: value.MediaType, Digest: value.Digest, Size: value.Size, CreatedAt: value.CreatedAt}
}
