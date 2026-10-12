package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func sbomComponentFromQuery(value evidencedomain.SBOMComponentRecord) domain.SBOMComponentRecord {
	return domain.SBOMComponentRecord{
		ID: value.ID, SBOMID: value.SBOMID, ReleaseID: value.ReleaseID,
		ArtifactID: value.ArtifactID, Format: value.Format, SpecVersion: value.SpecVersion,
		Component: domain.SBOMComponent{
			Identity: value.Component.Identity, Name: value.Component.Name,
			Version: value.Component.Version, PURL: value.Component.PURL,
		},
	}
}
