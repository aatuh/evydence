package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func sbomFromQuery(value evidencedomain.SBOM) domain.SBOM {
	sbom := domain.SBOM{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format,
		SpecVersion: value.SpecVersion, ComponentCount: value.ComponentCount,
		Components: make([]domain.SBOMComponent, 0, len(value.Components)), CreatedAt: value.CreatedAt,
	}
	for _, component := range value.Components {
		sbom.Components = append(sbom.Components, domain.SBOMComponent{
			Identity: component.Identity, Name: component.Name,
			Version: component.Version, PURL: component.PURL,
		})
	}
	return sbom
}
