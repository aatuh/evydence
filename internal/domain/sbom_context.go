package domain

import evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"

func SBOMFromContext(v evidencedomain.SBOM) SBOM {
	var components []SBOMComponent
	if v.Components != nil {
		components = make([]SBOMComponent, 0, len(v.Components))
	}
	for _, c := range v.Components {
		components = append(components, SBOMComponent{Identity: c.Identity, Name: c.Name, Version: c.Version, PURL: c.PURL})
	}
	return SBOM{ID: v.ID, TenantID: v.TenantID, EvidenceID: v.EvidenceID, ReleaseID: v.ReleaseID, ArtifactID: v.ArtifactID, Format: v.Format, SpecVersion: v.SpecVersion, ComponentCount: v.ComponentCount, Components: components, CreatedAt: v.CreatedAt}
}
