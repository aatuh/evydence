package domain

import evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"

func SBOMDiffFromContext(v evidencedomain.SBOMDiff) SBOMDiff {
	components := func(values []evidencedomain.SBOMComponent) []SBOMComponent {
		result := make([]SBOMComponent, 0, len(values))
		for _, c := range values {
			result = append(result, SBOMComponent{Identity: c.Identity, Name: c.Name, Version: c.Version, PURL: c.PURL})
		}
		return result
	}
	changes := make([]DependencyChange, 0, len(v.DependencyChanges))
	for _, c := range v.DependencyChanges {
		changes = append(changes, DependencyChange{ID: c.ID, TenantID: c.TenantID, SBOMDiffID: c.SBOMDiffID, ChangeType: c.ChangeType, Component: SBOMComponent{Identity: c.Component.Identity, Name: c.Component.Name, Version: c.Component.Version, PURL: c.Component.PURL}, SchemaVersion: c.SchemaVersion, CreatedAt: c.CreatedAt})
	}
	return SBOMDiff{ID: v.ID, TenantID: v.TenantID, BaseSBOMID: v.BaseSBOMID, TargetSBOMID: v.TargetSBOMID, ReleaseID: v.ReleaseID, AddedComponents: components(v.AddedComponents), RemovedComponents: components(v.RemovedComponents), UnchangedCount: v.UnchangedCount, DependencyChanges: changes, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
