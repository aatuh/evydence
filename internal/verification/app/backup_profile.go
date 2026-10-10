package app

import (
	"sort"
	"strings"
)

// BackupCommitmentProfileResources returns fresh copies of the immutable v2
// commitment vocabulary. Adapters supply records; SQL and storage mechanics
// are not part of this application-owned profile.
func BackupCommitmentProfileResources() []BackupCommitmentResource {
	sources := BackupCommitmentProfileResourcesV1()
	sources = append(sources, BackupCommitmentResource{Name: "vulnerability_decision_supersessions", Columns: []string{"tenant_id", "finding_id", "predecessor_id", "successor_id", "created_at", "schema_version"}})
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	return sources
}

// BackupCommitmentProfileResourcesV1 preserves the historical resource and
// column order for reproduction. Returned slices do not alias the definition.
func BackupCommitmentProfileResourcesV1() []BackupCommitmentResource {
	var sources []BackupCommitmentResource
	for _, line := range strings.Split(strings.TrimSpace(backupCommitmentCatalog), "\n") {
		name, columns, _ := strings.Cut(line, "|")
		sources = append(sources, BackupCommitmentResource{Name: name, Columns: strings.Split(columns, ",")})
	}
	return sources
}
