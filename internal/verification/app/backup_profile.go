package app

import (
	"sort"
	"strings"
)

// BackupCommitmentProfileResources returns fresh copies of the immutable v4
// commitment vocabulary. Adapters supply records; SQL and storage mechanics
// are not part of this application-owned profile.
func BackupCommitmentProfileResources() []BackupCommitmentResource {
	sources := BackupCommitmentProfileResourcesV3()
	sources = append(sources, BackupCommitmentResource{Name: "oidc_authentication_requests", Columns: []string{"id", "tenant_id", "provider_id", "delivery", "trust_fingerprint", "created_at", "expires_at", "consumed_at", "schema_version"}})
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	return sources
}

// BackupCommitmentProfileResourcesV3 preserves session-lifecycle commitments
// without adding later operational login-request metadata or secret hashes.
func BackupCommitmentProfileResourcesV3() []BackupCommitmentResource {
	sources := BackupCommitmentProfileResourcesV2()
	for i := range sources {
		if sources[i].Name == "sso_sessions" {
			sources[i].Columns = append(sources[i].Columns, "last_used_at", "maximum_lifetime_seconds", "idle_timeout_seconds")
		}
	}
	return sources
}

// BackupCommitmentProfileResourcesV2 keeps historical supersession-aware
// commitments reproducible without incorporating later session columns.
func BackupCommitmentProfileResourcesV2() []BackupCommitmentResource {
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
