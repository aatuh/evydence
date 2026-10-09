package domain

import verificationdomain "github.com/aatuh/evydence/internal/verification/domain"

// BackupManifestFromContextModel preserves the existing JSON field layout.
func BackupManifestFromContextModel(value verificationdomain.BackupManifest) BackupManifest {
	counts := make(map[string]int, len(value.ResourceCounts))
	for name, count := range value.ResourceCounts {
		counts[name] = count
	}
	return BackupManifest{ID: value.ID, TenantID: value.TenantID, StateHash: value.StateHash, ResourceCounts: counts, ConsistencyChecks: verificationChecksFromContext(value.ConsistencyChecks), Limitations: append([]string(nil), value.Limitations...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
