package domain

import (
	"testing"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestBackupManifestContextConversionPreservesSchemaAndCopiesMutableFields(t *testing.T) {
	input := verificationdomain.BackupManifest{ID: "backup", TenantID: "tenant", StateHash: "hash", ResourceCounts: map[string]int{"evidence": 1}, ConsistencyChecks: []verificationdomain.VerifyCheck{{Name: "audit_chain", Result: "failed"}}, Limitations: []string{"not a restore receipt"}, SchemaVersion: verificationdomain.BackupManifestTenantSchemaVersion}
	output := BackupManifestFromContextModel(input)
	if output.ID != input.ID || output.TenantID != input.TenantID || output.StateHash != input.StateHash || output.SchemaVersion != input.SchemaVersion || output.ConsistencyChecks[0].Result != "failed" {
		t.Fatal(output)
	}
	input.ResourceCounts["evidence"] = 99
	input.ConsistencyChecks[0].Result = "passed"
	input.Limitations[0] = "changed"
	if output.ResourceCounts["evidence"] != 1 || output.ConsistencyChecks[0].Result != "failed" || output.Limitations[0] != "not a restore receipt" {
		t.Fatal("mutable conversion aliases", output)
	}
}
