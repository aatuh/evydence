package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemorySecurityScanAcceptsEmptyFindingsWithoutRelaxingRequiredMetadata(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	value := domain.SecurityScan{ID: "empty-scan", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Category: "api_security", Format: "generic", Scanner: "fixture", TargetRef: "openapi", EvidenceID: "tenant-evidence", PayloadHash: "sha256:" + strings.Repeat("a", 64), FindingCount: 0, SchemaVersion: domain.SecurityScanSchemaVersion, CreatedAt: fixedNow()}
	if err := tx.Repositories().Risk.InsertSecurityScan(t.Context(), value); err != nil {
		t.Fatal("valid zero-finding projection rejected", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*domain.SecurityScan)
	}{
		{"missing nonempty summary", func(v *domain.SecurityScan) { v.FindingCount = 1 }},
		{"missing scanner", func(v *domain.SecurityScan) { v.Scanner = "" }},
		{"missing format", func(v *domain.SecurityScan) { v.Format = "" }},
		{"negative findings", func(v *domain.SecurityScan) { v.FindingCount = -1 }},
	} {
		candidate := value
		candidate.ID = tc.name
		tc.mutate(&candidate)
		if err := tx.Repositories().Risk.InsertSecurityScan(t.Context(), candidate); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid security projection accepted", tc.name, err)
		}
	}
}
