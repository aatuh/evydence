package app

import (
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestWorkerEvidenceRecordRejectsInvalidSelectedProjections(t *testing.T) {
	item := domain.EvidenceItem{ID: "evidence", TenantID: "tenant", ReleaseID: "release", Type: "sbom", SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}}
	value := domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "component"}}, CreatedAt: time.Now()}
	if err := ValidateWorkerEvidenceRecord(item, value); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*domain.SBOM){
		func(v *domain.SBOM) { v.ID = " malformed " },
		func(v *domain.SBOM) { v.TenantID = "foreign" }, func(v *domain.SBOM) { v.EvidenceID = "other" }, func(v *domain.SBOM) { v.ReleaseID = "other" },
		func(v *domain.SBOM) { v.ArtifactID = "other" }, func(v *domain.SBOM) { v.ComponentCount = 2 }, func(v *domain.SBOM) { v.Format = "" },
	} {
		bad := value
		mutate(&bad)
		if err := ValidateWorkerEvidenceRecord(item, bad); err == nil {
			t.Fatal("invalid projection accepted", bad)
		}
	}
}
