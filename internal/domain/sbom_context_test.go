package domain

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestSBOMContextMapperPreservesWireFieldsAndCopiesComponents(t *testing.T) {
	in := evidencedomain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, CreatedAt: time.Date(2026, 10, 3, 12, 0, 0, 123456000, time.UTC), Components: []evidencedomain.SBOMComponent{{Identity: "purl:pkg:generic/api@1", Name: "api", Version: "1", PURL: "pkg:generic/api@1"}}}
	v := SBOMFromContext(in)
	want := []byte(`{"id":"sbom","tenant_id":"tenant","evidence_id":"evidence","release_id":"release","artifact_id":"artifact","format":"cyclonedx","spec_version":"1.6","component_count":1,"components":[{"identity":"purl:pkg:generic/api@1","name":"api","version":"1","purl":"pkg:generic/api@1"}],"created_at":"2026-10-03T12:00:00.123456Z"}`)
	got, err := json.Marshal(v)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("public SBOM fields changed", string(got), string(want), err)
	}
	v.Components[0].Name = "changed"
	if in.Components[0].Name != "api" {
		t.Fatal("DTO shares parser component data")
	}
	for _, components := range [][]evidencedomain.SBOMComponent{nil, {}} {
		v := SBOMFromContext(evidencedomain.SBOM{Components: components})
		if (v.Components == nil) != (components == nil) || len(v.Components) != 0 {
			t.Fatal("nil/empty compatibility changed", v.Components)
		}
	}
}
