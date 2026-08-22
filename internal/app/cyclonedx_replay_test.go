package app

import "testing"

func TestParseCycloneDXReplayProjectionUsesSharedConformantParser(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"metadata":{"timestamp":"2026-08-09T00:00:00Z"},
		"components":[{
			"type":"library",
			"name":"api",
			"version":"1.0.0",
			"purl":"pkg:generic/api@1.0.0",
			"properties":[{"name":"source","value":"worker-replay"}]
		}],
		"services":[{"bom-ref":"service:api","name":"API"}]
	}`)

	got, err := ParseCycloneDXReplayProjection(raw, EvidenceDocumentLimit)
	if err != nil {
		t.Fatal(err)
	}
	if got.SpecVersion != "1.6" || len(got.Components) != 1 {
		t.Fatalf("projection=%#v", got)
	}
	component := got.Components[0]
	if component.Name != "api" || component.Version != "1.0.0" || component.PURL != "pkg:generic/api@1.0.0" {
		t.Fatalf("component=%#v", component)
	}
}

func TestParseCycloneDXReplayProjectionRejectsLegacyReducedComponent(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"missing-type"}]}`)
	if _, err := ParseCycloneDXReplayProjection(raw, EvidenceDocumentLimit); err != ErrValidation {
		t.Fatalf("err=%v, want validation", err)
	}
}
