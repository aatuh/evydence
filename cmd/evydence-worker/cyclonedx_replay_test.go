package main

import "testing"

func TestParseReplayedSBOMUsesSharedCycloneDXProjection(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"metadata":{"timestamp":"2026-08-10T06:30:00Z"},
		"components":[
			{"bom-ref":"z","type":"library","name":"z","properties":[{"name":"source","value":"worker"}]},
			{"bom-ref":"a","type":"library","name":"a","version":"1.0.0"}
		],
		"services":[{"name":"gateway"}],
		"properties":[{"name":"root","value":"preserved"}]
	}`)
	got, err := parseReplayedSBOM(raw)
	if err != nil {
		t.Fatalf("conformant replay rejected: %v", err)
	}
	if got.SpecVersion != "1.6" || got.ComponentCount != 2 || len(got.Components) != 2 {
		t.Fatalf("replayed sbom=%#v", got)
	}
	if got.Components[0].Name != "a" || got.Components[1].Name != "z" {
		t.Fatalf("component order=%#v", got.Components)
	}
}

func TestParseReplayedSBOMRejectsUnsupportedCycloneDXVersion(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"legacy"}]}`)
	if _, err := parseReplayedSBOM(raw); err == nil {
		t.Fatal("unsupported CycloneDX version was accepted for replay")
	}
}
