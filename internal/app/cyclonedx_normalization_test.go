package app

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCycloneDXNormalizationMapsGeneratorFixtureAndReportsOmissions(t *testing.T) {
	file, err := os.Open("parsers/cyclonedx/testdata/generators/trivy-1.6.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	got, err := parseCycloneDXReader(file, EvidenceDocumentLimit)
	if err != nil {
		t.Fatal(err)
	}
	if got.SpecVersion != "1.6" || got.ParserVersion != ParserVersionCycloneDXJSON || len(got.Components) != 6 || got.DependencyCount != 7 {
		t.Fatalf("normalization=%#v", got)
	}
	if got.Components[1].PURL != "pkg:golang/github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46" {
		t.Fatalf("component=%#v", got.Components[1])
	}
	metadata := got.evidenceMetadata()
	if metadata["component_count"] != 6 || metadata["dependency_count"] != 7 || metadata["parser_version"] != ParserVersionCycloneDXJSON {
		t.Fatalf("metadata=%#v", metadata)
	}
	if len(got.UnsupportedPaths) == 0 || len(got.Warnings) == 0 || len(got.limitations()) != 1 {
		t.Fatalf("warnings/limitations=%#v/%#v/%#v", got.UnsupportedPaths, got.Warnings, got.limitations())
	}
}

func TestCycloneDXNormalizationFailsClosedOnInvalidAndOversizedInput(t *testing.T) {
	for name, raw := range map[string]string{
		"unsupported version":    `{"bomFormat":"CycloneDX","specVersion":"1.5"}`,
		"missing component type": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCycloneDXReader(strings.NewReader(raw), EvidenceDocumentLimit); !errors.Is(err, ErrValidation) {
				t.Fatalf("err=%v, want validation", err)
			}
		})
	}
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6"}`
	if _, err := parseCycloneDXReader(strings.NewReader(valid+" "), int64(len(valid))); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversized err=%v, want validation", err)
	}
}
