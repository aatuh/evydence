package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
	scannerparser "github.com/aatuh/evydence/internal/app/parsers/scanners"
	spdxparser "github.com/aatuh/evydence/internal/app/parsers/spdx"
	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
)

type parserCorpusManifest struct {
	Fixtures []parserCorpusFixture `json:"fixtures"`
}
type parserCorpusFixture struct {
	ID              string         `json:"id"`
	Kind            string         `json:"kind"`
	Path            string         `json:"path"`
	ExpectedStatus  string         `json:"expected_status"`
	MaxBytes        int64          `json:"max_bytes"`
	ExpectedSummary map[string]any `json:"expected_summary"`
}

func TestParserConformanceCorpus(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "parser-corpus.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest parserCorpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || len(manifest.Fixtures) == 0 {
		t.Fatalf("read corpus manifest: %v", err)
	}
	for _, fixture := range manifest.Fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join(root, fixture.Path))
			if err != nil {
				t.Fatal(err)
			}
			if fixture.ExpectedStatus != "accepted" || int64(len(input)) > fixture.MaxBytes {
				t.Fatal("invalid corpus fixture")
			}
			var summary map[string]any
			switch fixture.Kind {
			case "cyclonedx":
				parsed, err := cyclonedxparser.ParseBounded(input, cyclonedxparser.DefaultLimits(fixture.MaxBytes))
				if err != nil {
					t.Fatal(err)
				}
				summary = map[string]any{"spec_version": parsed.SpecVersion, "component_count": len(parsed.Components)}
			case "spdx":
				parsed, err := spdxparser.ParseBounded(input, spdxparser.DefaultLimits(fixture.MaxBytes))
				if err != nil {
					t.Fatal(err)
				}
				summary = map[string]any{"spec_version": parsed.SpecVersion, "component_count": len(parsed.Packages)}
			case "openvex":
				parsed, err := vexparser.ParseOpenVEX(input, vexparser.DefaultLimits(fixture.MaxBytes))
				if err != nil {
					t.Fatal(err)
				}
				summary = map[string]any{"statement_count": len(parsed.Statements)}
			case "cyclonedx-vex":
				parsed, err := vexparser.ParseCycloneDX(input, vexparser.DefaultLimits(fixture.MaxBytes))
				if err != nil {
					t.Fatal(err)
				}
				summary = map[string]any{"statement_count": len(parsed.Statements)}
			case "scanner":
				parsed, err := scannerparser.ParseBounded(input, scannerparser.DefaultLimits(fixture.MaxBytes))
				if err != nil {
					t.Fatal(err)
				}
				summary = map[string]any{"finding_count": len(parsed.Findings)}
			default:
				t.Fatalf("unsupported corpus kind %q", fixture.Kind)
			}
			if len(summary) != len(fixture.ExpectedSummary) {
				t.Fatalf("summary = %#v, want %#v", summary, fixture.ExpectedSummary)
			}
			for key, want := range fixture.ExpectedSummary {
				if got := summary[key]; fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("summary[%s] = %#v, want %#v", key, got, want)
				}
			}
		})
	}
}
