package cyclonedx

import (
	"os"
	"slices"
	"testing"
)

func TestGeneratorCycloneDXFixturesSurfacePreservedLimitations(t *testing.T) {
	tests := []struct {
		name        string
		unsupported []string
	}{
		{name: "syft-1.6.json", unsupported: []string{"$schema", "serialNumber", "version", "metadata", "components[].cpe", "components[].properties"}},
		{name: "trivy-1.6.json", unsupported: []string{"$schema", "serialNumber", "version", "metadata", "components[].properties", "vulnerabilities"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/generators/" + test.name)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseBounded(raw, DefaultLimits(1<<20))
			if err != nil {
				t.Fatalf("generator fixture rejected: %v", err)
			}
			for _, want := range test.unsupported {
				if !slices.Contains(got.UnsupportedPaths, want) {
					t.Fatalf("unsupported=%#v missing %q", got.UnsupportedPaths, want)
				}
			}
			if len(got.Warnings) != len(got.UnsupportedPaths) {
				t.Fatalf("warnings=%d unsupported=%d", len(got.Warnings), len(got.UnsupportedPaths))
			}
		})
	}
}
