package cyclonedx

import (
	"os"
	"testing"
)

func TestGeneratorCycloneDX16FixturesAreAccepted(t *testing.T) {
	tests := []struct {
		name         string
		components   int
		dependencies int
		identity     string
	}{
		{name: "syft-1.6.json", components: 1, identity: "purl:pkg:golang/github.com/wagoodman/go-partybus@v0.0.0-20230516145632-8ccac152c651"},
		{name: "trivy-1.6.json", components: 6, dependencies: 7, identity: "purl:pkg:golang/github.com/aquasecurity/go-pep440-version@v0.0.0-20210121094942-22b2f8951d46"},
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
			if len(got.Components) != test.components || len(got.Dependencies) != test.dependencies {
				t.Fatalf("components/dependencies=%d/%d want=%d/%d", len(got.Components), len(got.Dependencies), test.components, test.dependencies)
			}
			foundIdentity := false
			for _, component := range got.Components {
				if component.Identity == test.identity {
					foundIdentity = true
					break
				}
			}
			if !foundIdentity {
				t.Fatalf("generator identities=%#v missing %q", got.Components, test.identity)
			}
		})
	}
}
