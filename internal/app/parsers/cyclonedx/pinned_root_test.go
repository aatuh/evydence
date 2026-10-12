package cyclonedx

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNewPinnedSchemaValidatorRejectsUnpinnedRoot(t *testing.T) {
	root := `{"$schema":"http://json-schema.org/draft-07/schema#","$id":"http://cyclonedx.org/schema/bom-1.6.schema.json","type":"object"}`
	if _, err := NewPinnedSchemaValidator(strings.NewReader(root)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

func TestEmbeddedPinnedBOMSchemaMatchesPinnedObject(t *testing.T) {
	raw, err := embeddedPinnedBOMSchema()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != pinnedBOMSchemaSize {
		t.Fatalf("root size=%d want=%d", len(raw), pinnedBOMSchemaSize)
	}
	if got := schemaGitBlobSHA(raw); got != PinnedBOMSchemaGitBlobSHA {
		t.Fatalf("root Git blob=%q want=%q", got, PinnedBOMSchemaGitBlobSHA)
	}
}

func TestNewEmbeddedPinnedSchemaValidatorEnforcesOfficialRootOffline(t *testing.T) {
	validator, err := NewEmbeddedPinnedSchemaValidator()
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","licenses":[{"license":{"id":"Apache-2.0"}}]}]}`
	got, err := validator.ValidateAndParseReader(strings.NewReader(valid), DefaultLimits(1<<20))
	if err != nil {
		t.Fatalf("valid CycloneDX 1.6 rejected: %v", err)
	}
	if len(got.Components) != 1 || got.Components[0].Name != "api" {
		t.Fatalf("normalized=%#v", got)
	}

	invalid := `{"bomFormat":"CycloneDX","specVersion":"1.6","definitelyNotCycloneDX":true}`
	if _, err := validator.ValidateAndParseReader(strings.NewReader(invalid), DefaultLimits(1<<20)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("schema-invalid document err=%v, want invalid", err)
	}
}

func TestEmbeddedPinnedSchemaAcceptsGeneratorFixtures(t *testing.T) {
	validator, err := NewEmbeddedPinnedSchemaValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syft-1.6.json", "trivy-1.6.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/generators/" + name)
			if err != nil {
				t.Fatal(err)
			}
			got, err := validator.ValidateAndParseReader(bytes.NewReader(raw), DefaultLimits(1<<20))
			if err != nil {
				t.Fatalf("generator fixture rejected by pinned schema: %v", err)
			}
			if got.SpecVersion != SupportedSpecVersion {
				t.Fatalf("specVersion=%q", got.SpecVersion)
			}
		})
	}
}

func TestPinnedBOMSchemaGitBlobSHAIsDeclared(t *testing.T) {
	if PinnedBOMSchemaGitBlobSHA != "b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba" {
		t.Fatalf("pinned root=%q", PinnedBOMSchemaGitBlobSHA)
	}
}
