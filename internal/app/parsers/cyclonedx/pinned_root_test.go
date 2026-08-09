package cyclonedx

import (
	"errors"
	"strings"
	"testing"
)

func TestNewPinnedSchemaValidatorRejectsUnpinnedRoot(t *testing.T) {
	root := `{"$schema":"http://json-schema.org/draft-07/schema#","$id":"http://cyclonedx.org/schema/bom-1.6.schema.json","type":"object"}`
	if _, err := NewPinnedSchemaValidator(strings.NewReader(root)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

func TestPinnedBOMSchemaGitBlobSHAIsDeclared(t *testing.T) {
	if PinnedBOMSchemaGitBlobSHA != "b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba" {
		t.Fatalf("pinned root=%q", PinnedBOMSchemaGitBlobSHA)
	}
}
