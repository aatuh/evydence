package cyclonedx

import (
	"errors"
	"strings"
	"testing"
)

func TestNewSchemaValidatorWithEmbeddedCompanionsResolvesPinnedReferencesOffline(t *testing.T) {
	root := `{
	  "$schema":"http://json-schema.org/draft-07/schema#",
	  "$id":"http://cyclonedx.org/schema/bom-1.6.schema.json",
	  "type":"object",
	  "additionalProperties":false,
	  "required":["license"],
	  "properties":{
	    "license":{"$ref":"spdx.schema.json"},
	    "signature":{"$ref":"jsf-0.82.schema.json#/definitions/signature"}
	  }
	}`
	validator, err := NewSchemaValidatorWithEmbeddedCompanions(strings.NewReader(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.ValidateReader(strings.NewReader(`{"license":"Apache-2.0"}`), 1<<20); err != nil {
		t.Fatalf("valid SPDX companion reference rejected: %v", err)
	}
	if err := validator.ValidateReader(strings.NewReader(`{"license":"definitely-not-an-spdx-id"}`), 1<<20); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid SPDX identifier err=%v, want invalid", err)
	}
}

func TestNewSchemaValidatorWithEmbeddedCompanionsRejectsMissingRoot(t *testing.T) {
	if _, err := NewSchemaValidatorWithEmbeddedCompanions(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}
