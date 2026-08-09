package cyclonedx

import (
	"errors"
	"strings"
	"testing"
)

const testBOMSchema = `{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "$id":"http://cyclonedx.org/schema/bom-1.6.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["bomFormat","specVersion","license","signature"],
  "properties":{
    "bomFormat":{"const":"CycloneDX"},
    "specVersion":{"const":"1.6"},
    "license":{"$ref":"spdx.schema.json#/definitions/license"},
    "signature":{"$ref":"jsf-0.82.schema.json#/definitions/signature"}
  }
}`

const testSPDXSchema = `{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "$id":"http://cyclonedx.org/schema/spdx.schema.json",
  "definitions":{"license":{"type":"string","enum":["Apache-2.0"]}}
}`

const testJSFSchema = `{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "$id":"http://cyclonedx.org/schema/jsf-0.82.schema.json",
  "definitions":{"signature":{"type":"object","required":["algorithm"],"properties":{"algorithm":{"const":"ES256"}}}}
}`

func newTestSchemaValidator(t *testing.T) *SchemaValidator {
	t.Helper()
	validator, err := NewSchemaValidator(
		strings.NewReader(testBOMSchema),
		strings.NewReader(testSPDXSchema),
		strings.NewReader(testJSFSchema),
	)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func TestSchemaValidatorResolvesCompanionSchemasAndFailsClosed(t *testing.T) {
	validator := newTestSchemaValidator(t)
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"Apache-2.0","signature":{"algorithm":"ES256"}}`
	if err := validator.ValidateReader(strings.NewReader(valid), 1<<20); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"wrong license":   `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"MIT","signature":{"algorithm":"ES256"}}`,
		"wrong signature": `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"Apache-2.0","signature":{"algorithm":"RS256"}}`,
		"extra field":     `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"Apache-2.0","signature":{"algorithm":"ES256"},"unknown":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validator.ValidateReader(strings.NewReader(raw), 1<<20); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
}

func TestSchemaValidatorEnforcesInputAndSchemaBounds(t *testing.T) {
	validator := newTestSchemaValidator(t)
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"Apache-2.0","signature":{"algorithm":"ES256"}}`
	if err := validator.ValidateReader(strings.NewReader(valid+" "), int64(len(valid))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized err=%v, want invalid", err)
	}
	if err := validator.ValidateReader(nil, 1<<20); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil reader err=%v, want invalid", err)
	}
	if _, err := NewSchemaValidator(strings.NewReader(`{`), strings.NewReader(testSPDXSchema), strings.NewReader(testJSFSchema)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed schema err=%v, want invalid", err)
	}
	if _, err := NewSchemaValidator(nil, strings.NewReader(testSPDXSchema), strings.NewReader(testJSFSchema)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil schema err=%v, want invalid", err)
	}
}

func TestSchemaValidatorValidatesAndParsesTheSameBoundedBytes(t *testing.T) {
	validator := newTestSchemaValidator(t)
	limits := DefaultLimits(1 << 20)
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"Apache-2.0","signature":{"algorithm":"ES256"}}`
	got, err := validator.ValidateAndParseReader(strings.NewReader(valid), limits)
	if err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if got.SpecVersion != SupportedSpecVersion {
		t.Fatalf("specVersion=%q", got.SpecVersion)
	}

	invalid := `{"bomFormat":"CycloneDX","specVersion":"1.6","license":"MIT","signature":{"algorithm":"ES256"}}`
	if _, err := validator.ValidateAndParseReader(strings.NewReader(invalid), limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("schema-invalid err=%v, want invalid", err)
	}

	tiny := limits
	tiny.MaxBytes = int64(len(valid) - 1)
	if _, err := validator.ValidateAndParseReader(strings.NewReader(valid), tiny); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized err=%v, want invalid", err)
	}
	if _, err := validator.ValidateAndParseReader(nil, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil reader err=%v, want invalid", err)
	}
}
