package app

import (
	"errors"
	"io"
	"strings"
	"testing"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
)

const testCycloneDXBOMSchema = `{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "$id":"http://cyclonedx.org/schema/bom-1.6.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["bomFormat","specVersion","components"],
  "properties":{
    "bomFormat":{"const":"CycloneDX"},
    "specVersion":{"const":"1.6"},
    "components":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["type","name"],"properties":{"type":{"type":"string"},"name":{"type":"string"},"version":{"type":"string"},"purl":{"type":"string"}}}}
  }
}`

const testCycloneDXCompanionSchema = `{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "type":"object",
  "definitions":{}
}`

func testCycloneDXValidator(t *testing.T) *cyclonedxparser.SchemaValidator {
	t.Helper()
	validator, err := cyclonedxparser.NewSchemaValidator(
		strings.NewReader(testCycloneDXBOMSchema),
		strings.NewReader(testCycloneDXCompanionSchema),
		strings.NewReader(testCycloneDXCompanionSchema),
	)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func TestValidateAndNormalizeCycloneDXSourceUsesRepeatableBoundedPasses(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0"}]}`)
	source := BytesPayloadSource(raw)
	openCount := 0
	open := source.Open
	source.Open = func() (io.ReadCloser, error) {
		openCount++
		return open()
	}

	got, err := validateAndNormalizeCycloneDXSource(source, testCycloneDXValidator(t))
	if err != nil {
		t.Fatal(err)
	}
	if openCount != 2 || got.SpecVersion != "1.6" || len(got.Components) != 1 || got.Components[0].PURL != "pkg:generic/api@1.0.0" {
		t.Fatalf("open_count=%d normalization=%#v", openCount, got)
	}
}

func TestValidateAndNormalizeCycloneDXSourceRejectsSchemaAndSourceFailures(t *testing.T) {
	validator := testCycloneDXValidator(t)
	invalid := BytesPayloadSource([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`))
	if _, err := validateAndNormalizeCycloneDXSource(invalid, validator); !errors.Is(err, ErrValidation) {
		t.Fatalf("schema-invalid err=%v, want validation", err)
	}

	badSource := BytesPayloadSource([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`))
	badSource.Open = func() (io.ReadCloser, error) { return nil, errors.New("source unavailable") }
	if _, err := validateAndNormalizeCycloneDXSource(badSource, validator); !errors.Is(err, ErrValidation) {
		t.Fatalf("open failure err=%v, want validation", err)
	}
	if _, err := validateAndNormalizeCycloneDXSource(BytesPayloadSource([]byte(`{}`)), nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil validator err=%v, want validation", err)
	}
}
