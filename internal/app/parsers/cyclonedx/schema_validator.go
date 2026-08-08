package cyclonedx

import (
	"errors"
	"io"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	BOMSchemaURL  = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	SPDXSchemaURL = "http://cyclonedx.org/schema/spdx.schema.json"
	JSFSchemaURL  = "http://cyclonedx.org/schema/jsf-0.82.schema.json"
)

// SchemaValidator validates CycloneDX documents with an explicitly supplied,
// offline schema set. Production construction uses the pinned official 1.6
// schema resources; accepting readers here keeps schema provenance and loading
// separate from untrusted document validation.
type SchemaValidator struct {
	schema *jsonschema.Schema
}

func NewSchemaValidator(bom, spdx, jsf io.Reader) (*SchemaValidator, error) {
	if bom == nil || spdx == nil || jsf == nil {
		return nil, ErrInvalid
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	for _, resource := range []struct {
		url    string
		reader io.Reader
	}{
		{url: BOMSchemaURL, reader: bom},
		{url: SPDXSchemaURL, reader: spdx},
		{url: JSFSchemaURL, reader: jsf},
	} {
		doc, err := jsonschema.UnmarshalJSON(resource.reader)
		if err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		if err := compiler.AddResource(resource.url, doc); err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
	}
	schema, err := compiler.Compile(BOMSchemaURL)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	return &SchemaValidator{schema: schema}, nil
}

// ValidateReader validates one JSON document under a hard byte limit. Schema
// diagnostics are intentionally collapsed to ErrInvalid at this trust boundary
// so upstream paths cannot leak attacker-controlled values through errors.
func (v *SchemaValidator) ValidateReader(reader io.Reader, maxBytes int64) error {
	if v == nil || v.schema == nil || reader == nil || maxBytes < 1 {
		return ErrInvalid
	}
	limited := &io.LimitedReader{R: reader, N: maxBytes + 1}
	doc, err := jsonschema.UnmarshalJSON(limited)
	if err != nil || limited.N == 0 {
		return ErrInvalid
	}
	if err := v.schema.Validate(doc); err != nil {
		return ErrInvalid
	}
	return nil
}
