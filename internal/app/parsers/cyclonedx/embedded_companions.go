package cyclonedx

import (
	"embed"
	"fmt"
	"io"
)

// companionSchemaFS contains the exact CycloneDX 1.6 companion schemas pinned
// in schema/SOURCE.md. The root BOM schema is supplied separately so callers
// cannot accidentally activate a root whose provenance has not been verified.
//
//go:embed schema/spdx.schema.json schema/jsf-0.82.schema.json
var companionSchemaFS embed.FS

// NewSchemaValidatorWithEmbeddedCompanions compiles a CycloneDX validator from
// the supplied root BOM schema and the repository-pinned SPDX/JSF companions.
// External schema resolution remains disabled by NewSchemaValidator.
func NewSchemaValidatorWithEmbeddedCompanions(bom io.Reader) (*SchemaValidator, error) {
	spdx, err := companionSchemaFS.Open("schema/spdx.schema.json")
	if err != nil {
		return nil, fmt.Errorf("open embedded CycloneDX SPDX schema: %w", err)
	}
	defer spdx.Close()

	jsf, err := companionSchemaFS.Open("schema/jsf-0.82.schema.json")
	if err != nil {
		return nil, fmt.Errorf("open embedded CycloneDX JSF schema: %w", err)
	}
	defer jsf.Close()

	return NewSchemaValidator(bom, spdx, jsf)
}
