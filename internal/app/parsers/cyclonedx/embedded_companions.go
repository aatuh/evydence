package cyclonedx

import (
	"bytes"
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
)

const PinnedBOMSchemaGitBlobSHA = "b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba"

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

// NewPinnedSchemaValidator admits a CycloneDX 1.6 root schema only when its
// bytes are exactly the Git object pinned in schema/SOURCE.md. SHA-1 is used
// here solely because Git's blob object identity is the provenance contract;
// this is not a general-purpose cryptographic authenticity check.
func NewPinnedSchemaValidator(bom io.Reader) (*SchemaValidator, error) {
	if bom == nil {
		return nil, ErrInvalid
	}
	limited := &io.LimitedReader{R: bom, N: maxSchemaResourceBytes + 1}
	raw, err := io.ReadAll(limited)
	if err != nil || int64(len(raw)) > maxSchemaResourceBytes || schemaGitBlobSHA(raw) != PinnedBOMSchemaGitBlobSHA {
		return nil, ErrInvalid
	}
	return NewSchemaValidatorWithEmbeddedCompanions(bytes.NewReader(raw))
}

func schemaGitBlobSHA(raw []byte) string {
	h := sha1.New() // #nosec G505 -- matching Git's pinned blob object identifier.
	_, _ = fmt.Fprintf(h, "blob %d%c", len(raw), byte(0))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
