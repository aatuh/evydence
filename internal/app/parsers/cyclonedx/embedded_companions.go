package cyclonedx

import (
	"bytes"
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
)

const (
	PinnedBOMSchemaGitBlobSHA = "b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba"
	pinnedBOMSchemaSize       = 262666
	pinnedBOMSchemaPartCount  = 23
)

// pinnedSchemaFS contains the exact CycloneDX 1.6 schema resources pinned in
// schema/SOURCE.md. The root schema is split only to make exact-byte vendoring
// practical; it is reconstructed and verified before it can be compiled.
//
//go:embed schema/spdx.schema.json schema/jsf-0.82.schema.json schema/bom-1.6.part-*.json
var pinnedSchemaFS embed.FS

// NewSchemaValidatorWithEmbeddedCompanions compiles a CycloneDX validator from
// the supplied root BOM schema and the repository-pinned SPDX/JSF companions.
// External schema resolution remains disabled by NewSchemaValidator.
func NewSchemaValidatorWithEmbeddedCompanions(bom io.Reader) (*SchemaValidator, error) {
	spdx, err := pinnedSchemaFS.Open("schema/spdx.schema.json")
	if err != nil {
		return nil, fmt.Errorf("open embedded CycloneDX SPDX schema: %w", err)
	}
	defer spdx.Close()

	jsf, err := pinnedSchemaFS.Open("schema/jsf-0.82.schema.json")
	if err != nil {
		return nil, fmt.Errorf("open embedded CycloneDX JSF schema: %w", err)
	}
	defer jsf.Close()

	return NewSchemaValidator(bom, spdx, jsf)
}

// NewEmbeddedPinnedSchemaValidator compiles the repository-pinned CycloneDX
// 1.6 root and companion schemas without network access. Root fragments are not
// trusted individually: their exact reconstruction must match the pinned Git
// object before compilation is attempted.
func NewEmbeddedPinnedSchemaValidator() (*SchemaValidator, error) {
	raw, err := embeddedPinnedBOMSchema()
	if err != nil {
		return nil, err
	}
	return NewPinnedSchemaValidator(bytes.NewReader(raw))
}

func embeddedPinnedBOMSchema() ([]byte, error) {
	names, err := fs.Glob(pinnedSchemaFS, "schema/bom-1.6.part-*.json")
	if err != nil || len(names) != pinnedBOMSchemaPartCount {
		return nil, ErrInvalid
	}
	sort.Strings(names)

	var joined bytes.Buffer
	joined.Grow(pinnedBOMSchemaSize)
	for _, name := range names {
		part, err := fs.ReadFile(pinnedSchemaFS, name)
		if err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		if joined.Len()+len(part)+1 > pinnedBOMSchemaSize {
			return nil, ErrInvalid
		}
		_, _ = joined.Write(part)
		_ = joined.WriteByte('\n')
	}

	raw := joined.Bytes()
	if len(raw) != pinnedBOMSchemaSize || schemaGitBlobSHA(raw) != PinnedBOMSchemaGitBlobSHA {
		return nil, ErrInvalid
	}
	return append([]byte(nil), raw...), nil
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
