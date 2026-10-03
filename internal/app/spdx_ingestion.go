package app

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// validateAndNormalizeSPDXSource binds structured parsing to the declared
// repeatable payload source before object storage can accept its raw bytes.
func validateAndNormalizeSPDXSource(source PayloadSource) (spdxNormalization, error) {
	if validatePayloadSource(source, EvidenceDocumentLimit) != nil {
		return spdxNormalization{}, ErrValidation
	}
	reader, err := source.Open()
	if err != nil {
		return spdxNormalization{}, ErrValidation
	}
	hasher, counter := sha256.New(), &payloadByteCounter{}
	normalized, parseErr := parseSPDXReader(io.TeeReader(reader, io.MultiWriter(hasher, counter)), EvidenceDocumentLimit)
	closeErr := reader.Close()
	if parseErr != nil {
		return spdxNormalization{}, parseErr
	}
	if closeErr != nil {
		return spdxNormalization{}, ErrValidation
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if counter.n != source.Size || digest != source.Digest {
		return spdxNormalization{}, ErrValidation
	}
	return normalized, nil
}
