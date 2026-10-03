package app

import (
	"io"
)

// validateAndNormalizeSPDXSource binds structured parsing to the declared
// repeatable payload source before object storage can accept its raw bytes.
func validateAndNormalizeSPDXSource(source PayloadSource) (spdxNormalization, error) {
	if validatePayloadSource(source, EvidenceDocumentLimit) != nil {
		return spdxNormalization{}, ErrValidation
	}
	var normalized spdxNormalization
	err := parseDigestBoundEvidenceSource(payloadSourceToEvidenceContext(source), func(reader io.Reader) error {
		var err error
		normalized, err = parseSPDXReader(reader, EvidenceDocumentLimit)
		return err
	})
	if err != nil {
		return spdxNormalization{}, err
	}
	return normalized, nil
}
