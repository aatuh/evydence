package app

import (
	"errors"
	"io"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
)

type payloadByteCounter struct {
	n int64
}

func (c *payloadByteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// validateAndNormalizeCycloneDXSource validates and normalizes the same bounded
// payload bytes, and binds the trusted result to the source's declared size and
// digest. Object staging reopens and independently verifies those same claims,
// preventing mutable PayloadSource implementations from substituting bytes
// across validation, normalization, and durable storage.
func validateAndNormalizeCycloneDXSource(source PayloadSource, validator *cyclonedxparser.SchemaValidator) (cyclonedxNormalization, error) {
	if validatePayloadSource(source, EvidenceDocumentLimit) != nil || validator == nil {
		return cyclonedxNormalization{}, ErrValidation
	}
	var parsed cyclonedxparser.Result
	err := parseDigestBoundEvidenceSource(payloadSourceToEvidenceContext(source), func(reader io.Reader) error {
		var err error
		parsed, err = validator.ValidateAndParseReader(reader, cyclonedxparser.DefaultLimits(EvidenceDocumentLimit))
		return err
	})
	if err != nil {
		if errors.Is(err, cyclonedxparser.ErrInvalid) {
			return cyclonedxNormalization{}, ErrValidation
		}
		return cyclonedxNormalization{}, err
	}
	return normalizeCycloneDXResult(parsed), nil
}
