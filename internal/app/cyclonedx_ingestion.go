package app

import (
	"crypto/sha256"
	"encoding/hex"
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
	payloadReader, err := source.Open()
	if err != nil {
		return cyclonedxNormalization{}, ErrValidation
	}

	hasher := sha256.New()
	counter := &payloadByteCounter{}
	reader := io.TeeReader(payloadReader, io.MultiWriter(hasher, counter))
	parsed, parseErr := validator.ValidateAndParseReader(reader, cyclonedxparser.DefaultLimits(EvidenceDocumentLimit))
	closeErr := payloadReader.Close()
	if parseErr != nil {
		if errors.Is(parseErr, cyclonedxparser.ErrInvalid) {
			return cyclonedxNormalization{}, ErrValidation
		}
		return cyclonedxNormalization{}, parseErr
	}
	if closeErr != nil {
		return cyclonedxNormalization{}, ErrValidation
	}

	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if counter.n != source.Size || digest != source.Digest {
		return cyclonedxNormalization{}, ErrValidation
	}
	return normalizeCycloneDXResult(parsed), nil
}
