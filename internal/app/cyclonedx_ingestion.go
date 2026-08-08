package app

import (
	"errors"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
)

// validateAndNormalizeCycloneDXSource consumes a repeatable payload source in
// two bounded passes: official-schema validation first, then deterministic
// normalization. The source bytes themselves are not copied here; later object
// staging reopens the same source and preserves the original payload.
func validateAndNormalizeCycloneDXSource(source PayloadSource, validator *cyclonedxparser.SchemaValidator) (cyclonedxNormalization, error) {
	if validatePayloadSource(source, EvidenceDocumentLimit) != nil || validator == nil {
		return cyclonedxNormalization{}, ErrValidation
	}
	validationReader, err := source.Open()
	if err != nil {
		return cyclonedxNormalization{}, ErrValidation
	}
	validationErr := validator.ValidateReader(validationReader, EvidenceDocumentLimit)
	closeErr := validationReader.Close()
	if validationErr != nil || closeErr != nil {
		return cyclonedxNormalization{}, ErrValidation
	}

	normalizationReader, err := source.Open()
	if err != nil {
		return cyclonedxNormalization{}, ErrValidation
	}
	normalized, normalizeErr := parseCycloneDXReader(normalizationReader, EvidenceDocumentLimit)
	closeErr = normalizationReader.Close()
	if normalizeErr != nil {
		if errors.Is(normalizeErr, ErrValidation) {
			return cyclonedxNormalization{}, ErrValidation
		}
		return cyclonedxNormalization{}, normalizeErr
	}
	if closeErr != nil {
		return cyclonedxNormalization{}, ErrValidation
	}
	return normalized, nil
}
