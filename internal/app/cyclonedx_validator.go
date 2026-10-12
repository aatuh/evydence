package app

import (
	"sync"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
)

var productionCycloneDXValidatorOnce = sync.OnceValues(cyclonedxparser.NewEmbeddedPinnedSchemaValidator)

func productionCycloneDXValidator() (*cyclonedxparser.SchemaValidator, error) {
	return productionCycloneDXValidatorOnce()
}
