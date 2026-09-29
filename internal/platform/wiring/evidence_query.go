package wiring

import evidencequery "github.com/aatuh/evydence/internal/evidence/query"

// BuildEvidencePointQuery binds tenant-scoped ordinary evidence reads to the
// focused evidence policy. Worker-owned rows retain their validated projection.
func BuildEvidencePointQuery(reader evidencequery.EvidencePointReader) (*evidencequery.EvidencePoints, error) {
	return evidencequery.NewEvidencePoints(reader)
}

// BuildOpenAPIContractPointQuery binds parsed contract metadata to current
// tenant-owned evidence and release-catalog parents.
func BuildOpenAPIContractPointQuery(reader evidencequery.OpenAPIContractPointReader) (*evidencequery.OpenAPIContractPoints, error) {
	return evidencequery.NewOpenAPIContractPoints(reader)
}
