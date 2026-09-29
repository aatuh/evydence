package wiring

import evidencequery "github.com/aatuh/evydence/internal/evidence/query"

// BuildEvidencePointQuery binds tenant-scoped ordinary evidence reads to the
// focused evidence policy. Worker-owned rows retain their validated projection.
func BuildEvidencePointQuery(reader evidencequery.EvidencePointReader) (*evidencequery.EvidencePoints, error) {
	return evidencequery.NewEvidencePoints(reader)
}

// BuildLifecycleEventsQuery pages ordinary evidence events from a durable
// snapshot while worker-owned evidence keeps its provenance projection.
func BuildLifecycleEventsQuery(reader evidencequery.LifecycleEventReader) (*evidencequery.LifecycleEvents, error) {
	return evidencequery.NewLifecycleEvents(reader)
}

// BuildOpenAPIContractPointQuery binds parsed contract metadata to current
// tenant-owned evidence and release-catalog parents.
func BuildOpenAPIContractPointQuery(reader evidencequery.OpenAPIContractPointReader) (*evidencequery.OpenAPIContractPoints, error) {
	return evidencequery.NewOpenAPIContractPoints(reader)
}

// BuildSBOMPointQuery binds parsed SBOM reads to current tenant-owned parents.
func BuildSBOMPointQuery(reader evidencequery.SBOMPointReader) (*evidencequery.SBOMPoints, error) {
	return evidencequery.NewSBOMPoints(reader)
}

// BuildVulnerabilityScanPointQuery binds parsed scans to current source and
// release ownership without loading the worker's tenant-wide projection.
func BuildVulnerabilityScanPointQuery(reader evidencequery.VulnerabilityScanPointReader) (*evidencequery.VulnerabilityScanPoints, error) {
	return evidencequery.NewVulnerabilityScanPoints(reader)
}

// BuildSBOMComponentsQuery binds tenant- and grant-scoped component pages to
// the durable reader without loading the Ledger snapshot.
func BuildSBOMComponentsQuery(reader evidencequery.SBOMComponentReader) (*evidencequery.SBOMComponents, error) {
	return evidencequery.NewSBOMComponents(reader)
}
