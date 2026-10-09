package app

import (
	"context"
	"maps"
	"slices"

	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type memoryCustomerPackageEvidence struct {
	SBOMs, Scans, VEX []map[string]any
	Contracts         map[string]any
}

// Public parsed metadata only: raw payloads, SBOM components, scanner findings,
// VEX statements/authors and OpenAPI extensions are not copied or traversed.
func readMemoryCustomerPackageEvidence(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, budget *memoryCustomerSnapshotBudget) (memoryCustomerPackageEvidence, error) {
	var empty memoryCustomerPackageEvidence
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return empty, err
	}
	working := *budget
	out := memoryCustomerPackageEvidence{SBOMs: []map[string]any{}, Scans: []map[string]any{}, VEX: []map[string]any{}}
	for key, d := range s.SBOMs {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if d.ID != key || d.TenantID != tenant || d.ReleaseID != release {
			continue
		}
		owned, err := memoryCustomerParsedPackageSource(s, tenant, product, release, d.EvidenceID, "sbom", d.ArtifactID)
		if err != nil {
			return empty, err
		}
		if !owned {
			continue
		}
		if d.ComponentCount < 0 {
			return empty, ErrConflict
		}
		created, err := memoryCustomerSnapshotTime(d.CreatedAt)
		if err != nil {
			return empty, err
		}
		row := map[string]any{"id": d.ID, "evidence_id": d.EvidenceID, "release_id": d.ReleaseID, "artifact_id": d.ArtifactID, "format": d.Format, "spec_version": d.SpecVersion, "component_count": d.ComponentCount, "created_at": created}
		if err := appendMemoryCustomerMetadata(&out.SBOMs, row, &working); err != nil {
			return empty, err
		}
	}
	for key, d := range s.VulnerabilityScans {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if d.ID != key || d.TenantID != tenant || d.ReleaseID != release {
			continue
		}
		owned, err := memoryCustomerParsedPackageSource(s, tenant, product, release, d.EvidenceID, "vulnerability_scan", "")
		if err != nil {
			return empty, err
		}
		if !owned {
			continue
		}
		created, err := memoryCustomerSnapshotTime(d.CreatedAt)
		if err != nil {
			return empty, err
		}
		row := map[string]any{"id": d.ID, "evidence_id": d.EvidenceID, "release_id": d.ReleaseID, "scanner": d.Scanner, "target_ref": d.TargetRef, "summary": d.Summary, "finding_count": len(d.Findings), "created_at": created}
		if err := appendMemoryCustomerMetadata(&out.Scans, row, &working); err != nil {
			return empty, err
		}
		row["summary"] = cloneMemoryCustomerCounts(d.Summary)
	}
	for key, d := range s.VEXDocuments {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if d.ID != key || d.TenantID != tenant || d.ReleaseID != release {
			continue
		}
		owned, err := memoryCustomerParsedPackageSource(s, tenant, product, release, d.EvidenceID, "vex", d.ArtifactID)
		if err != nil {
			return empty, err
		}
		if !owned {
			continue
		}
		if d.StatementCount < 0 {
			return empty, ErrConflict
		}
		created, err := memoryCustomerSnapshotTime(d.CreatedAt)
		if err != nil {
			return empty, err
		}
		row := map[string]any{"id": d.ID, "evidence_id": d.EvidenceID, "release_id": d.ReleaseID, "artifact_id": d.ArtifactID, "format": d.Format, "version": d.Version, "statement_count": d.StatementCount, "status_summary": d.StatusSummary, "schema_version": d.SchemaVersion, "created_at": created}
		if err := appendMemoryCustomerMetadata(&out.VEX, row, &working); err != nil {
			return empty, err
		}
		row["status_summary"] = cloneMemoryCustomerCounts(d.StatusSummary)
	}
	contracts, err := readMemoryCustomerContracts(ctx, s, tenant, product, release, &working)
	if err != nil {
		return empty, err
	}
	out.Contracts = contracts
	for _, rows := range [][]map[string]any{out.SBOMs, out.Scans, out.VEX} {
		sortMemoryCustomerMetadata(rows)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*budget = working
	return out, nil
}

func appendMemoryCustomerMetadata(rows *[]map[string]any, row map[string]any, budget *memoryCustomerSnapshotBudget) error {
	if !memoryCustomerSnapshotID(row["id"].(string), false) || len(*rows) == packageapp.MaxSecurityReviewEvidenceIDs {
		return ErrConflict
	}
	if err := budget.charge(row); err != nil {
		return err
	}
	*rows = append(*rows, row)
	return nil
}

func cloneMemoryCustomerCounts(counts map[string]int) map[string]int {
	if counts == nil {
		return map[string]int{}
	}
	return maps.Clone(counts)
}

func memoryCustomerParsedPackageSource(s *MemoryUnitOfWorkSnapshot, tenant, product, release, source, kind, artifact string) (bool, error) {
	e, ok := s.Evidence[source]
	if !ok || e.ID != source || e.Type != kind || e.ReleaseID != release || !memoryCustomerEvidenceInScope(s, source, e, tenant, product, release) {
		return false, nil
	}
	if !memoryCustomerSnapshotID(source, false) || !memoryCustomerSnapshotID(artifact, true) || len(e.SubjectRefs) > packageapp.MaxSecurityReviewEvidenceIDs {
		return false, ErrConflict
	}
	remaining, matched := packageapp.MaxCustomerPackageManifestBytes, false
	for _, ref := range e.SubjectRefs {
		for _, text := range []string{ref.Type, ref.ID, ref.Digest} {
			if !memoryGovernanceText(text, remaining) {
				return false, ErrConflict
			}
			remaining -= len(text)
		}
		if ref.Type != "artifact" {
			continue
		}
		if artifact == "" || ref.ID != "" && ref.ID != artifact {
			return false, nil
		}
		matched = matched || ref.ID == artifact
	}
	if artifact == "" {
		return true, nil
	}
	a, ok := s.Artifacts[artifact]
	return matched && ok && a.ID == artifact && a.TenantID == tenant, nil
}

// Historical diff endpoints may belong to another release, but both contract
// sources must remain coherent with this tenant and product in the same view.
func memoryCustomerContractOwned(s *MemoryUnitOfWorkSnapshot, tenant, product, id string) bool {
	c, ok := s.OpenAPIContracts[id]
	if !ok || c.ID != id || c.TenantID != tenant || c.ProductID != product {
		return false
	}
	if _, err := memoryGovernanceProductRelease(s, tenant, product, c.ReleaseID); err != nil {
		return false
	}
	e, ok := s.Evidence[c.EvidenceID]
	if !ok || e.ID != c.EvidenceID || e.TenantID != tenant || e.Type != "openapi_contract" || e.ProductID != "" && e.ProductID != product || e.ReleaseID != "" && e.ReleaseID != c.ReleaseID {
		return false
	}
	_, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: product, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
	return err == nil
}

func readMemoryCustomerContracts(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, budget *memoryCustomerSnapshotBudget) (map[string]any, error) {
	contracts, diffs := []map[string]any{}, []map[string]any{}
	for key, c := range s.OpenAPIContracts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if c.ReleaseID != release || !memoryCustomerContractOwned(s, tenant, product, key) {
			continue
		}
		if c.PathCount < 0 || len(c.Operations) > packageapp.MaxSecurityReviewEvidenceIDs {
			return nil, ErrConflict
		}
		created, err := memoryCustomerSnapshotTime(c.CreatedAt)
		if err != nil {
			return nil, err
		}
		operations := make([]map[string]any, 0, len(c.Operations))
		for _, op := range c.Operations {
			operations = append(operations, map[string]any{"path": op.Path, "method": op.Method, "operation_id": op.OperationID, "deprecated": op.Deprecated, "request_body_required": op.RequestBodyRequired, "required_request_fields": op.RequiredRequestFields, "response_statuses": op.ResponseStatuses})
		}
		row := map[string]any{"id": c.ID, "evidence_id": c.EvidenceID, "product_id": c.ProductID, "release_id": c.ReleaseID, "version": c.Version, "hash": c.Hash, "path_count": c.PathCount, "operation_count": len(c.Operations), "operations": operations, "created_at": created}
		beforeBudget := *budget
		if err := appendMemoryCustomerMetadata(&contracts, row, budget); err != nil {
			return nil, err
		}
		// Normalization can duplicate paths into labels and expand text. Bound
		// raw public inputs before the shared renderer copies their slices.
		inputs := make([]packageapp.CustomerPackageAPIOperation, 0, len(c.Operations))
		for _, op := range c.Operations {
			inputs = append(inputs, packageapp.CustomerPackageAPIOperation{Path: op.Path, Method: op.Method, OperationID: op.OperationID, Deprecated: op.Deprecated, RequestBodyRequired: op.RequestBodyRequired, RequiredRequestFields: op.RequiredRequestFields, ResponseStatuses: op.ResponseStatuses})
		}
		row["operations"] = packageapp.CustomerPackageOperationSummaries(inputs)
		if err := beforeBudget.charge(row); err != nil {
			return nil, err
		}
		if beforeBudget.remainingBytes < budget.remainingBytes {
			*budget = beforeBudget
		}
	}
	for key, d := range s.ContractDiffs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if d.ID != key || d.TenantID != tenant || d.ProductID != product || d.ReleaseID != release || !memoryCustomerContractOwned(s, tenant, product, d.BaseContractID) || !memoryCustomerContractOwned(s, tenant, product, d.TargetContractID) {
			continue
		}
		created, err := memoryCustomerSnapshotTime(d.CreatedAt)
		if err != nil {
			return nil, err
		}
		row := map[string]any{"id": d.ID, "base_contract_id": d.BaseContractID, "target_contract_id": d.TargetContractID, "product_id": d.ProductID, "release_id": d.ReleaseID, "result": d.Result, "breaking_changes": d.BreakingChanges, "non_breaking_changes": d.NonBreakingChanges, "schema_version": d.SchemaVersion, "created_at": created}
		if err := appendMemoryCustomerMetadata(&diffs, row, budget); err != nil {
			return nil, err
		}
		row["breaking_changes"], row["non_breaking_changes"] = slices.Clone(d.BreakingChanges), slices.Clone(d.NonBreakingChanges)
	}
	sortMemoryCustomerMetadata(contracts)
	sortMemoryCustomerMetadata(diffs)
	return map[string]any{"openapi_contracts": contracts, "contract_diffs": diffs, "limitations": []string{
		"OpenAPI contract evidence includes stored metadata, hashes, and normalized operation summaries only.",
		"Raw OpenAPI document bytes, object-store payload references, and private/internal extensions are not included.",
		"Diff results summarize recorded contract evidence and do not make this package an API governance approval.",
	}}, nil
}
