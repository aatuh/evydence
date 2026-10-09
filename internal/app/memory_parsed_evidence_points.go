package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var (
	_ evidencequery.SBOMPointReader              = memoryEvidenceRepository{}
	_ evidencequery.VulnerabilityScanPointReader = memoryEvidenceRepository{}
	_ evidencequery.OpenAPIContractPointReader   = memoryEvidenceRepository{}
)

// Typed memory rows model current ownership and detached point projections;
// they do not prove PostgreSQL JSON shapes, transfer/work limits or locks.
func (r memoryEvidenceRepository) parsedPointRead(ctx context.Context, tenant, id string, read func(*MemoryUnitOfWorkSnapshot, string) error) error {
	if ctx == nil || r.uow == nil || strings.TrimSpace(tenant) == "" {
		return evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencequery.ErrNotFound
	}
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		if err := read(s, id); err != nil {
			return err
		}
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		return evidencequery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		return evidencequery.ErrConflict
	}
	return err
}

func memoryParsedSource(s *MemoryUnitOfWorkSnapshot, tenant, id, kind string) (domain.EvidenceItem, application.ResourceReferences, error) {
	e, ok := s.Evidence[id]
	if !ok || e.ID != id || e.TenantID != tenant || e.Type != kind {
		return domain.EvidenceItem{}, application.ResourceReferences{}, evidencequery.ErrNotFound
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
	return e, refs, err
}

// Point and component readers share the current source/parent binding. The
// paging view deliberately does not require point-projection completion.
func memoryOwnedSBOM(s *MemoryUnitOfWorkSnapshot, tenant, id string) (domain.SBOM, string, error) {
	b, ok := s.SBOMs[id]
	if !ok || b.ID != id || b.TenantID != tenant {
		return domain.SBOM{}, "", evidencequery.ErrNotFound
	}
	e, _, err := memoryParsedSource(s, tenant, b.EvidenceID, "sbom")
	if err != nil {
		return domain.SBOM{}, "", err
	}
	if e.ReleaseID != b.ReleaseID {
		return domain.SBOM{}, "", evidencequery.ErrNotFound
	}
	artifactRefs := map[string]bool{}
	for _, ref := range e.SubjectRefs {
		if ref.Type == "artifact" && ref.ID != "" {
			artifactRefs[ref.ID] = true
		}
	}
	if b.ArtifactID == "" && len(artifactRefs) != 0 || b.ArtifactID != "" && (len(artifactRefs) != 1 || !artifactRefs[b.ArtifactID]) {
		return domain.SBOM{}, "", evidencequery.ErrNotFound
	}
	if b.ArtifactID != "" {
		a, ok := s.Artifacts[b.ArtifactID]
		if !ok || a.ID != b.ArtifactID || a.TenantID != tenant {
			return domain.SBOM{}, "", evidencequery.ErrNotFound
		}
	}
	product := ""
	if b.ReleaseID != "" {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: b.ReleaseID})
		if err != nil {
			return domain.SBOM{}, "", err
		}
		product = refs.ProductID
	}
	return b, product, nil
}

func (r memoryEvidenceRepository) GetSBOMPoint(ctx context.Context, tenant, id string) (evidencequery.SBOMPoint, error) {
	var out evidencequery.SBOMPoint
	err := r.parsedPointRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot, id string) error {
		b, product, err := memoryOwnedSBOM(s, tenant, id)
		if err != nil {
			return err
		}
		if b.Components == nil && b.ComponentCount != 0 {
			return evidencequery.ErrConflict
		}
		out.ProductID = product
		out.SBOM = sbomToEvidenceContext(b)
		return nil
	})
	if err != nil {
		return evidencequery.SBOMPoint{}, err
	}
	return out, nil
}

func (r memoryEvidenceRepository) GetVulnerabilityScanPoint(ctx context.Context, tenant, id string) (evidencequery.VulnerabilityScanPoint, error) {
	var out evidencequery.VulnerabilityScanPoint
	err := r.parsedPointRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot, id string) error {
		v, ok := s.VulnerabilityScans[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return evidencequery.ErrNotFound
		}
		e, refs, err := memoryParsedSource(s, tenant, v.EvidenceID, "vulnerability_scan")
		if err != nil {
			return err
		}
		if e.ReleaseID != v.ReleaseID || refs.ReleaseID != v.ReleaseID {
			return evidencequery.ErrNotFound
		}
		for _, ref := range e.SubjectRefs {
			if ref.Type == "artifact" && ref.ID != "" {
				return evidencequery.ErrNotFound
			}
		}
		if !memoryParsedJSONFits(v.Summary) || !memoryParsedJSONFits(v.Findings) {
			return evidencequery.ErrConflict
		}
		out = evidencequery.VulnerabilityScanPoint{Scan: vulnerabilityScanToEvidenceContext(v), ProductID: refs.ProductID}
		return nil
	})
	if err != nil {
		return evidencequery.VulnerabilityScanPoint{}, err
	}
	return out, nil
}

func (r memoryEvidenceRepository) GetOpenAPIContractPoint(ctx context.Context, tenant, id string) (evidencequery.OpenAPIContractPoint, error) {
	var out evidencequery.OpenAPIContractPoint
	err := r.parsedPointRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot, id string) error {
		c, ok := s.OpenAPIContracts[id]
		if !ok || c.ID != id || c.TenantID != tenant || c.ProductID == "" {
			return evidencequery.ErrNotFound
		}
		if _, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: c.ProductID, ReleaseID: c.ReleaseID}); err != nil {
			return err
		}
		e, refs, err := memoryParsedSource(s, tenant, c.EvidenceID, "openapi_contract")
		if err != nil {
			return err
		}
		if refs.ProductID != "" && refs.ProductID != c.ProductID || e.ReleaseID != "" && e.ReleaseID != c.ReleaseID {
			return evidencequery.ErrNotFound
		}
		if c.Operations == nil || !memoryParsedJSONFits(c.Operations) {
			return evidencequery.ErrConflict
		}
		out.Contract = openAPIContractToEvidenceContext(c)
		return nil
	})
	if err != nil {
		return evidencequery.OpenAPIContractPoint{}, err
	}
	return out, nil
}

// The native scan/contract readers cap each selected JSON value at 32 MiB.
// This models response size, not SQL-side JSON validation or bounded work.
func memoryParsedJSONFits(value any) bool {
	raw, err := json.Marshal(value)
	return err == nil && len(raw) <= 32<<20
}

// The legacy operations tag omits completed empty arrays. Typed copies
// preserve their distinction from unfinished projections and detach fields.
func cloneMemoryOpenAPIContract(c domain.OpenAPIContract) domain.OpenAPIContract {
	c.Operations = slices.Clone(c.Operations)
	for i := range c.Operations {
		c.Operations[i].RequiredRequestFields = slices.Clone(c.Operations[i].RequiredRequestFields)
		c.Operations[i].ResponseStatuses = slices.Clone(c.Operations[i].ResponseStatuses)
	}
	return c
}
