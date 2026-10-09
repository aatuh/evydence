package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

var (
	_ evidenceapp.SBOMDiffReader     = memoryEvidenceRepository{}
	_ evidenceapp.ContractDiffReader = memoryEvidenceRepository{}
)

// Typed fixture readers mirror native coordinate/projection separation. They
// never consult Ledger and do not model SQL JSON shape checks or share locks.
func memorySBOMDiffSubject(s *MemoryUnitOfWorkSnapshot, tenant, id string) (evidenceapp.SBOMDiffSubject, error) {
	b, ok := s.SBOMs[id]
	if !ok || b.ID != id || b.TenantID != tenant {
		return evidenceapp.SBOMDiffSubject{}, ErrNotFound
	}
	e, ok := s.Evidence[b.EvidenceID]
	if !ok || e.ID != b.EvidenceID || e.TenantID != tenant || e.Type != "sbom" || b.ReleaseID != e.ReleaseID {
		return evidenceapp.SBOMDiffSubject{}, ErrNotFound
	}
	if !memoryMembershipQueryText(b.EvidenceID, 1024) || !memoryGovernanceText(b.ArtifactID, 1024) || strings.TrimSpace(b.ArtifactID) != b.ArtifactID {
		return evidenceapp.SBOMDiffSubject{}, ErrValidation
	}
	foundArtifact := false
	for _, ref := range e.SubjectRefs {
		if ref.Type != "artifact" || ref.ID == "" {
			continue
		}
		if ref.ID != b.ArtifactID {
			return evidenceapp.SBOMDiffSubject{}, ErrNotFound
		}
		foundArtifact = true
	}
	if b.ArtifactID != "" {
		a, ok := s.Artifacts[b.ArtifactID]
		if !foundArtifact || !ok || a.ID != b.ArtifactID || a.TenantID != tenant {
			return evidenceapp.SBOMDiffSubject{}, ErrNotFound
		}
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
	if err != nil {
		return evidenceapp.SBOMDiffSubject{}, err
	}
	// Resolved build/deployment parents verify ownership, not parsed release identity.
	return evidenceapp.SBOMDiffSubject{ID: id, TenantID: tenant, EvidenceID: b.EvidenceID, Resources: application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: e.ReleaseID, ArtifactID: b.ArtifactID}}, nil
}
func (r memoryEvidenceRepository) ReadSBOMDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.SBOMDiffSubject, error) {
	var out evidenceapp.SBOMDiffSubject
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memorySBOMDiffSubject(s, tenant, id)
		return err
	})
	if err != nil {
		return evidenceapp.SBOMDiffSubject{}, err
	}
	return out, nil
}

func (r memoryEvidenceRepository) ReadSBOMDiffComponents(ctx context.Context, tenant, id string) ([]evidencedomain.SBOMComponent, error) {
	var out []evidencedomain.SBOMComponent
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		if _, err := memorySBOMDiffSubject(s, tenant, id); err != nil {
			return err
		}
		b := s.SBOMs[id]
		if len(b.Components) > evidenceapp.SBOMDiffComponentLimit || b.ComponentCount != len(b.Components) {
			return ErrValidation
		}
		remaining := evidenceapp.SBOMDiffProjectionByteLimit
		for _, c := range b.Components {
			for _, text := range []string{c.Identity, c.Name, c.Version, c.PURL} {
				if len(text) > remaining {
					return ErrValidation
				}
				remaining -= len(text)
			}
		}
		raw, err := json.Marshal(b.Components)
		if err != nil || len(raw) > evidenceapp.SBOMDiffProjectionByteLimit {
			return ErrValidation
		}
		out = make([]evidencedomain.SBOMComponent, 0, len(b.Components))
		for _, c := range b.Components {
			out = append(out, evidencedomain.SBOMComponent(c))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func memoryContractDiffRelease(s *MemoryUnitOfWorkSnapshot, tenant, id string) (evidenceapp.ContractDiffRelease, error) {
	r, ok := s.Releases[id]
	if !ok || r.ID != id || r.TenantID != tenant {
		return evidenceapp.ContractDiffRelease{}, ErrNotFound
	}
	if !memoryMembershipQueryText(r.ProductID, 1024) {
		return evidenceapp.ContractDiffRelease{}, ErrValidation
	}
	p, ok := s.Products[r.ProductID]
	if !ok || p.ID != r.ProductID || p.TenantID != tenant {
		return evidenceapp.ContractDiffRelease{}, ErrNotFound
	}
	return evidenceapp.ContractDiffRelease{ID: id, TenantID: tenant, ProductID: r.ProductID}, nil
}
func (r memoryEvidenceRepository) ReadContractDiffRelease(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffRelease, error) {
	var out evidenceapp.ContractDiffRelease
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryContractDiffRelease(s, tenant, id)
		return err
	})
	if err != nil {
		return evidenceapp.ContractDiffRelease{}, err
	}
	return out, nil
}
func memoryContractDiffSubject(s *MemoryUnitOfWorkSnapshot, tenant, id string) (evidenceapp.ContractDiffSubject, error) {
	c, ok := s.OpenAPIContracts[id]
	if !ok || c.ID != id || c.TenantID != tenant {
		return evidenceapp.ContractDiffSubject{}, ErrNotFound
	}
	for _, text := range []string{c.ProductID, c.EvidenceID} {
		if !memoryMembershipQueryText(text, 1024) {
			return evidenceapp.ContractDiffSubject{}, ErrValidation
		}
	}
	if !memoryGovernanceText(c.ReleaseID, 1024) || strings.TrimSpace(c.ReleaseID) != c.ReleaseID {
		return evidenceapp.ContractDiffSubject{}, ErrValidation
	}
	e, ok := s.Evidence[c.EvidenceID]
	if !ok || e.ID != c.EvidenceID || e.TenantID != tenant || e.Type != "openapi_contract" || e.ProductID != "" && e.ProductID != c.ProductID || e.ReleaseID != "" && e.ReleaseID != c.ReleaseID {
		return evidenceapp.ContractDiffSubject{}, ErrNotFound
	}
	if _, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: c.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID}); err != nil {
		return evidenceapp.ContractDiffSubject{}, err
	}
	if c.ReleaseID != "" {
		release, err := memoryContractDiffRelease(s, tenant, c.ReleaseID)
		if err != nil {
			return evidenceapp.ContractDiffSubject{}, err
		}
		if release.ProductID != c.ProductID {
			return evidenceapp.ContractDiffSubject{}, ErrNotFound
		}
	}
	return evidenceapp.ContractDiffSubject{ID: id, TenantID: tenant, ProductID: c.ProductID, ReleaseID: c.ReleaseID, EvidenceID: c.EvidenceID}, nil
}
func (r memoryEvidenceRepository) ReadContractDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffSubject, error) {
	var out evidenceapp.ContractDiffSubject
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryContractDiffSubject(s, tenant, id)
		return err
	})
	if err != nil {
		return evidenceapp.ContractDiffSubject{}, err
	}
	return out, nil
}
func (r memoryEvidenceRepository) ReadContractDiffProjection(ctx context.Context, tenant, id string) (evidencedomain.OpenAPIContract, error) {
	var out evidencedomain.OpenAPIContract
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		subject, err := memoryContractDiffSubject(s, tenant, id)
		if err != nil {
			return err
		}
		c := s.OpenAPIContracts[id]
		if len(c.Hash) > 71 || len(c.Operations) > evidenceapp.ContractDiffOperationLimit {
			return ErrValidation
		}
		// Precheck a conservative unescaped byte budget before encoding; the
		// encoded JSON check additionally accounts for escapes and field names.
		remaining := evidenceapp.ContractDiffProjectionByteLimit
		consume := func(v string) bool {
			if len(v) > remaining {
				return false
			}
			remaining -= len(v)
			return true
		}
		for _, op := range c.Operations {
			if remaining < 64 {
				return ErrValidation
			}
			remaining -= 64
			for _, text := range []string{op.Path, op.Method, op.OperationID} {
				if !consume(text) {
					return ErrValidation
				}
			}
			for _, values := range [][]string{op.RequiredRequestFields, op.ResponseStatuses} {
				for _, text := range values {
					if remaining < 8 {
						return ErrValidation
					}
					remaining -= 8
					if !consume(text) {
						return ErrValidation
					}
				}
			}
		}
		raw, err := json.Marshal(c.Operations)
		if err != nil || len(raw) > evidenceapp.ContractDiffProjectionByteLimit {
			return ErrValidation
		}
		out = evidencedomain.OpenAPIContract{ID: subject.ID, TenantID: subject.TenantID, ProductID: subject.ProductID, ReleaseID: subject.ReleaseID, EvidenceID: subject.EvidenceID, Hash: c.Hash, PathCount: c.PathCount, Operations: make([]evidencedomain.OpenAPIOperation, 0, len(c.Operations))}
		for _, op := range c.Operations {
			v := evidencedomain.OpenAPIOperation(op)
			v.RequiredRequestFields = slices.Clone(op.RequiredRequestFields)
			v.ResponseStatuses = slices.Clone(op.ResponseStatuses)
			out.Operations = append(out.Operations, v)
		}
		return nil
	})
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	return out, nil
}
