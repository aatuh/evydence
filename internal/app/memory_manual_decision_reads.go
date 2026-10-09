package app

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ riskapp.VulnerabilityDecisionReader = memoryDecisionRepository{}

// Typed coordinates model current native read policy, not PostgreSQL JSON
// shape, query work/transfer, projection fences, row locks or durability.
func (r memoryDecisionRepository) ReadDecisionFinding(ctx context.Context, tenant, id string) (riskapp.FindingReference, error) {
	var out riskapp.FindingReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		return readMemoryDecisionFinding(ctx, s, tenant, id, &out)
	})
	if err != nil {
		return riskapp.FindingReference{}, err
	}
	return out, nil
}

func memoryDecisionParsedOwner(s *MemoryUnitOfWorkSnapshot, tenant, source, kind, release, artifact string) (riskapp.GovernanceSubjectReference, error) {
	owner, err := memoryGovernanceEvidence(s, tenant, source, kind)
	if err != nil {
		return owner, err
	}
	if release != "" && owner.ReleaseID != "" && release != owner.ReleaseID {
		return riskapp.GovernanceSubjectReference{}, ErrNotFound
	}
	release = nonEmpty(release, owner.ReleaseID)
	if release != "" {
		r, ok := s.Releases[release]
		if !ok || r.ID != release || r.TenantID != tenant || owner.ProductID != "" && owner.ProductID != r.ProductID {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		owner, err = memoryGovernanceProductRelease(s, tenant, r.ProductID, release)
		if err != nil {
			return owner, err
		}
	}
	if artifact != "" {
		a, ok := s.Artifacts[artifact]
		if !ok || a.ID != artifact || a.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
	}
	return owner, nil
}

func memoryDecisionSBOMContext(ctx context.Context, s *MemoryUnitOfWorkSnapshot, f *riskapp.FindingReference) error {
	component := strings.TrimSpace(f.Component)
	if component == "" {
		return ctx.Err()
	}
	var selected domain.SBOM
	var selectedComponent domain.SBOMComponent
	priority := 2
	for key, b := range s.SBOMs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if key != b.ID || b.TenantID != f.TenantID {
			continue
		}
		owner, err := memoryDecisionParsedOwner(s, f.TenantID, b.EvidenceID, "sbom", b.ReleaseID, b.ArtifactID)
		if err != nil || owner.ProductID != f.ProductID || owner.ReleaseID != f.ReleaseID {
			continue
		}
		for _, c := range b.Components {
			if err := ctx.Err(); err != nil {
				return err
			}
			purl, name, version := strings.TrimSpace(c.PURL), strings.TrimSpace(c.Name), strings.TrimSpace(c.Version)
			rank := 2
			if purl != "" && purl == component {
				rank = 0
			} else if name == component || version != "" && name+"@"+version == component {
				rank = 1
			}
			if rank >= 2 || rank > priority || rank == priority && (b.CreatedAt.After(selected.CreatedAt) || b.CreatedAt.Equal(selected.CreatedAt) && b.ID >= selected.ID) {
				continue
			}
			selected, selectedComponent, priority = b, c, rank
		}
	}
	if priority == 2 {
		return ctx.Err()
	}
	if !memoryGovernanceText(selected.ID, 1024) || !memoryGovernanceText(selectedComponent.PURL, 1024) || !memoryGovernanceText(selectedComponent.Name, 65536) || !memoryGovernanceText(selectedComponent.Version, len(selectedComponent.Version)) {
		return ErrValidation
	}
	f.SBOMID, f.SBOMComponentPURL, f.SBOMComponentName = selected.ID, strings.TrimSpace(selectedComponent.PURL), strings.TrimSpace(selectedComponent.Name)
	return ctx.Err()
}

func (r memoryDecisionRepository) ReadDecisionEvidence(ctx context.Context, tenant, id string) (riskapp.DecisionEvidenceReference, error) {
	var out riskapp.DecisionEvidenceReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		owner, err := memoryGovernanceEvidence(s, tenant, id, s.Evidence[id].Type)
		if err != nil {
			return err
		}
		out = riskapp.DecisionEvidenceReference{ID: id, TenantID: tenant, ProductID: owner.ProductID, ReleaseID: owner.ReleaseID}
		return ctx.Err()
	})
	if err != nil {
		return riskapp.DecisionEvidenceReference{}, err
	}
	return out, nil
}

func (r memoryDecisionRepository) ReadDecisionVEX(ctx context.Context, tenant, id string) (riskapp.DecisionVEXReference, error) {
	var out riskapp.DecisionVEXReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.VEXDocuments[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.EvidenceID, 1024) {
			return ErrValidation
		}
		owner, err := memoryDecisionParsedOwner(s, tenant, v.EvidenceID, "vex", v.ReleaseID, v.ArtifactID)
		if err != nil {
			return err
		}
		out = riskapp.DecisionVEXReference{ID: id, TenantID: tenant, ProductID: owner.ProductID, ReleaseID: owner.ReleaseID, EvidenceID: v.EvidenceID}
		return ctx.Err()
	})
	if err != nil {
		return riskapp.DecisionVEXReference{}, err
	}
	return out, nil
}

func (r memoryDecisionRepository) ReadActiveDecisionHeads(ctx context.Context, tenant, finding string, limit int) ([]riskapp.ActiveDecisionHead, error) {
	if limit < 1 || limit > 129 {
		return nil, ErrValidation
	}
	var out []riskapp.ActiveDecisionHead
	err := memoryGovernanceRead(ctx, r.uow, tenant, finding, func(s *MemoryUnitOfWorkSnapshot) error {
		return readMemoryActiveDecisionHeads(ctx, s, tenant, finding, limit, &out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readMemoryDecisionFinding(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, id string, out *riskapp.FindingReference) error {
	count := 0
	for key, scan := range s.VulnerabilityScans {
		if err := ctx.Err(); err != nil {
			return err
		}
		if key != scan.ID || scan.TenantID != tenant {
			continue
		}
		for _, f := range scan.Findings {
			if err := ctx.Err(); err != nil {
				return err
			}
			if f.ID != id {
				continue
			}
			owner, err := memoryDecisionParsedOwner(s, tenant, scan.EvidenceID, "vulnerability_scan", scan.ReleaseID, "")
			if err != nil || owner.ReleaseID == "" {
				if errors.Is(err, ErrValidation) {
					return err
				}
				continue
			}
			for _, text := range []string{scan.ID, owner.ProductID, owner.ReleaseID, s.Evidence[scan.EvidenceID].ProjectID, f.Vulnerability, f.Component} {
				if !memoryGovernanceText(text, 1024) {
					return ErrValidation
				}
			}
			if strings.TrimSpace(f.Vulnerability) == "" || !memoryGovernanceText(f.Severity, 128) || !memoryGovernanceText(f.State, 128) {
				return ErrValidation
			}
			count++
			if count > 1 {
				return ErrConflict
			}
			*out = riskapp.FindingReference{ID: id, TenantID: tenant, ScanID: scan.ID, ProductID: owner.ProductID, ProjectID: s.Evidence[scan.EvidenceID].ProjectID, ReleaseID: owner.ReleaseID, Vulnerability: f.Vulnerability, Component: f.Component, Severity: f.Severity, State: f.State}
		}
	}
	if count == 0 {
		return ErrNotFound
	}
	return memoryDecisionSBOMContext(ctx, s, out)
}

func readMemoryActiveDecisionHeads(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, finding string, limit int, out *[]riskapp.ActiveDecisionHead) error {
	ids := make([]string, 0, limit)
	for id, v := range s.Decisions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if v.TenantID != tenant || v.FindingID != finding || v.SupersededBy != "" {
			continue
		}
		position := sort.SearchStrings(ids, id)
		if position >= limit {
			continue
		}
		if len(ids) < limit {
			ids = append(ids, "")
		}
		copy(ids[position+1:], ids[position:])
		ids[position] = id
	}
	*out = make([]riskapp.ActiveDecisionHead, 0, len(ids))
	for _, id := range ids {
		v := s.Decisions[id]
		if v.ID != id {
			return ErrConflict
		}
		for _, text := range []string{v.ID, v.ScanID, v.ReleaseID} {
			if !memoryGovernanceText(text, 1024) {
				return ErrValidation
			}
		}
		if !memoryGovernanceText(v.Status, 128) {
			return ErrValidation
		}
		status, err := riskdomain.ParseDecisionStatus(v.Status)
		if err != nil {
			return ErrConflict
		}
		*out = append(*out, riskapp.ActiveDecisionHead{ID: id, TenantID: tenant, FindingID: finding, ScanID: v.ScanID, ReleaseID: v.ReleaseID, Status: status})
	}
	return ctx.Err()
}
