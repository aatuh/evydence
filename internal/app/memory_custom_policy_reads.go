package app

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ riskapp.CustomPolicyReader = memoryRiskRepository{}

func (r memoryRiskRepository) PolicyTenantExists(ctx context.Context, tenant string) (bool, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(tenant, 1024) {
		return false, ErrValidation
	}
	var exists bool
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.Tenants[tenant]
		exists = ok && v.ID == tenant
		return nil
	})
	return exists, err
}

func (r memoryRiskRepository) ReadCustomPolicySubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	if kind != "policy" && kind != "release" {
		return riskapp.GovernanceSubjectReference{}, ErrValidation
	}
	return memoryGovernanceRepository(r).ReadWaiverSubject(ctx, tenant, kind, id)
}

// Selected policy metadata is bounded and detached from the current memory
// transaction. This test model does not select a Ledger or SQL row-lock proof.
func (r memoryRiskRepository) ReadCustomPolicy(ctx context.Context, tenant, id string) (riskdomain.CustomPolicy, error) {
	var out riskdomain.CustomPolicy
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.CustomPolicies[id]
		if !ok || p.ID != id || p.TenantID != tenant {
			return ErrNotFound
		}
		for _, text := range []string{p.Name, p.Version, p.SchemaVersion} {
			if !memoryGovernanceText(text, 1024) {
				return ErrValidation
			}
		}
		if !memoryGovernanceText(p.Description, 65536) || len(p.Rules) == 0 || len(p.Rules) > 4096 {
			return ErrValidation
		}
		budget := 8 << 20
		for _, rule := range p.Rules {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !memoryGovernanceText(rule.Name, 65536) || !memoryGovernanceText(rule.Severity, 128) || !memoryGovernanceText(rule.EvidenceType, 128) {
				return ErrValidation
			}
			budget -= len(rule.Name) + len(rule.Severity) + len(rule.EvidenceType)
			if budget < 0 {
				return ErrValidation
			}
		}
		encoded, err := json.Marshal(p.Rules)
		// Conservatively account for JSONB colon/comma spaces as well as Go
		// escaping. Typed records cannot represent arbitrary SQL JSON shapes.
		if err != nil || len(encoded)+8*len(p.Rules)-1 > 8<<20 {
			return ErrValidation
		}
		p.Rules = append([]domain.PolicyRule(nil), p.Rules...)
		p.CreatedAt = p.CreatedAt.UTC()
		out = domain.CustomPolicyToContext(p)
		return nil
	})
	if err != nil {
		return riskdomain.CustomPolicy{}, err
	}
	return out, nil
}

func (r memoryRiskRepository) ReadCustomPolicyEvidencePresence(ctx context.Context, tenant, release string, types []string) (map[string]bool, error) {
	if len(types) > 19 {
		return nil, ErrValidation
	}
	result := make(map[string]bool, len(types))
	for _, kind := range types {
		if _, duplicate := result[kind]; duplicate || !riskdomain.ValidPolicyEvidenceType(kind) {
			return nil, ErrValidation
		}
		result[kind] = false
	}
	err := memoryGovernanceRead(ctx, r.uow, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		for id, e := range s.Evidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.TenantID != tenant || e.ReleaseID != release {
				continue
			}
			if _, requested := result[e.Type]; !requested {
				continue
			}
			_, err := memoryGovernanceEvidence(s, tenant, id, e.Type)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			result[e.Type] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
