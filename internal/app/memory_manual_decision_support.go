package app

import (
	"context"
	"strings"

	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func (r memoryDecisionRepository) ValidateDecisionSupportingReference(ctx context.Context, tenant, product, release string, ref riskdomain.SupportingReference) error {
	if !memoryMembershipQueryText(product, 1024) || !memoryMembershipQueryText(release, 1024) || !memoryGovernanceText(ref.Digest, 128) || strings.TrimSpace(ref.Digest) != "" {
		return ErrValidation
	}
	return memoryGovernanceRead(ctx, r.uow, tenant, ref.ID, func(s *MemoryUnitOfWorkSnapshot) error {
		if _, err := memoryGovernanceProductRelease(s, tenant, product, release); err != nil {
			return err
		}
		if !memoryDecisionSupportingOwned(s, tenant, product, release, ref.Type, ref.ID) {
			return ErrNotFound
		}
		return ctx.Err()
	})
}

func memoryDecisionSupportingOwned(s *MemoryUnitOfWorkSnapshot, tenant, product, release, kind, id string) bool {
	evidenceOwned := func(id string) bool {
		if id == "" {
			return true
		}
		_, err := memoryGovernanceEvidence(s, tenant, id, s.Evidence[id].Type)
		return err == nil
	}
	incidentOwned := func(id string) bool {
		v, ok := s.Incidents[id]
		return ok && v.ID == id && v.TenantID == tenant && v.ProductID == product && v.ReleaseID == release
	}
	waiverOwned := func(id string) bool {
		v, ok := s.Waivers[id]
		return ok && v.ID == id && v.TenantID == tenant && (v.ScopeType == "product" && v.ScopeID == product || v.ScopeType == "release" && v.ScopeID == release)
	}
	switch kind {
	case "exception":
		v, ok := s.Exceptions[id]
		return ok && v.ID == id && v.TenantID == tenant && v.ReleaseID == release
	case "waiver":
		return waiverOwned(id)
	case "incident":
		return incidentOwned(id)
	case "release_bundle":
		v, ok := s.ReleaseBundles[id]
		return ok && v.ID == id && v.TenantID == tenant && v.ReleaseID == release
	case "remediation_task":
		v, ok := s.RemediationTasks[id]
		return ok && v.ID == id && v.TenantID == tenant && evidenceOwned(v.EvidenceID) && (v.IncidentID == "" || incidentOwned(v.IncidentID)) && (v.ReleaseID == "" || v.ReleaseID == release) && (v.ReleaseID == release || v.IncidentID != "" && incidentOwned(v.IncidentID))
	case "approval":
		v, ok := s.Approvals[id]
		if !ok || v.ID != id || v.TenantID != tenant || !evidenceOwned(v.EvidenceID) {
			return false
		}
		switch v.SubjectType {
		case "release":
			return v.SubjectID == release
		case "waiver":
			return waiverOwned(v.SubjectID)
		case "customer_package":
			p, ok := s.CustomerPackages[v.SubjectID]
			profile, profileOK := s.RedactionProfiles[p.RedactionProfileID]
			return ok && p.ID == v.SubjectID && p.TenantID == tenant && p.ProductID == product && p.ReleaseID == release && profileOK && profile.ID == p.RedactionProfileID && profile.TenantID == tenant
		case "security_review":
			d, ok := s.ManualSecurityDocuments[v.SubjectID]
			if !ok || d.ID != v.SubjectID || d.TenantID != tenant || d.DocumentType != "security_review" || d.ProductID != product || d.ReleaseID != release {
				return false
			}
			e, err := memoryGovernanceEvidence(s, tenant, d.EvidenceID, "security_review")
			return err == nil && (e.ProductID == "" || e.ProductID == product) && (e.ReleaseID == "" || e.ReleaseID == release)
		case "contract_diff":
			d, ok := s.ContractDiffs[v.SubjectID]
			if !ok || d.ID != v.SubjectID || d.TenantID != tenant || d.ProductID != product || d.ReleaseID != release {
				return false
			}
			for _, id := range []string{d.BaseContractID, d.TargetContractID} {
				c, ok := s.OpenAPIContracts[id]
				if !ok || c.ID != id || c.TenantID != tenant || c.ProductID != product {
					return false
				}
				if _, err := memoryGovernanceProductRelease(s, tenant, product, c.ReleaseID); err != nil {
					return false
				}
				e, err := memoryGovernanceEvidence(s, tenant, c.EvidenceID, "openapi_contract")
				if err != nil || e.ProductID != "" && e.ProductID != product || c.ReleaseID != "" && e.ReleaseID != "" && c.ReleaseID != e.ReleaseID {
					return false
				}
			}
			return true
		}
	}
	return false
}
