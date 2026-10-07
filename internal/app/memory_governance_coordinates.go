package app

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func memoryGovernanceText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// The memory adapter protects its transaction snapshot, not SQL row locks.
// These reads never construct or consult Ledger or its compatibility maps.
func memoryGovernanceRead(ctx context.Context, tx *memoryUnitOfWork, tenant, id string, read func(*MemoryUnitOfWorkSnapshot) error) error {
	if ctx == nil || tx == nil || read == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, value := range []string{tenant, id} {
		if value == "" || strings.TrimSpace(value) != value || !memoryGovernanceText(value, 1024) {
			return ErrValidation
		}
	}
	return tx.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, tenant); err != nil {
			return err
		}
		return read(state)
	})
}

func memoryGovernanceProductRelease(state *MemoryUnitOfWorkSnapshot, tenant, product, release string) (riskapp.GovernanceSubjectReference, error) {
	if product == "" || !memoryGovernanceText(product, 1024) || !memoryGovernanceText(release, 1024) {
		return riskapp.GovernanceSubjectReference{}, ErrValidation
	}
	p, ok := state.Products[product]
	if !ok || p.ID != product || p.TenantID != tenant {
		return riskapp.GovernanceSubjectReference{}, ErrNotFound
	}
	if release != "" {
		r, ok := state.Releases[release]
		if !ok || r.ID != release || r.TenantID != tenant || r.ProductID != product {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
	}
	return riskapp.GovernanceSubjectReference{TenantID: tenant, ProductID: product, ReleaseID: release}, nil
}

// Match the typed evidence/product/project/release parent agreement used by
// the native governance reader. No payload bytes, hashes or metadata are read.
func memoryGovernanceEvidence(state *MemoryUnitOfWorkSnapshot, tenant, id, kind string) (riskapp.GovernanceSubjectReference, error) {
	e, ok := state.Evidence[id]
	if !ok || e.ID != id || e.TenantID != tenant || e.Type != kind {
		return riskapp.GovernanceSubjectReference{}, ErrNotFound
	}
	product := e.ProductID
	for _, value := range []string{e.ProductID, e.ProjectID, e.ReleaseID} {
		if !memoryGovernanceText(value, 1024) {
			return riskapp.GovernanceSubjectReference{}, ErrValidation
		}
	}
	if e.ProjectID != "" {
		project, ok := state.Projects[e.ProjectID]
		if !ok || project.ID != e.ProjectID || project.TenantID != tenant || project.ProductID == "" || product != "" && project.ProductID != product {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		if _, err := memoryGovernanceProductRelease(state, tenant, project.ProductID, ""); err != nil {
			return riskapp.GovernanceSubjectReference{}, err
		}
		product = project.ProductID
	}
	if e.ReleaseID != "" {
		release, ok := state.Releases[e.ReleaseID]
		if !ok || release.ID != e.ReleaseID || release.TenantID != tenant || product != "" && release.ProductID != product {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		product = release.ProductID
	}
	if product == "" {
		return riskapp.GovernanceSubjectReference{TenantID: tenant}, nil
	}
	return memoryGovernanceProductRelease(state, tenant, product, e.ReleaseID)
}

func memoryGovernanceFinding(state *MemoryUnitOfWorkSnapshot, tenant, id string) (riskapp.GovernanceSubjectReference, error) {
	var found riskapp.GovernanceSubjectReference
	count := 0
	for key, scan := range state.VulnerabilityScans {
		if scan.TenantID != tenant || scan.ID != key {
			continue
		}
		for _, finding := range scan.Findings {
			if finding.ID != id {
				continue
			}
			evidence, err := memoryGovernanceEvidence(state, tenant, scan.EvidenceID, "vulnerability_scan")
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue
				}
				return found, err
			}
			release := scan.ReleaseID
			if release == "" {
				release = evidence.ReleaseID
			}
			if release == "" || evidence.ReleaseID != "" && evidence.ReleaseID != release {
				continue
			}
			r, ok := state.Releases[release]
			if !ok || r.ID != release || r.TenantID != tenant || evidence.ProductID != "" && evidence.ProductID != r.ProductID {
				continue
			}
			owner, err := memoryGovernanceProductRelease(state, tenant, r.ProductID, release)
			if err != nil {
				return found, err
			}
			if strings.TrimSpace(finding.Vulnerability) == "" || !memoryGovernanceText(finding.Vulnerability, 1024) || !memoryGovernanceText(finding.Component, 1024) || !memoryGovernanceText(finding.Severity, 128) || !memoryGovernanceText(finding.State, 128) {
				return found, ErrValidation
			}
			count++
			if count > 1 {
				return riskapp.GovernanceSubjectReference{}, ErrConflict
			}
			found = owner
		}
	}
	if count == 0 {
		return found, ErrNotFound
	}
	return found, nil
}

func memoryGovernanceOwner(state *MemoryUnitOfWorkSnapshot, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	switch kind {
	case "release":
		v, ok := state.Releases[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		return memoryGovernanceProductRelease(state, tenant, v.ProductID, id)
	case "finding":
		return memoryGovernanceFinding(state, tenant, id)
	case "control":
		v, ok := state.SecurityControls[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		framework, ok := state.ControlFrameworks[v.FrameworkID]
		if !ok || framework.ID != v.FrameworkID || framework.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
	case "policy":
		v, ok := state.CustomPolicies[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
	case "waiver":
		v, ok := state.Waivers[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		if !memoryGovernanceText(v.ScopeType, 128) || !memoryGovernanceText(v.ScopeID, 1024) {
			return riskapp.GovernanceSubjectReference{}, ErrValidation
		}
		switch v.ScopeType {
		case "release", "finding", "control", "policy":
			return memoryGovernanceOwner(state, tenant, v.ScopeType, v.ScopeID)
		default:
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
	case "customer_package":
		v, ok := state.CustomerPackages[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		profile, ok := state.RedactionProfiles[v.RedactionProfileID]
		if !ok || profile.ID != v.RedactionProfileID || profile.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		return memoryGovernanceProductRelease(state, tenant, v.ProductID, v.ReleaseID)
	case "security_review":
		v, ok := state.ManualSecurityDocuments[id]
		if !ok || v.ID != id || v.TenantID != tenant || v.DocumentType != "security_review" {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		e, err := memoryGovernanceEvidence(state, tenant, v.EvidenceID, "security_review")
		if err != nil {
			return e, err
		}
		if e.ProductID != "" && e.ProductID != v.ProductID || e.ReleaseID != "" && v.ReleaseID != "" && e.ReleaseID != v.ReleaseID {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		return memoryGovernanceProductRelease(state, tenant, v.ProductID, v.ReleaseID)
	case "contract_diff":
		v, ok := state.ContractDiffs[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskapp.GovernanceSubjectReference{}, ErrNotFound
		}
		for _, id := range []string{v.BaseContractID, v.TargetContractID} {
			c, ok := state.OpenAPIContracts[id]
			if !ok || c.ID != id || c.TenantID != tenant || c.ProductID != v.ProductID {
				return riskapp.GovernanceSubjectReference{}, ErrNotFound
			}
			e, err := memoryGovernanceEvidence(state, tenant, c.EvidenceID, "openapi_contract")
			if err != nil {
				return e, err
			}
			if e.ProductID != "" && e.ProductID != c.ProductID || e.ReleaseID != "" && c.ReleaseID != "" && e.ReleaseID != c.ReleaseID {
				return riskapp.GovernanceSubjectReference{}, ErrNotFound
			}
			if _, err := memoryGovernanceProductRelease(state, tenant, c.ProductID, c.ReleaseID); err != nil {
				return riskapp.GovernanceSubjectReference{}, err
			}
		}
		return memoryGovernanceProductRelease(state, tenant, v.ProductID, v.ReleaseID)
	default:
		return riskapp.GovernanceSubjectReference{}, ErrValidation
	}
	return riskapp.GovernanceSubjectReference{TenantID: tenant}, nil
}
