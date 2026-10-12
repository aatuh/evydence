package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Coordinate-only predicates for one focused fixture snapshot. They never
// inspect referenced approval/incident/control text or raw evidence payloads.
type memoryCustomerGovernanceScope struct {
	ctx                      context.Context
	rows                     *MemoryUnitOfWorkSnapshot
	tenant, product, release string
}

func (g memoryCustomerGovernanceScope) evidence(id string, optional bool) bool {
	if id == "" {
		return optional
	}
	e, ok := g.rows.Evidence[id]
	return ok && memoryCustomerEvidenceInScope(g.rows, id, e, g.tenant, g.product, g.release)
}

func (g memoryCustomerGovernanceScope) control(id string) bool {
	if id == "" {
		return true
	}
	c, ok := g.rows.SecurityControls[id]
	if !ok || c.ID != id || c.TenantID != g.tenant {
		return false
	}
	f, ok := g.rows.ControlFrameworks[c.FrameworkID]
	return ok && f.ID == c.FrameworkID && f.TenantID == g.tenant
}

func (g memoryCustomerGovernanceScope) subject(kind, id string) bool {
	return kind == "product" && id == g.product || g.release != "" && kind == "release" && id == g.release
}

func (g memoryCustomerGovernanceScope) waiver(id string) bool {
	w, ok := g.rows.Waivers[id]
	if !ok || w.ID != id || w.TenantID != g.tenant || !g.subject(w.ScopeType, w.ScopeID) || !g.control(w.ControlID) {
		return false
	}
	if w.PolicyID == "" {
		return true
	}
	p, ok := g.rows.CustomPolicies[w.PolicyID]
	return ok && p.ID == w.PolicyID && p.TenantID == g.tenant
}

func (g memoryCustomerGovernanceScope) scan(id string) (domain.VulnerabilityScan, bool) {
	d, ok := g.rows.VulnerabilityScans[id]
	if !ok || d.ID != id || d.TenantID != g.tenant || d.ReleaseID != g.release {
		return domain.VulnerabilityScan{}, false
	}
	e, ok := g.rows.Evidence[d.EvidenceID]
	owned := ok && e.Type == "vulnerability_scan" && e.ReleaseID == g.release && memoryCustomerEvidenceInScope(g.rows, d.EvidenceID, e, g.tenant, g.product, g.release)
	return d, owned
}

func (g memoryCustomerGovernanceScope) finding(id string) (bool, error) {
	if id == "" {
		return true, nil
	}
	for key := range g.rows.VulnerabilityScans {
		if err := g.ctx.Err(); err != nil {
			return false, err
		}
		d, owned := g.scan(key)
		if !owned {
			continue
		}
		for _, f := range d.Findings {
			if err := g.ctx.Err(); err != nil {
				return false, err
			}
			if f.ID == id {
				return true, nil
			}
		}
	}
	return false, nil
}

func (g memoryCustomerGovernanceScope) exception(id string) (bool, error) {
	x, ok := g.rows.Exceptions[id]
	if !ok || x.ID != id || x.TenantID != g.tenant || x.ReleaseID != g.release || !g.control(x.ControlID) {
		return false, nil
	}
	return g.finding(x.FindingID)
}

func (g memoryCustomerGovernanceScope) approval(id string) bool {
	a, ok := g.rows.Approvals[id]
	if !ok || a.ID != id || a.TenantID != g.tenant || !g.evidence(a.EvidenceID, true) {
		return false
	}
	if g.subject(a.SubjectType, a.SubjectID) {
		return true
	}
	switch a.SubjectType {
	case "waiver":
		return g.waiver(a.SubjectID)
	case "customer_package":
		p, ok := g.rows.CustomerPackages[a.SubjectID]
		if !ok || p.ID != a.SubjectID || p.TenantID != g.tenant || p.ProductID != g.product || p.ReleaseID != g.release {
			return false
		}
		r, ok := g.rows.RedactionProfiles[p.RedactionProfileID]
		return ok && r.ID == p.RedactionProfileID && r.TenantID == g.tenant
	case "contract_diff":
		d, ok := g.rows.ContractDiffs[a.SubjectID]
		return ok && d.ID == a.SubjectID && d.TenantID == g.tenant && d.ProductID == g.product && d.ReleaseID == g.release && memoryCustomerContractOwned(g.rows, g.tenant, g.product, d.BaseContractID) && memoryCustomerContractOwned(g.rows, g.tenant, g.product, d.TargetContractID)
	case "security_review":
		d, ok := g.rows.ManualSecurityDocuments[a.SubjectID]
		if !ok || d.ID != a.SubjectID || d.TenantID != g.tenant || d.DocumentType != "security_review" || d.ProductID != g.product || d.ReleaseID != g.release {
			return false
		}
		e, ok := g.rows.Evidence[d.EvidenceID]
		return ok && e.Type == "security_review" && e.ReleaseID == g.release && memoryCustomerEvidenceInScope(g.rows, d.EvidenceID, e, g.tenant, g.product, g.release)
	default:
		return false
	}
}

func (g memoryCustomerGovernanceScope) incident(id string) bool {
	i, ok := g.rows.Incidents[id]
	return ok && i.ID == id && i.TenantID == g.tenant && i.ProductID == g.product && i.ReleaseID == g.release
}

func (g memoryCustomerGovernanceScope) supporting(ref domain.SubjectRef) (bool, error) {
	switch ref.Type {
	case "approval":
		return g.approval(ref.ID), nil
	case "exception":
		return g.exception(ref.ID)
	case "waiver":
		return g.waiver(ref.ID), nil
	case "release_bundle":
		b, ok := g.rows.ReleaseBundles[ref.ID]
		return g.release != "" && ok && b.ID == ref.ID && b.TenantID == g.tenant && b.ReleaseID == g.release, nil
	case "incident":
		return g.release != "" && g.incident(ref.ID), nil
	case "remediation_task":
		t, ok := g.rows.RemediationTasks[ref.ID]
		if !ok || t.ID != ref.ID || t.TenantID != g.tenant || t.ReleaseID != "" && t.ReleaseID != g.release || !g.evidence(t.EvidenceID, true) || t.IncidentID != "" && !g.incident(t.IncidentID) {
			return false, nil
		}
		return g.release != "" && t.ReleaseID == g.release || t.IncidentID != "", nil
	default:
		return false, nil
	}
}

func (g memoryCustomerGovernanceScope) parsed(kind, id string) (bool, error) {
	if id == "" {
		return true, nil
	}
	var source, artifact string
	switch kind {
	case "sbom":
		d, ok := g.rows.SBOMs[id]
		if !ok || d.ID != id || d.TenantID != g.tenant || d.ReleaseID != g.release {
			return false, nil
		}
		source, artifact = d.EvidenceID, d.ArtifactID
	case "vex":
		d, ok := g.rows.VEXDocuments[id]
		if !ok || d.ID != id || d.TenantID != g.tenant || d.ReleaseID != g.release {
			return false, nil
		}
		source, artifact = d.EvidenceID, d.ArtifactID
	default:
		return false, ErrValidation
	}
	return memoryCustomerParsedPackageSource(g.rows, g.tenant, g.product, g.release, source, kind, artifact)
}
