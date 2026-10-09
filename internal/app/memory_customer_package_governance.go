package app

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type memoryCustomerPackageGovernance struct {
	Decisions, Approvals, Exceptions, Waivers, AnswerLibrary []map[string]any
}

// One read-only fixture component. The complete reader must combine this with
// the other components in one typed view, using the same generation time and
// metadata budget. No Ledger caches or referenced private documents are read.
func readMemoryCustomerPackageGovernance(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, profile packagedomain.RedactionProfile, at time.Time, budget *memoryCustomerSnapshotBudget) (memoryCustomerPackageGovernance, error) {
	var empty memoryCustomerPackageGovernance
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return empty, err
	}
	at = at.UTC()
	if profile.TenantID != tenant || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return empty, ErrValidation
	}
	g := memoryCustomerGovernanceScope{ctx: ctx, rows: s, tenant: tenant, product: product, release: release}
	working := *budget
	out := memoryCustomerPackageGovernance{}
	if packageapp.CustomerPackageIncludesType(profile, "vulnerability_decision") {
		values := []packagedomain.VulnerabilityDecisionSnapshot{}
		for key, d := range s.Decisions {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			value, owned, err := readMemoryCustomerDecision(g, key, d, &working)
			if err != nil {
				return empty, err
			}
			if owned {
				if len(values) == packageapp.MaxSecurityReviewEvidenceIDs {
					return empty, ErrConflict
				}
				values = append(values, value)
			}
		}
		out.Decisions = packageapp.CustomerPackageDecisionSummaries(values, profile)
	}
	for key, a := range s.Approvals {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if a.ID != key || a.TenantID != tenant || !g.subject(a.SubjectType, a.SubjectID) || !g.evidence(a.EvidenceID, true) {
			continue
		}
		row := map[string]any{"id": a.ID, "subject_type": a.SubjectType, "subject_id": a.SubjectID, "decision": a.Decision, "reason": a.Reason, "evidence_id": a.EvidenceID}
		if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": a.CreatedAt}, nil); err != nil {
			return empty, err
		}
		if err := appendMemoryCustomerMetadata(&out.Approvals, row, &working); err != nil {
			return empty, err
		}
	}
	if release != "" {
		for key, x := range s.Exceptions {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			if x.ID != key || x.TenantID != tenant || x.ReleaseID != release || !x.Approved || !x.ExpiresAt.After(at) {
				continue
			}
			owned, err := g.exception(key)
			if err != nil {
				return empty, err
			}
			if !owned {
				continue
			}
			row := map[string]any{"id": x.ID, "release_id": x.ReleaseID, "finding_id": x.FindingID, "control_id": x.ControlID, "reason": x.Reason, "owner": x.Owner, "approved": x.Approved}
			if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": x.CreatedAt, "expires_at": x.ExpiresAt}, map[string]*time.Time{"approved_at": x.ApprovedAt}); err != nil {
				return empty, err
			}
			if err := appendMemoryCustomerMetadata(&out.Exceptions, row, &working); err != nil {
				return empty, err
			}
		}
	}
	for key, w := range s.Waivers {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if w.ID != key || w.TenantID != tenant || !w.Approved || !w.ExpiresAt.After(at) || !g.waiver(key) {
			continue
		}
		row := map[string]any{"id": w.ID, "scope_type": w.ScopeType, "scope_id": w.ScopeID, "control_id": w.ControlID, "policy_id": w.PolicyID, "owner": w.Owner, "risk": w.Risk, "reason": w.Reason, "approved": w.Approved}
		if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": w.CreatedAt, "expires_at": w.ExpiresAt}, map[string]*time.Time{"approved_at": w.ApprovedAt}); err != nil {
			return empty, err
		}
		if err := appendMemoryCustomerMetadata(&out.Waivers, row, &working); err != nil {
			return empty, err
		}
	}
	for key, a := range s.AnswerLibrary {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if a.ID != key || a.TenantID != tenant || a.ProductID != "" && a.ProductID != product || a.ReleaseID != "" && a.ReleaseID != release || !g.control(a.ControlID) {
			continue
		}
		if len(a.EvidenceIDs) > packageapp.MaxSecurityReviewEvidenceIDs || len(a.Limitations) > packageapp.MaxSecurityReviewEvidenceIDs {
			return empty, ErrConflict
		}
		owned := true
		for _, id := range a.EvidenceIDs {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			owned = owned && g.evidence(id, false)
		}
		if !owned {
			continue
		}
		row := map[string]any{"id": a.ID, "question_id": a.QuestionID, "evidence_type": a.EvidenceType, "control_id": a.ControlID, "product_id": a.ProductID, "release_id": a.ReleaseID, "answer": a.Answer, "evidence_ids": a.EvidenceIDs, "limitations": a.Limitations}
		if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": a.CreatedAt}, nil); err != nil {
			return empty, err
		}
		if err := appendMemoryCustomerMetadata(&out.AnswerLibrary, row, &working); err != nil {
			return empty, err
		}
		row["evidence_ids"], row["limitations"] = slices.Clone(a.EvidenceIDs), slices.Clone(a.Limitations)
	}
	for _, rows := range [][]map[string]any{out.Approvals, out.Exceptions, out.Waivers, out.AnswerLibrary} {
		sortMemoryCustomerMetadata(rows)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*budget = working
	return out, nil
}

func memoryCustomerMetadataTimes(row map[string]any, required map[string]time.Time, optional map[string]*time.Time) error {
	for key, at := range required {
		text, err := memoryCustomerSnapshotTime(at)
		if err != nil {
			return err
		}
		row[key] = text
	}
	for key, at := range optional {
		if at == nil {
			continue
		}
		text, err := memoryCustomerSnapshotTime(*at)
		if err != nil {
			return err
		}
		row[key] = text
	}
	return nil
}

func readMemoryCustomerDecision(g memoryCustomerGovernanceScope, key string, d domain.VulnerabilityDecision, budget *memoryCustomerSnapshotBudget) (packagedomain.VulnerabilityDecisionSnapshot, bool, error) {
	var empty packagedomain.VulnerabilityDecisionSnapshot
	if d.ID != key || d.TenantID != g.tenant || d.ReleaseID != g.release || !d.CustomerVisible || d.SupersededBy != "" {
		return empty, false, nil
	}
	scan, owned := g.scan(d.ScanID)
	if !owned {
		return empty, false, nil
	}
	count, matches := 0, false
	for _, f := range scan.Findings {
		if err := g.ctx.Err(); err != nil {
			return empty, false, err
		}
		if f.ID == d.FindingID {
			count++
			matches = f.Vulnerability == d.Vulnerability && f.Component == d.Component
			if count > 1 {
				break
			}
		}
	}
	if count != 1 || !matches {
		return empty, false, nil
	}
	if len(d.EvidenceIDs) > packageapp.MaxSecurityReviewEvidenceIDs || len(d.SupportingRefs) > packageapp.MaxSecurityReviewEvidenceIDs || !memoryCustomerSnapshotID(d.ID, false) {
		return empty, false, ErrConflict
	}
	if !g.evidence(d.EvidenceID, true) {
		return empty, false, nil
	}
	for _, id := range d.EvidenceIDs {
		if err := g.ctx.Err(); err != nil {
			return empty, false, err
		}
		if !memoryCustomerSnapshotID(id, false) {
			return empty, false, ErrConflict
		}
		if !g.evidence(id, false) {
			return empty, false, nil
		}
	}
	for _, part := range []struct{ kind, id string }{{"sbom", d.SBOMID}, {"vex", d.VEXDocumentID}} {
		owned, err := g.parsed(part.kind, part.id)
		if err != nil || !owned {
			return empty, false, err
		}
	}
	refs := make([]map[string]any, 0, len(d.SupportingRefs))
	values := make([]packagedomain.SupportingReference, 0, len(d.SupportingRefs))
	for _, ref := range d.SupportingRefs {
		if err := g.ctx.Err(); err != nil {
			return empty, false, err
		}
		if !memoryCustomerSnapshotID(ref.ID, false) || !memoryCustomerSnapshotID(ref.Type, false) || !memoryGovernanceText(ref.Digest, 1024) {
			return empty, false, ErrConflict
		}
		owned, err := g.supporting(ref)
		if err != nil || !owned {
			return empty, false, err
		}
		refs = append(refs, map[string]any{"type": ref.Type, "id": ref.ID, "digest": ref.Digest})
		values = append(values, packagedomain.SupportingReference{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
	}
	row := map[string]any{"id": d.ID, "finding_id": d.FindingID, "scan_id": d.ScanID, "release_id": d.ReleaseID, "vulnerability": d.Vulnerability, "component": d.Component, "sbom_id": d.SBOMID, "sbom_component_purl": d.SBOMComponentPURL, "sbom_component_name": d.SBOMComponentName, "status": d.Status, "justification": d.Justification, "impact_statement": d.ImpactStatement, "action_statement": d.ActionStatement, "source": d.Source, "evidence_id": d.EvidenceID, "evidence_ids": d.EvidenceIDs, "vex_document_id": d.VEXDocumentID, "supporting_refs": refs}
	if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": d.CreatedAt}, map[string]*time.Time{"reviewed_at": d.ReviewedAt, "review_due_at": d.ReviewDueAt}); err != nil {
		return empty, false, err
	}
	if err := budget.charge(row); err != nil {
		return empty, false, err
	}
	// The shared renderer detaches public collections. The projection contains
	// neither InternalNotes nor ApprovedBy and cannot expose those identities.
	v := packagedomain.VulnerabilityDecisionSnapshot{ID: d.ID, FindingID: d.FindingID, ScanID: d.ScanID, ReleaseID: d.ReleaseID, Vulnerability: d.Vulnerability, Component: d.Component, SBOMID: d.SBOMID, SBOMComponentPURL: d.SBOMComponentPURL, SBOMComponentName: d.SBOMComponentName, Status: d.Status, Justification: d.Justification, ImpactStatement: d.ImpactStatement, ActionStatement: d.ActionStatement, Source: d.Source, EvidenceID: d.EvidenceID, EvidenceIDs: d.EvidenceIDs, SupportingRefs: values, VEXDocumentID: d.VEXDocumentID, ReviewedAt: d.ReviewedAt, ReviewDueAt: d.ReviewDueAt, CreatedAt: d.CreatedAt}
	return v, true, nil
}
