package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
)

// Enumerate only current owner coordinates, matching the native subject joins.
// Commands require parser provenance/type and artifact parents; historical page
// joins intentionally have their existing weaker metadata-only projection.
// Returning true from visit stops the bounded selection (not an inventory).
func memoryControlSubjectCandidates(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, kind, id string, strict bool, visit func(application.ResourceReferences, time.Time) bool) error {
	emit := func(raw application.ResourceReferences, at time.Time) bool {
		refs, err := memoryOperationsCoordinates(s, tenant, raw)
		if err != nil {
			return false
		}
		return visit(application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}, at)
	}
	evidence := func(eid, source, product, release, artifact string, at time.Time) bool {
		e, ok := s.Evidence[eid]
		if !ok || e.ID != eid || e.TenantID != tenant || strict && source != "" && e.Type != source {
			return false
		}
		if strict && artifact != "" {
			a, ok := s.Artifacts[artifact]
			if !ok || a.ID != artifact || a.TenantID != tenant {
				return false
			}
		}
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID})
		if err != nil || product != "" && refs.ProductID != "" && product != refs.ProductID || release != "" && refs.ReleaseID != "" && release != refs.ReleaseID {
			return false
		}
		refs.ProductID, refs.ReleaseID = nonEmpty(product, refs.ProductID), nonEmpty(release, refs.ReleaseID)
		return emit(refs, at)
	}
	switch kind {
	case "product":
		emit(application.ResourceReferences{ProductID: id}, time.Time{})
	case "release":
		emit(application.ResourceReferences{ReleaseID: id}, time.Time{})
	case "evidence", "evidence_item":
		evidence(id, "", "", "", "", s.Evidence[id].ObservedAt)
	case "artifact":
		a, ok := s.Artifacts[id]
		if !ok || a.ID != id || a.TenantID != tenant {
			return nil
		}
		if emit(application.ResourceReferences{}, time.Time{}) {
			return nil
		}
		for eid, e := range s.Evidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.ID != eid || e.TenantID != tenant {
				continue
			}
			for _, ref := range e.SubjectRefs {
				if ref.Type == "artifact" && ref.ID == id {
					if evidence(eid, "", "", "", "", time.Time{}) {
						return nil
					}
					break
				}
			}
		}
		for bid, b := range s.BuildRuns {
			if err := ctx.Err(); err != nil {
				return err
			}
			if b.ID != bid || b.TenantID != tenant {
				continue
			}
			for _, output := range b.Outputs {
				if output.ArtifactID == id && output.Digest == a.Digest {
					if emit(application.ResourceReferences{BuildID: bid}, time.Time{}) {
						return nil
					}
					break
				}
			}
		}
	case "sbom":
		v, ok := s.SBOMs[id]
		if ok && v.ID == id && v.TenantID == tenant {
			evidence(v.EvidenceID, "sbom", "", v.ReleaseID, v.ArtifactID, v.CreatedAt)
		}
	case "vulnerability_scan":
		v, ok := s.VulnerabilityScans[id]
		if ok && v.ID == id && v.TenantID == tenant {
			evidence(v.EvidenceID, "vulnerability_scan", "", v.ReleaseID, "", v.CreatedAt)
		}
	case "vex":
		v, ok := s.VEXDocuments[id]
		if ok && v.ID == id && v.TenantID == tenant {
			evidence(v.EvidenceID, "vex", "", v.ReleaseID, v.ArtifactID, v.CreatedAt)
		}
	case "finding", "vulnerability_finding":
		for sid, scan := range s.VulnerabilityScans {
			if err := ctx.Err(); err != nil {
				return err
			}
			if scan.ID != sid || scan.TenantID != tenant {
				continue
			}
			for _, finding := range scan.Findings {
				if finding.ID == id {
					if evidence(scan.EvidenceID, "vulnerability_scan", "", scan.ReleaseID, "", time.Time{}) {
						return nil
					}
					break
				}
			}
		}
	case "vulnerability_decision":
		v, ok := s.Decisions[id]
		scan, hasScan := s.VulnerabilityScans[v.ScanID]
		if !ok || v.ID != id || v.TenantID != tenant || !hasScan || scan.ID != v.ScanID || scan.TenantID != tenant || v.ReleaseID != "" && scan.ReleaseID != "" && v.ReleaseID != scan.ReleaseID {
			break
		}
		if strict {
			found := false
			for _, finding := range scan.Findings {
				if finding.ID == v.FindingID {
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		e := s.Evidence[scan.EvidenceID]
		if scan.ReleaseID != "" && e.ReleaseID != "" && scan.ReleaseID != e.ReleaseID {
			break
		}
		evidence(scan.EvidenceID, "vulnerability_scan", "", nonEmpty(v.ReleaseID, scan.ReleaseID), "", v.CreatedAt)
	case "exception":
		v, ok := s.Exceptions[id]
		if ok && v.ID == id && v.TenantID == tenant && v.ReleaseID != "" {
			emit(application.ResourceReferences{ReleaseID: v.ReleaseID}, v.CreatedAt)
		}
	case "build":
		v, ok := s.BuildRuns[id]
		if ok && v.ID == id && v.TenantID == tenant {
			emit(application.ResourceReferences{BuildID: id}, v.CreatedAt)
		}
	case "build_attestation":
		v, ok := s.BuildAttestations[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			break
		}
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: v.BuildID})
		e, hasEvidence := s.Evidence[v.EvidenceID]
		if err != nil || !hasEvidence || e.ID != v.EvidenceID || e.TenantID != tenant || e.ProjectID != "" && e.ProjectID != refs.ProjectID {
			break
		}
		if strict && e.Type != "build_attestation" || e.ProductID != "" && e.ProductID != refs.ProductID || e.ReleaseID != "" && e.ReleaseID != refs.ReleaseID {
			break
		}
		if _, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID}); err != nil {
			break
		}
		emit(refs, v.CreatedAt)
	case "openapi_contract":
		v, ok := s.OpenAPIContracts[id]
		if !ok || v.ID != id || v.TenantID != tenant || v.ProductID == "" {
			break
		}
		e, hasEvidence := s.Evidence[v.EvidenceID]
		if !hasEvidence || e.ID != v.EvidenceID || e.TenantID != tenant || strict && e.Type != "openapi_contract" {
			break
		}
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID})
		if err != nil || refs.ProductID != "" && refs.ProductID != v.ProductID || refs.ReleaseID != "" && v.ReleaseID != "" && refs.ReleaseID != v.ReleaseID {
			break
		}
		emit(application.ResourceReferences{ProductID: v.ProductID, ReleaseID: v.ReleaseID}, v.CreatedAt)
	case "release_bundle":
		v, ok := s.ReleaseBundles[id]
		if ok && v.ID == id && v.TenantID == tenant && v.ReleaseID != "" {
			emit(application.ResourceReferences{ReleaseID: v.ReleaseID}, v.CreatedAt)
		}
	}
	return ctx.Err()
}
