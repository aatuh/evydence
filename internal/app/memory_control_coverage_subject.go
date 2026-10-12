package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

// Match the native control-evidence subject joins using only current owner
// coordinates and observation times, not payloads or aggregate projections.
func memoryCoverageSubject(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant string, link domain.ControlEvidence, product, release string) (time.Time, bool, error) {
	if _, owned := memoryCoverageCoordinates(s, tenant, application.ResourceReferences{ProductID: link.ProductID, ReleaseID: link.ReleaseID}); !owned {
		return time.Time{}, false, nil
	}
	match := func(refs application.ResourceReferences, observed time.Time) (time.Time, bool, error) {
		if err := ctx.Err(); err != nil {
			return time.Time{}, false, err
		}
		refs, owned := memoryCoverageCoordinates(s, tenant, refs)
		if !owned || link.ProductID != "" && link.ProductID != refs.ProductID || link.ReleaseID != "" && link.ReleaseID != refs.ReleaseID || product != "" && refs.ProductID != "" && product != refs.ProductID || release != "" && refs.ReleaseID != "" && release != refs.ReleaseID {
			return time.Time{}, false, nil
		}
		if observed.IsZero() {
			observed = link.CreatedAt
		}
		return observed, !observed.IsZero(), nil
	}
	evidence := func(id, boundProduct, boundRelease string, observed time.Time) (time.Time, bool, error) {
		e, ok := s.Evidence[id]
		if !ok || e.ID != id || e.TenantID != tenant || boundProduct != "" && e.ProductID != "" && boundProduct != e.ProductID || boundRelease != "" && e.ReleaseID != "" && boundRelease != e.ReleaseID {
			return time.Time{}, false, nil
		}
		return match(application.ResourceReferences{ProductID: nonEmpty(boundProduct, e.ProductID), ProjectID: e.ProjectID, ReleaseID: nonEmpty(boundRelease, e.ReleaseID)}, observed)
	}
	id := link.SubjectID
	switch link.SubjectType {
	case "evidence", "evidence_item":
		return evidence(id, "", "", s.Evidence[id].ObservedAt)
	case "product":
		return match(application.ResourceReferences{ProductID: id}, time.Time{})
	case "release":
		return match(application.ResourceReferences{ReleaseID: id}, time.Time{})
	case "artifact":
		a, ok := s.Artifacts[id]
		if !ok || a.ID != id || a.TenantID != tenant {
			return time.Time{}, false, nil
		}
		// Native report reads are tenant-wide within the authorized report
		// root. A link without explicit coordinates accepts an owned artifact.
		if observed, owned, err := match(application.ResourceReferences{}, time.Time{}); owned || err != nil {
			return observed, owned, err
		}
		for key, e := range s.Evidence {
			if err := ctx.Err(); err != nil {
				return time.Time{}, false, err
			}
			if e.ID != key || e.TenantID != tenant {
				continue
			}
			for _, ref := range e.SubjectRefs {
				if ref.Type == "artifact" && ref.ID == id {
					if observed, owned, err := evidence(key, "", "", time.Time{}); owned || err != nil {
						return observed, owned, err
					}
				}
			}
		}
		for key, b := range s.BuildRuns {
			if err := ctx.Err(); err != nil {
				return time.Time{}, false, err
			}
			if b.ID != key || b.TenantID != tenant {
				continue
			}
			for _, output := range b.Outputs {
				if output.ArtifactID == id && output.Digest == a.Digest {
					if observed, owned, err := match(application.ResourceReferences{BuildID: key}, time.Time{}); owned || err != nil {
						return observed, owned, err
					}
				}
			}
		}
	case "sbom":
		v, ok := s.SBOMs[id]
		if ok && v.ID == id && v.TenantID == tenant {
			return evidence(v.EvidenceID, "", v.ReleaseID, v.CreatedAt)
		}
	case "vulnerability_scan":
		v, ok := s.VulnerabilityScans[id]
		if ok && v.ID == id && v.TenantID == tenant {
			return evidence(v.EvidenceID, "", v.ReleaseID, v.CreatedAt)
		}
	case "vex":
		v, ok := s.VEXDocuments[id]
		if ok && v.ID == id && v.TenantID == tenant {
			return evidence(v.EvidenceID, "", v.ReleaseID, v.CreatedAt)
		}
	case "vulnerability_decision":
		v, ok := s.Decisions[id]
		scan, scanOK := s.VulnerabilityScans[v.ScanID]
		if ok && v.ID == id && v.TenantID == tenant && scanOK && scan.ID == v.ScanID && scan.TenantID == tenant && (v.ReleaseID == "" || scan.ReleaseID == "" || v.ReleaseID == scan.ReleaseID) {
			return evidence(scan.EvidenceID, "", nonEmpty(v.ReleaseID, scan.ReleaseID), v.CreatedAt)
		}
	case "finding", "vulnerability_finding":
		for key, scan := range s.VulnerabilityScans {
			if err := ctx.Err(); err != nil {
				return time.Time{}, false, err
			}
			if scan.ID != key || scan.TenantID != tenant {
				continue
			}
			for _, finding := range scan.Findings {
				if finding.ID == id {
					if observed, owned, err := evidence(scan.EvidenceID, "", scan.ReleaseID, time.Time{}); owned || err != nil {
						return observed, owned, err
					}
				}
			}
		}
	case "exception":
		v, ok := s.Exceptions[id]
		if ok && v.ID == id && v.TenantID == tenant && v.ReleaseID != "" {
			return match(application.ResourceReferences{ReleaseID: v.ReleaseID}, v.CreatedAt)
		}
	case "build":
		v, ok := s.BuildRuns[id]
		if ok && v.ID == id && v.TenantID == tenant {
			return match(application.ResourceReferences{BuildID: id}, v.CreatedAt)
		}
	case "build_attestation":
		v, ok := s.BuildAttestations[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			break
		}
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: v.BuildID})
		e, evidenceOK := s.Evidence[v.EvidenceID]
		if err != nil || !evidenceOK || e.ID != v.EvidenceID || e.TenantID != tenant || e.ProjectID != "" && e.ProjectID != refs.ProjectID {
			break
		}
		return evidence(v.EvidenceID, refs.ProductID, refs.ReleaseID, v.CreatedAt)
	case "openapi_contract":
		v, ok := s.OpenAPIContracts[id]
		if ok && v.ID == id && v.TenantID == tenant && v.ProductID != "" {
			return evidence(v.EvidenceID, v.ProductID, v.ReleaseID, v.CreatedAt)
		}
	case "release_bundle":
		v, ok := s.ReleaseBundles[id]
		if ok && v.ID == id && v.TenantID == tenant && v.ReleaseID != "" {
			return match(application.ResourceReferences{ReleaseID: v.ReleaseID}, v.CreatedAt)
		}
	}
	return time.Time{}, false, ctx.Err()
}

// Invalid/missing owner coordinates are excluded like a failed native join,
// not exposed as a query error or accepted through stored link IDs alone.
func memoryCoverageCoordinates(s *MemoryUnitOfWorkSnapshot, tenant string, raw application.ResourceReferences) (application.ResourceReferences, bool) {
	refs, err := memoryOperationsCoordinates(s, tenant, raw)
	return refs, err == nil
}
