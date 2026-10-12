package app

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ evidencequery.VEXPreviewReader = memoryEvidenceRepository{}

// Typed memory snapshots model read policy and selected response limits, not
// PostgreSQL JSON shapes, query work/transfer, locking or durability.
func (r memoryEvidenceRepository) ReadVEXPreviewSnapshot(ctx context.Context, tenant, release, artifact string, prepare evidencequery.VEXPreviewPreparation) (evidencequery.VEXPreviewSnapshot, error) {
	var out evidencequery.VEXPreviewSnapshot
	if ctx == nil || r.uow == nil || prepare == nil || strings.TrimSpace(tenant) == "" {
		return out, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	release, artifact = strings.TrimSpace(release), strings.TrimSpace(artifact)
	if release == "" {
		return out, evidencequery.ErrNotFound
	}
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		if !memoryMembershipQueryText(refs.ProductID, 1024) {
			return evidencequery.ErrConflict
		}
		if artifact != "" {
			a, ok := s.Artifacts[artifact]
			if !ok || a.ID != artifact || a.TenantID != tenant {
				return evidencequery.ErrNotFound
			}
		}
		auth, err := releasequery.NewArtifactReadAuthorizer(memorySnapshotArtifactReader{s})
		if err != nil {
			return err
		}
		ids, err := prepare(application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: release}, auth)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return evidencequery.ErrConflict
		}
		wanted := make(map[string]bool, len(ids))
		for _, id := range ids {
			wanted[id] = true
		}
		out = evidencequery.VEXPreviewSnapshot{TenantID: tenant, ProductID: refs.ProductID, ReleaseID: release, ArtifactID: artifact}
		count, budget := 0, evidencequery.MaxVEXPreviewTextBytes
		for key, scan := range s.VulnerabilityScans {
			if err := ctx.Err(); err != nil {
				return err
			}
			if scan.TenantID != tenant || scan.ReleaseID != release {
				continue
			}
			count++
			if count > evidencequery.MaxVEXPreviewScans {
				return evidencequery.ErrConflict
			}
			source, exists := s.Evidence[scan.EvidenceID]
			if key != scan.ID || !exists || source.ID != scan.EvidenceID || source.TenantID != tenant || source.Type != "vulnerability_scan" || source.ReleaseID != release || source.ProductID != "" && source.ProductID != refs.ProductID {
				return evidencequery.ErrNotFound
			}
			if source.ProjectID != "" {
				project, exists := s.Projects[source.ProjectID]
				if !exists || project.ID != source.ProjectID || project.TenantID != tenant || project.ProductID != refs.ProductID {
					return evidencequery.ErrNotFound
				}
			}
			for _, finding := range scan.Findings {
				if !wanted[finding.Vulnerability] {
					continue
				}
				if len(out.Findings) >= evidencequery.MaxVEXPreviewFindings || !memoryMembershipText(finding.ID, 1024) || !memoryMembershipText(scan.ID, 1024) || !memoryMembershipText(finding.Vulnerability, 1<<20) || !memoryMembershipText(finding.Component, 1<<20) {
					return evidencequery.ErrConflict
				}
				f := evidencequery.VEXPreviewFinding{ID: finding.ID, ScanID: scan.ID, TenantID: tenant, ReleaseID: release, Vulnerability: finding.Vulnerability, Component: finding.Component}
				for _, decision := range s.Decisions {
					if decision.TenantID == tenant && decision.FindingID == finding.ID && decision.SupersededBy == "" {
						if decision.ScanID != scan.ID || decision.ReleaseID != "" && decision.ReleaseID != release {
							return evidencequery.ErrConflict
						}
						f.HasActiveDecision = true
					}
				}
				for _, text := range []string{f.ID, f.ScanID, f.TenantID, f.ReleaseID, f.Vulnerability, f.Component} {
					if len(text) > budget {
						return evidencequery.ErrConflict
					}
					budget -= len(text)
				}
				out.Findings = append(out.Findings, f)
			}
		}
		slices.SortFunc(out.Findings, func(a, b evidencequery.VEXPreviewFinding) int {
			if a.ScanID != b.ScanID {
				return strings.Compare(a.ScanID, b.ScanID)
			}
			return strings.Compare(a.ID, b.ID)
		})
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, err
	}
	return out, nil
}
