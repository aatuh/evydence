package app

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ packagequery.SecurityUpdateReader = memoryPackageRepository{}

// The memory transaction model projects current public report facts without
// Ledger. It models the native row/reference budgets, not SQL work, transfer,
// JSON shapes, locking or durability.
func (r memoryPackageRepository) ReadSecurityUpdateSnapshot(ctx context.Context, tenant, product, release string) (packagequery.SecurityUpdateSnapshot, error) {
	if ctx == nil || r.uow == nil || product == "" || release == "" {
		return packagequery.SecurityUpdateSnapshot{}, packagequery.ErrSecurityUpdateValidation
	}
	var out packagequery.SecurityUpdateSnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: product, ReleaseID: release})
		if err != nil {
			return err
		}
		out = packagequery.SecurityUpdateSnapshot{TenantID: tenant, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, ScanEvidenceIDs: []string{}, Decisions: []riskdomain.VulnerabilityDecision{}, VEXEvidenceIDs: map[string]string{}, Incidents: []operationsdomain.Incident{}, Tasks: []operationsdomain.RemediationTask{}}
		remaining := packagequery.MaxSecurityUpdateEntries
		consume := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if remaining == 0 {
				return packagequery.ErrSecurityUpdateCapacity
			}
			remaining--
			return nil
		}
		scanIDs := []string{}
		for id, scan := range s.VulnerabilityScans {
			if err := ctx.Err(); err != nil {
				return err
			}
			if scan.TenantID != tenant || scan.ReleaseID != release {
				continue
			}
			if err := consume(); err != nil {
				return err
			}
			e, ok := s.Evidence[scan.EvidenceID]
			if id == "" || scan.ID != id || !ok || e.ID != scan.EvidenceID || e.TenantID != tenant {
				return packagequery.ErrSecurityUpdateProjection
			}
			// Raw finding arrays and scan metadata are not report inputs.
			scanIDs = append(scanIDs, id)
		}
		sort.Slice(scanIDs, func(i, j int) bool {
			a, b := s.VulnerabilityScans[scanIDs[i]], s.VulnerabilityScans[scanIDs[j]]
			return a.CreatedAt.Before(b.CreatedAt) || a.CreatedAt.Equal(b.CreatedAt) && a.ID < b.ID
		})
		for _, id := range scanIDs {
			out.ScanEvidenceIDs = append(out.ScanEvidenceIDs, s.VulnerabilityScans[id].EvidenceID)
		}
		for id, d := range s.Decisions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.TenantID != tenant || d.ReleaseID != release || d.Status != "fixed" || d.SupersededBy != "" {
				continue
			}
			if err := consume(); err != nil {
				return err
			}
			if id == "" || d.ID != id || d.ScanID == "" || d.FindingID == "" {
				return packagequery.ErrSecurityUpdateProjection
			}
			d.InternalNotes = ""
			model, err := domain.VulnerabilityDecisionToContextModel(d)
			if err != nil {
				return packagequery.ErrSecurityUpdateProjection
			}
			out.Decisions = append(out.Decisions, model)
			if d.VEXDocumentID != "" {
				v, ok := s.VEXDocuments[d.VEXDocumentID]
				e, evidenceOK := s.Evidence[v.EvidenceID]
				if !ok || v.ID != d.VEXDocumentID || v.TenantID != tenant || v.ReleaseID != release || !evidenceOK || e.ID != v.EvidenceID || e.TenantID != tenant {
					return packagequery.ErrSecurityUpdateProjection
				}
				out.VEXEvidenceIDs[v.ID] = v.EvidenceID
			}
		}
		incidents := map[string]bool{}
		for id, incident := range s.Incidents {
			if err := ctx.Err(); err != nil {
				return err
			}
			if incident.TenantID != tenant || incident.ProductID != product || incident.ReleaseID != release {
				continue
			}
			if err := consume(); err != nil {
				return err
			}
			if id == "" || incident.ID != id {
				return packagequery.ErrSecurityUpdateProjection
			}
			model, err := domain.IncidentToContextModel(incident)
			if err != nil {
				return packagequery.ErrSecurityUpdateProjection
			}
			out.Incidents = append(out.Incidents, model)
			incidents[id] = true
		}
		for id, task := range s.RemediationTasks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if task.TenantID != tenant || task.ReleaseID != "" && task.ReleaseID != release || task.IncidentID != "" && !incidents[task.IncidentID] || task.ReleaseID == "" && !incidents[task.IncidentID] {
				continue
			}
			if err := consume(); err != nil {
				return err
			}
			if id == "" || task.ID != id {
				return packagequery.ErrSecurityUpdateProjection
			}
			task.DueAt = cloneTimePtr(task.DueAt)
			out.Tasks = append(out.Tasks, operationsdomain.RemediationTask(task))
		}
		if err := verifyMemorySecurityUpdateEvidence(ctx, s, out); err != nil {
			return err
		}
		sort.Slice(out.Decisions, func(i, j int) bool { return out.Decisions[i].ID < out.Decisions[j].ID })
		sort.Slice(out.Incidents, func(i, j int) bool { return out.Incidents[i].ID < out.Incidents[j].ID })
		sort.Slice(out.Tasks, func(i, j int) bool { return out.Tasks[i].ID < out.Tasks[j].ID })
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = packagequery.ErrSecurityUpdateNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = packagequery.ErrSecurityUpdateValidation
	}
	if err != nil {
		return packagequery.SecurityUpdateSnapshot{}, err
	}
	return out, nil
}

func verifyMemorySecurityUpdateEvidence(ctx context.Context, s *MemoryUnitOfWorkSnapshot, snapshot packagequery.SecurityUpdateSnapshot) error {
	ids := map[string]bool{}
	add := func(id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if id = strings.TrimSpace(id); id != "" {
			ids[id] = true
		}
		if len(ids) > packagequery.MaxSecurityUpdateEntries {
			return packagequery.ErrSecurityUpdateCapacity
		}
		return nil
	}
	for _, id := range snapshot.ScanEvidenceIDs {
		if err := add(id); err != nil {
			return err
		}
	}
	for _, d := range snapshot.Decisions {
		if err := add(d.EvidenceID); err != nil {
			return err
		}
		for _, id := range d.EvidenceIDs {
			if err := add(id); err != nil {
				return err
			}
		}
		for _, ref := range d.SupportingRefs {
			if ref.Type == "evidence" {
				if err := add(ref.ID); err != nil {
					return err
				}
			}
		}
	}
	for _, id := range snapshot.VEXEvidenceIDs {
		if err := add(id); err != nil {
			return err
		}
	}
	for _, task := range snapshot.Tasks {
		if err := add(task.EvidenceID); err != nil {
			return err
		}
	}
	for id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		e, ok := s.Evidence[id]
		if !ok || e.ID != id || e.TenantID != snapshot.TenantID || e.ProductID != "" && e.ProductID != snapshot.ProductID {
			return packagequery.ErrSecurityUpdateProjection
		}
		if e.ProjectID != "" {
			project, ok := s.Projects[e.ProjectID]
			if !ok || project.ID != e.ProjectID || project.TenantID != snapshot.TenantID || project.ProductID != snapshot.ProductID {
				return packagequery.ErrSecurityUpdateProjection
			}
		}
		if e.ReleaseID != "" && e.ReleaseID != snapshot.ReleaseID {
			return packagequery.ErrSecurityUpdateProjection
		}
	}
	return nil
}
