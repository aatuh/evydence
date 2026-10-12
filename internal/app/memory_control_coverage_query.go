package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ packagequery.ControlCoverageReader = memoryPackageRepository{}

// The memory transaction model projects current report facts, never Ledger
// caches. Conservative JSON encoding budgets do not establish SQL transfer,
// work, locking or durability guarantees.
func (r memoryPackageRepository) ReadControlCoverageSnapshot(ctx context.Context, tenant, framework, product, release string, at time.Time) (packagequery.ControlCoverageSnapshot, error) {
	if ctx == nil || r.uow == nil || at.IsZero() {
		return packagequery.ControlCoverageSnapshot{}, packagequery.ErrControlCoverageValidation
	}
	var out packagequery.ControlCoverageSnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: product, ReleaseID: release})
		if err != nil {
			return err
		}
		if framework == "" {
			var first domain.ControlFramework
			for id, f := range s.ControlFrameworks {
				if err := ctx.Err(); err != nil {
					return err
				}
				if f.ID != id || f.TenantID != tenant {
					continue
				}
				if first.ID == "" || f.Slug < first.Slug || f.Slug == first.Slug && (f.Version < first.Version || f.Version == first.Version && f.ID < first.ID) {
					first = f
				}
			}
			framework = first.ID
		}
		f, ok := s.ControlFrameworks[framework]
		if !ok || f.ID != framework || f.TenantID != tenant {
			return ErrNotFound
		}
		out = packagequery.ControlCoverageSnapshot{TenantID: tenant, FrameworkID: framework, ScopeProductID: refs.ProductID, ScopeReleaseID: release}
		remaining, remainingBytes := packagequery.MaxControlCoverageEntries, 8<<20
		consume := func(bytes, limit int) error {
			if bytes > limit || remaining == 0 || bytes > remainingBytes {
				return packagequery.ErrControlCoverageCapacity
			}
			remaining--
			remainingBytes -= bytes
			return nil
		}
		controls := map[string]bool{}
		for id, c := range s.SecurityControls {
			if err := ctx.Err(); err != nil {
				return err
			}
			if c.TenantID != tenant || c.FrameworkID != framework {
				continue
			}
			if id == "" || c.ID != id {
				return packagequery.ErrControlCoverageProjection
			}
			bytes, err := memoryCoverageControlBytes(c)
			if err != nil {
				return err
			}
			if err := consume(bytes, 64<<10); err != nil {
				return err
			}
			requirements := make([]riskdomain.ControlEvidenceRequirement, len(c.EvidenceRequirements))
			for i, requirement := range c.EvidenceRequirements {
				requirements[i] = riskdomain.ControlEvidenceRequirement(requirement)
			}
			out.Controls = append(out.Controls, riskdomain.SecurityControl{ID: id, TenantID: tenant, FrameworkID: framework, Code: c.Code, Title: c.Title, Objective: c.Objective, EvidenceRequirements: requirements, Applicability: slices.Clone(c.Applicability), Limitations: slices.Clone(c.Limitations), SchemaVersion: c.SchemaVersion, CreatedAt: c.CreatedAt})
			controls[id] = true
		}
		for id, link := range s.ControlEvidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			if link.TenantID != tenant || !controls[link.ControlID] || refs.ProductID != "" && link.ProductID != "" && link.ProductID != refs.ProductID || release != "" && link.ReleaseID != "" && link.ReleaseID != release {
				continue
			}
			bytes, err := memoryCoverageTextBytes(link.ID, link.TenantID, link.ControlID, link.EvidenceType, link.SubjectType, link.SubjectID, link.ProductID, link.ReleaseID, link.Confidence, link.Notes, link.SchemaVersion)
			if err != nil {
				return err
			}
			// Match the native preflight: scoped oversized link rows fail even
			// when their subject would subsequently be excluded by the join.
			if bytes > 8<<10 {
				return packagequery.ErrControlCoverageCapacity
			}
			observed, owned, err := memoryCoverageSubject(ctx, s, tenant, link, refs.ProductID, release)
			if err != nil {
				return err
			}
			if id == "" || link.ID != id || !owned {
				continue
			}
			if err := consume(bytes, 8<<10); err != nil {
				return err
			}
			out.Links = append(out.Links, packagequery.ControlCoverageLink{Link: riskdomain.ControlEvidence(link), SubjectObservedAt: observed})
		}
		for id, x := range s.Exceptions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if x.ID != id || x.TenantID != tenant || !controls[x.ControlID] || !x.Approved || !x.ExpiresAt.After(at) || release != "" && x.ReleaseID != release {
				continue
			}
			owner, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: x.ReleaseID})
			if err != nil || x.ReleaseID == "" || refs.ProductID != "" && owner.ProductID != refs.ProductID {
				continue
			}
			bytes, err := memoryCoverageTextBytes(x.ID, x.TenantID, x.ReleaseID, x.FindingID, x.ControlID, x.Reason, x.Owner, x.ApprovedBy)
			if err != nil {
				return err
			}
			if err := consume(bytes, 8<<10); err != nil {
				return err
			}
			x.ApprovedAt = cloneTimePtr(x.ApprovedAt)
			out.Exceptions = append(out.Exceptions, riskdomain.Exception(x))
		}
		sort.Slice(out.Controls, func(i, j int) bool {
			a, b := out.Controls[i], out.Controls[j]
			return a.Code < b.Code || a.Code == b.Code && a.ID < b.ID
		})
		sort.Slice(out.Links, func(i, j int) bool { return out.Links[i].Link.ID < out.Links[j].Link.ID })
		sort.Slice(out.Exceptions, func(i, j int) bool { return out.Exceptions[i].ID < out.Exceptions[j].ID })
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = packagequery.ErrControlCoverageNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = packagequery.ErrControlCoverageValidation
	}
	if err != nil {
		return packagequery.ControlCoverageSnapshot{}, err
	}
	return out, nil
}

func memoryCoverageTextBytes(values ...string) (int, error) {
	total := 0
	for _, value := range values {
		if !memoryGovernanceText(value, len(value)) {
			return 0, packagequery.ErrControlCoverageProjection
		}
		total += len(value)
	}
	return total, nil
}

func memoryCoverageControlBytes(c domain.SecurityControl) (int, error) {
	bytes, err := memoryCoverageTextBytes(c.ID, c.TenantID, c.FrameworkID, c.Code, c.Title, c.Objective, c.SchemaVersion)
	if err != nil {
		return 0, err
	}
	if bytes > 64<<10 || len(c.EvidenceRequirements)+len(c.Applicability)+len(c.Limitations) > 32<<10 {
		return 0, packagequery.ErrControlCoverageCapacity
	}
	for _, requirement := range c.EvidenceRequirements {
		if !memoryGovernanceText(requirement.Type, len(requirement.Type)) {
			return 0, packagequery.ErrControlCoverageProjection
		}
	}
	for _, values := range [][]string{c.Applicability, c.Limitations} {
		if _, err := memoryCoverageTextBytes(values...); err != nil {
			return 0, err
		}
	}
	// Go escaping plus conservative JSONB separator spaces may reject a
	// pathological memory row earlier than PostgreSQL's exact octet count.
	for _, field := range []struct {
		value  any
		spaces int
	}{{c.EvidenceRequirements, 6 * len(c.EvidenceRequirements)}, {c.Applicability, max(0, len(c.Applicability)-1)}, {c.Limitations, max(0, len(c.Limitations)-1)}} {
		encoded, err := json.Marshal(field.value)
		if err != nil {
			return 0, packagequery.ErrControlCoverageProjection
		}
		bytes += len(encoded) + field.spaces
	}
	return bytes, nil
}
