package app

import (
	"context"
	"encoding/json"
	"slices"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ControlsReader = memoryControlRepository{}

// Keep only page-size+1 sort coordinates before selecting current tenant rows.
// This typed snapshot models keysets, not SQL transfer/work or durability.
// Native framework pages have no metadata byte ceiling; do not invent one here.
func (r memoryControlRepository) PageFrameworks(ctx context.Context, req riskquery.FrameworkPageRequest) (appquery.Result[riskdomain.ControlFramework], error) {
	var out appquery.Result[riskdomain.ControlFramework]
	window, err := newMemoryDeploymentPageWindow(req.Page, req.After)
	if err != nil {
		return out, err
	}
	err = memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		for id, v := range s.ControlFrameworks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID == req.TenantID {
				window.offer(id, v.CreatedAt)
			}
		}
		items := make([]riskdomain.ControlFramework, 0, len(window.keys))
		for _, key := range window.keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			v := s.ControlFrameworks[key.id]
			if v.ID != key.id || v.ID == "" || !memoryGovernanceText(v.ID, 1024) || v.Name == "" || v.Slug == "" || v.Version == "" || v.Status == "" || v.CreatedAt.IsZero() {
				return riskquery.ErrInvalidProjection
			}
			v.CreatedAt = v.CreatedAt.UTC()
			items = append(items, riskdomain.ControlFramework(v))
		}
		out = appquery.Result[riskdomain.ControlFramework]{Items: items, Next: window.next()}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	return out, nil
}

// GetControl checks the current tenant-owned framework in the same snapshot,
// matches the native per-JSON-column ceiling, and detaches every mutable list.
func (r memoryControlRepository) GetControl(ctx context.Context, tenant, id string) (riskdomain.SecurityControl, error) {
	var out riskdomain.SecurityControl
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.SecurityControls[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return riskquery.ErrNotFound
		}
		f, ok := s.ControlFrameworks[v.FrameworkID]
		if !ok || v.FrameworkID == "" || f.ID != v.FrameworkID || f.TenantID != tenant {
			return riskquery.ErrNotFound
		}
		for _, values := range []any{v.EvidenceRequirements, v.Applicability, v.Limitations} {
			// Bound the source material before JSON encoding. The conservative
			// minimum per element is below its smallest actual encoding; exact
			// escaped JSON size is checked separately below.
			remaining := 1 << 20
			switch list := values.(type) {
			case []domain.ControlEvidenceRequirement:
				for _, item := range list {
					if len(item.Type) > remaining-16 {
						return riskquery.ErrInvalidProjection
					}
					remaining -= len(item.Type) + 16
				}
			case []string:
				for _, item := range list {
					if len(item) > remaining-3 {
						return riskquery.ErrInvalidProjection
					}
					remaining -= len(item) + 3
				}
			}
			raw, err := json.Marshal(values)
			if err != nil || len(raw) > 1<<20 {
				return riskquery.ErrInvalidProjection
			}
		}
		requirements := make([]riskdomain.ControlEvidenceRequirement, len(v.EvidenceRequirements))
		for i, requirement := range v.EvidenceRequirements {
			requirements[i] = riskdomain.ControlEvidenceRequirement(requirement)
		}
		out = riskdomain.SecurityControl{ID: v.ID, TenantID: v.TenantID, FrameworkID: v.FrameworkID, Code: v.Code, Title: v.Title, Objective: v.Objective, EvidenceRequirements: requirements, Applicability: slices.Clone(v.Applicability), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt.UTC()}
		return ctx.Err()
	})
	if err != nil {
		return riskdomain.SecurityControl{}, err
	}
	return out, nil
}
