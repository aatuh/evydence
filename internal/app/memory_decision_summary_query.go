package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.DecisionSummaryReader = memoryDecisionRepository{}

// Typed test snapshots model current ownership and selected response budgets,
// not PostgreSQL transfer limits, JSON shape checks, row locks or durability.
func (r memoryDecisionRepository) ReadVulnerabilityDecisionSummary(ctx context.Context, req riskquery.DecisionSummaryRequest) (riskquery.DecisionSummarySnapshot, error) {
	var out riskquery.DecisionSummarySnapshot
	if req.TenantWide && (len(req.AllowedProductIDs) != 0 || len(req.AllowedReleaseIDs) != 0) {
		return out, riskquery.ErrValidation
	}
	err := memoryGovernanceRead(ctx, r.uow, req.TenantID, req.ReleaseID, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, req.TenantID, application.ResourceReferences{ReleaseID: req.ReleaseID})
		if err != nil {
			return err
		}
		if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, refs.ProductID) && !slices.Contains(req.AllowedReleaseIDs, req.ReleaseID) {
			return application.ErrForbidden
		}
		out = riskquery.DecisionSummarySnapshot{Release: riskquery.ReleaseScope{ID: req.ReleaseID, ProductID: refs.ProductID}, Decisions: []riskquery.DecisionPoint{}}
		remaining := riskquery.MaxDecisionSummaryTextBytes
		for id, value := range s.Decisions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if value.TenantID != req.TenantID || value.ReleaseID != req.ReleaseID || !value.CustomerVisible || value.SupersededBy != "" {
				continue
			}
			if id != value.ID || len(out.Decisions) >= riskquery.MaxDecisionSummaryDecisions {
				return riskquery.ErrInvalidProjection
			}
			// Omit notes before measuring, copying or mapping selected metadata.
			value.InternalNotes = ""
			if !memoryDecisionSummaryBudget(value, refs.ProductID, &remaining) {
				return riskquery.ErrInvalidProjection
			}
			model, err := domain.VulnerabilityDecisionToContextModel(value)
			if err != nil {
				return riskquery.ErrInvalidProjection
			}
			out.Decisions = append(out.Decisions, riskquery.DecisionPoint{Decision: model, ProductID: refs.ProductID})
		}
		slices.SortFunc(out.Decisions, func(a, b riskquery.DecisionPoint) int {
			if order := a.Decision.CreatedAt.Compare(b.Decision.CreatedAt); order != 0 {
				return order
			}
			return strings.Compare(a.Decision.ID, b.Decision.ID)
		})
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = riskquery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = riskquery.ErrValidation
	}
	if err != nil {
		return riskquery.DecisionSummarySnapshot{}, err
	}
	return out, nil
}

func memoryDecisionSummaryBudget(d domain.VulnerabilityDecision, product string, remaining *int) bool {
	for _, value := range []string{d.ID, d.TenantID, d.FindingID, d.ScanID, d.ReleaseID, product, d.Vulnerability, d.Component, d.SBOMID, d.SBOMComponentPURL, d.SBOMComponentName, d.Status, d.Justification, d.ImpactStatement, d.ActionStatement, d.Source, d.EvidenceID, d.VEXDocumentID, d.Supersedes, d.SupersededBy, d.ApprovedBy, d.SchemaVersion} {
		if !memoryGovernanceText(value, *remaining) {
			return false
		}
		*remaining -= len(value)
	}
	for _, id := range d.EvidenceIDs {
		if !memoryGovernanceText(id, *remaining) {
			return false
		}
	}
	for _, ref := range d.SupportingRefs {
		for _, text := range []string{ref.Type, ref.ID, ref.Digest} {
			if !memoryGovernanceText(text, *remaining) {
				return false
			}
		}
	}
	for _, container := range []any{d.EvidenceIDs, d.SupportingRefs} {
		raw, err := json.Marshal(container)
		if err != nil || len(raw) > *remaining {
			return false
		}
		*remaining -= len(raw)
	}
	return true
}
