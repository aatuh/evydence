package query

import (
	"context"
	"sort"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ReadinessEvaluator interface {
	Preview(context.Context, identitydomain.Actor, string) (riskdomain.PolicyEvaluation, error)
}

type MissingEvidenceReport struct{ readiness ReadinessEvaluator }

func NewMissingEvidenceReport(readiness ReadinessEvaluator) (*MissingEvidenceReport, error) {
	if readiness == nil {
		return nil, ErrValidation
	}
	return &MissingEvidenceReport{readiness: readiness}, nil
}

// Report is a read-only rendering of one tenant-scoped readiness evaluation.
func (s *MissingEvidenceReport) Report(ctx context.Context, actor identitydomain.Actor, releaseID string) (map[string]any, error) {
	if s == nil || ctx == nil {
		return nil, ErrValidation
	}
	evaluation, err := s.readiness.Preview(ctx, actor, releaseID)
	if err != nil {
		return nil, err
	}
	if evaluation.TenantID != actor.TenantID || evaluation.ReleaseID != releaseID || evaluation.Result != "passed" && evaluation.Result != "failed" {
		return nil, ErrInvalidProjection
	}
	missing := []string{}
	for _, check := range evaluation.Checks {
		missing = append(missing, check.Missing...)
	}
	sort.Strings(missing)
	return map[string]any{
		"report_type": "missing_evidence", "template_version": "missing-evidence.v1.0.0",
		"release_id": releaseID, "result": evaluation.Result, "missing": missing,
		"assumptions": []string{"This report supports compliance readiness and is not a legal compliance conclusion."},
		"limitations": []string{"Missing evidence is based only on evidence recorded in this Evydence instance."},
	}, nil
}
