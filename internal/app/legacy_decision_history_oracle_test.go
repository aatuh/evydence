package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// Historical package-local characterization only; HTTP and production reads
// use bounded focused queries over current typed repositories.
type ListVulnerabilityDecisionsInput struct {
	ProductID     string
	ReleaseID     string
	Vulnerability string
	Component     string
	Status        string
	Active        *bool
}

func (l *Ledger) ListVulnerabilityDecisions(ctx context.Context, actor domain.Actor, in ListVulnerabilityDecisionsInput) ([]domain.VulnerabilityDecision, error) {
	values, err := l.riskCommands.ListVulnerabilityDecisions(ctx, actor, riskapp.ListVulnerabilityDecisionsInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, Vulnerability: in.Vulnerability,
		Component: in.Component, Status: in.Status, Active: in.Active,
	})
	if err != nil {
		return nil, fromRiskContextError(err)
	}
	result := make([]domain.VulnerabilityDecision, 0, len(values))
	for _, value := range values {
		result = append(result, domain.VulnerabilityDecisionFromContextModel(value))
	}
	return result, nil
}
