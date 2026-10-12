package app

import (
	"context"
	"sort"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical aggregate oracles, excluded from production builds.
func (l *Ledger) ListDeploymentEnvironments(ctx context.Context, actor domain.Actor, productID string) ([]domain.DeploymentEnvironment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeDeploymentRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.DeploymentEnvironment{}
	for _, env := range l.environments {
		if env.TenantID != actor.TenantID {
			continue
		}
		if productID != "" && env.ProductID != productID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeDeploymentRead, resourceRefs{ProductID: env.ProductID, EnvironmentID: env.ID}) {
			continue
		}
		out = append(out, env)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (l *Ledger) ListDeployments(ctx context.Context, actor domain.Actor, releaseID, environmentID string) ([]domain.DeploymentEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeDeploymentRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.DeploymentEvent{}
	for _, deployment := range l.deployments {
		if deployment.TenantID != actor.TenantID {
			continue
		}
		if releaseID != "" && deployment.ReleaseID != releaseID {
			continue
		}
		if environmentID != "" && deployment.EnvironmentID != environmentID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeDeploymentRead, resourceRefs{ReleaseID: deployment.ReleaseID, DeploymentID: deployment.ID, EnvironmentID: deployment.EnvironmentID}) {
			continue
		}
		out = append(out, deployment)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
