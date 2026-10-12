package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Retained unchanged for historical aggregate tests; not part of production.
func (l *Ledger) GetDeployment(ctx context.Context, actor domain.Actor, id string) (domain.DeploymentEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.DeploymentEvent{}, err
	}
	if err := require(actor, ScopeDeploymentRead); err != nil {
		return domain.DeploymentEvent{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	deployment, ok := l.deployments[strings.TrimSpace(id)]
	if !ok || deployment.TenantID != actor.TenantID {
		return domain.DeploymentEvent{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeDeploymentRead, resourceRefs{ReleaseID: deployment.ReleaseID, DeploymentID: deployment.ID}); err != nil {
		return domain.DeploymentEvent{}, err
	}
	return deployment, nil
}
