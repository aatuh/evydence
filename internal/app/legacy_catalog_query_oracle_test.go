package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Unchanged historical algorithms remain package-local test oracles only.
func (l *Ledger) ListProducts(ctx context.Context, actor domain.Actor) ([]domain.Product, error) {
	values, err := l.releaseCommands.ListProducts(ctx, actor)
	if err != nil {
		return nil, fromReleaseContextError(err)
	}
	result := make([]domain.Product, 0, len(values))
	for _, value := range values {
		result = append(result, productFromReleaseContext(value))
	}
	return result, nil
}

func (l *Ledger) ReleaseEvidenceFlowPlan(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseEvidenceFlow, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	if err := require(actor, ScopeReleaseRead); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return domain.ReleaseEvidenceFlow{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	release, ok := l.releases[releaseID]
	if !ok || release.TenantID != actor.TenantID {
		return domain.ReleaseEvidenceFlow{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	counts := releaseEvidenceFlowCountsLocked(l, actor.TenantID, release.ID)
	return domain.ReleaseEvidenceFlowFromContextModel(releasequery.AssembleEvidenceFlow(release.ID, release.ProductID, counts, l.now())), nil
}

func (l *Ledger) GetProject(ctx context.Context, actor domain.Actor, id string) (domain.Project, error) {
	value, err := l.releaseCommands.GetProject(ctx, actor, id)
	return projectFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetBuildRun(ctx context.Context, actor domain.Actor, id string) (domain.BuildRun, error) {
	value, err := l.releaseCommands.GetBuildRun(ctx, actor, id)
	return buildRunFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetReleaseCandidate(ctx context.Context, actor domain.Actor, id string) (domain.ReleaseCandidate, error) {
	value, err := l.releaseCommands.GetReleaseCandidate(ctx, actor, id)
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) ListReleaseCandidates(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.ReleaseCandidate, error) {
	values, err := l.releaseCommands.ListReleaseCandidates(ctx, actor, releaseID)
	if err != nil {
		return nil, fromReleaseContextError(err)
	}
	result := make([]domain.ReleaseCandidate, 0, len(values))
	for _, value := range values {
		result = append(result, releaseCandidateFromReleaseContext(value))
	}
	return result, nil
}
