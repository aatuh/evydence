package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical implementations remain unchanged and cannot be built into production.
const (
	deploymentStatusStarted    = "started"
	deploymentStatusSucceeded  = "succeeded"
	deploymentStatusFailed     = "failed"
	deploymentStatusRolledBack = "rolled_back"
)

type CreateEnvironmentInput struct {
	ProductID string
	Name      string
	Kind      string
}

type RecordDeploymentInput struct {
	EnvironmentID string
	ReleaseID     string
	ArtifactIDs   []string
	Status        string
	StartedAt     time.Time
	FinishedAt    *time.Time
	RollbackOf    string
}

func (l *Ledger) CreateDeploymentEnvironment(ctx context.Context, actor domain.Actor, in CreateEnvironmentInput) (domain.DeploymentEnvironment, error) {
	if err := ctx.Err(); err != nil {
		return domain.DeploymentEnvironment{}, err
	}
	if err := require(actor, ScopeDeploymentWrite); err != nil {
		return domain.DeploymentEnvironment{}, err
	}
	in.ProductID, in.Name, in.Kind = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.Name), strings.TrimSpace(in.Kind)
	if in.ProductID == "" || in.Name == "" || in.Kind == "" {
		return domain.DeploymentEnvironment{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	product, ok := l.products[in.ProductID]
	if !ok || product.TenantID != actor.TenantID {
		return domain.DeploymentEnvironment{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeDeploymentWrite, resourceRefs{ProductID: product.ID}); err != nil {
		return domain.DeploymentEnvironment{}, err
	}
	for _, existing := range l.environments {
		if existing.TenantID == actor.TenantID && existing.ProductID == product.ID && existing.Name == in.Name {
			return existing, nil
		}
	}
	env := domain.DeploymentEnvironment{
		ID:            newID("env"),
		TenantID:      actor.TenantID,
		ProductID:     product.ID,
		Name:          in.Name,
		Kind:          in.Kind,
		SchemaVersion: domain.DeploymentEnvironmentVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Deployments.InsertDeploymentEnvironment(ctx, env); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(env.CreatedAt, actor.TenantID, "deployment_environment.created", "deployment_environment", env.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.DeploymentEnvironment{}, err
		}
		l.environments[env.ID] = env
		l.publishCommittedAuditEntryLocked(entry)
		return env, nil
	}
	l.environments[env.ID] = env
	_, _ = l.appendChainLocked(actor.TenantID, "deployment_environment.created", "deployment_environment", env.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.DeploymentEnvironment{}, err
	}
	return env, nil
}

func (l *Ledger) RecordDeployment(ctx context.Context, actor domain.Actor, in RecordDeploymentInput) (domain.DeploymentEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.DeploymentEvent{}, err
	}
	if err := require(actor, ScopeDeploymentWrite); err != nil {
		return domain.DeploymentEvent{}, err
	}
	in.EnvironmentID, in.ReleaseID, in.Status = strings.TrimSpace(in.EnvironmentID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.Status)
	if in.EnvironmentID == "" || in.ReleaseID == "" || !validDeploymentStatus(in.Status) {
		return domain.DeploymentEvent{}, ErrValidation
	}
	if in.StartedAt.IsZero() {
		in.StartedAt = l.now()
	}
	l.mu.Lock()
	env, ok := l.environments[in.EnvironmentID]
	if !ok || env.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.DeploymentEvent{}, ErrNotFound
	}
	release, ok := l.releases[in.ReleaseID]
	if !ok || release.TenantID != actor.TenantID || release.ProductID != env.ProductID {
		l.mu.Unlock()
		return domain.DeploymentEvent{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeDeploymentWrite, resourceRefs{ProductID: env.ProductID, ReleaseID: release.ID, EnvironmentID: env.ID}); err != nil {
		l.mu.Unlock()
		return domain.DeploymentEvent{}, err
	}
	for _, artifactID := range in.ArtifactIDs {
		artifact, ok := l.artifacts[strings.TrimSpace(artifactID)]
		if !ok || artifact.TenantID != actor.TenantID {
			l.mu.Unlock()
			return domain.DeploymentEvent{}, ErrNotFound
		}
	}
	if in.RollbackOf != "" {
		previous, ok := l.deployments[strings.TrimSpace(in.RollbackOf)]
		if !ok || previous.TenantID != actor.TenantID || previous.EnvironmentID != env.ID {
			l.mu.Unlock()
			return domain.DeploymentEvent{}, ErrNotFound
		}
	}
	l.mu.Unlock()
	deploymentID := newID("dep")
	refs := []domain.SubjectRef{{Type: "release", ID: release.ID}}
	for _, artifactID := range sortedStrings(in.ArtifactIDs) {
		refs = append(refs, domain.SubjectRef{Type: "artifact", ID: artifactID})
	}
	// ADR 0003 limits this compatibility bridge to the fixed deployment/event
	// evidence shape. The deployment and its immediately readable evidence
	// back-reference remain atomic until EVY-906 introduces the durable saga.
	evidenceInput := CreateEvidenceInput{
		ProductID:    env.ProductID,
		ReleaseID:    release.ID,
		DeploymentID: deploymentID,
		Type:         "deployment",
		Subtype:      "event",
		Title:        "Deployment event",
		SourceSystem: "api",
		ObservedAt:   in.StartedAt,
		PayloadHash:  hashBytes([]byte(deploymentID + ":" + in.Status)),
		SubjectRefs:  refs,
		Metadata:     map[string]any{"environment_id": env.ID, "status": in.Status},
		Limitations:  []string{"Deployment evidence records the supplied deployment metadata; it does not prove runtime security or availability."},
	}
	deployment := domain.DeploymentEvent{
		ID:            deploymentID,
		TenantID:      actor.TenantID,
		EnvironmentID: env.ID,
		ReleaseID:     release.ID,
		ArtifactIDs:   sortedStrings(in.ArtifactIDs),
		Status:        in.Status,
		StartedAt:     in.StartedAt.UTC(),
		FinishedAt:    in.FinishedAt,
		RollbackOf:    strings.TrimSpace(in.RollbackOf),
		EvidenceID:    "",
		SchemaVersion: domain.DeploymentEventSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		item, err := l.newEvidenceItemForScopeLocked(actor, ScopeDeploymentWrite, evidenceInput)
		if err != nil {
			return domain.DeploymentEvent{}, err
		}
		deployment.EvidenceID = item.ID
		var evidenceEntry, deploymentEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			var err error
			evidenceEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(item.CreatedAt, actor.TenantID, "evidence.created", "evidence_item", item.ID, actorType(actor), actorID(actor), item.PayloadHash, ""))
			if err != nil {
				return err
			}
			item.ChainEntryID = evidenceEntry.ID
			if err := repos.Evidence.InsertEvidence(ctx, item); err != nil {
				return err
			}
			deploymentEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(deployment.CreatedAt, actor.TenantID, "deployment.recorded", "deployment", deployment.ID, actorType(actor), actorID(actor), "", ""))
			if err != nil {
				return err
			}
			return repos.Deployments.InsertDeploymentEvent(ctx, deployment)
		}); err != nil {
			return domain.DeploymentEvent{}, err
		}
		l.evidence[item.ID] = item
		l.deployments[deployment.ID] = deployment
		l.publishCommittedAuditEntryLocked(evidenceEntry)
		l.publishCommittedAuditEntryLocked(deploymentEntry)
		return deployment, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	item, err := l.newEvidenceItemForScopeLocked(actor, ScopeDeploymentWrite, evidenceInput)
	if err != nil {
		return domain.DeploymentEvent{}, err
	}
	deployment.EvidenceID = item.ID
	evidenceEntry, err := l.appendChainLocked(actor.TenantID, "evidence.created", "evidence_item", item.ID, actorType(actor), actorID(actor), item.PayloadHash, "")
	if err != nil {
		return domain.DeploymentEvent{}, err
	}
	item.ChainEntryID = evidenceEntry.ID
	l.evidence[item.ID] = item
	l.deployments[deployment.ID] = deployment
	_, _ = l.appendChainLocked(actor.TenantID, "deployment.recorded", "deployment", deployment.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.DeploymentEvent{}, err
	}
	return deployment, nil
}

func validDeploymentStatus(status string) bool {
	switch status {
	case deploymentStatusStarted, deploymentStatusSucceeded, deploymentStatusFailed, deploymentStatusRolledBack:
		return true
	default:
		return false
	}
}
