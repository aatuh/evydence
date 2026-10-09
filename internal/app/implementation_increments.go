package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

const (
	lifecycleAmendment       = "amendment"
	lifecycleRedaction       = "redaction"
	lifecycleTombstone       = "tombstone"
	lifecycleRetentionMarker = "retention_marker"

	candidateOpen     = "open"
	candidatePromoted = "promoted"
	candidateRejected = "rejected"

	deploymentStatusStarted    = "started"
	deploymentStatusSucceeded  = "succeeded"
	deploymentStatusFailed     = "failed"
	deploymentStatusRolledBack = "rolled_back"
)

type EvidenceSearchInput struct {
	ProductID          string
	ProjectID          string
	ReleaseID          string
	BuildID            string
	DeploymentID       string
	Type               string
	Subtype            string
	SourceSystem       string
	CollectorID        string
	VerificationStatus string
	SubjectType        string
	SubjectID          string
	Tag                string
	CreatedAfter       time.Time
	CreatedBefore      time.Time
	Limit              int
}

type RecordEvidenceLifecycleInput struct {
	Action        string
	Reason        string
	Details       map[string]any
	ReplacementID string
}

type CreateReleaseCandidateInput struct {
	ReleaseID   string
	Name        string
	BuildIDs    []string
	ArtifactIDs []string
	SBOMIDs     []string
	ScanIDs     []string
	VEXIDs      []string
	ContractIDs []string
	BundleIDs   []string
}

type RegisterContainerImageInput struct {
	ArtifactID string
	Repository string
	Tag        string
	Digest     string
	Platform   string
}

type CreateRepositoryInput struct {
	ProjectID     string
	Provider      string
	FullName      string
	CloneURL      string
	DefaultBranch string
}

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

func (l *Ledger) RecordEvidenceLifecycleEvent(ctx context.Context, actor domain.Actor, evidenceID string, in RecordEvidenceLifecycleInput) (domain.EvidenceLifecycleEvent, error) {
	event, err := l.evidenceCommands.RecordLifecycleEvent(ctx, actor, evidenceID, evidenceapp.RecordLifecycleInput{
		Action: in.Action, Reason: in.Reason, Details: cloneMap(in.Details), ReplacementID: in.ReplacementID,
	})
	return lifecycleFromEvidenceContext(event), fromEvidenceContextError(err)
}

func (l *Ledger) CreateReleaseCandidate(ctx context.Context, actor domain.Actor, in CreateReleaseCandidateInput) (domain.ReleaseCandidate, error) {
	value, err := l.releaseCommands.CreateReleaseCandidate(ctx, actor, releaseapp.CreateReleaseCandidateInput{
		ReleaseID: in.ReleaseID, Name: in.Name, BuildIDs: append([]string(nil), in.BuildIDs...),
		ArtifactIDs: append([]string(nil), in.ArtifactIDs...), SBOMIDs: append([]string(nil), in.SBOMIDs...),
		ScanIDs: append([]string(nil), in.ScanIDs...), VEXIDs: append([]string(nil), in.VEXIDs...),
		ContractIDs: append([]string(nil), in.ContractIDs...), BundleIDs: append([]string(nil), in.BundleIDs...),
	})
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) UpdateReleaseCandidateState(ctx context.Context, actor domain.Actor, id, state, reason string, expectedRevision int64) (domain.ReleaseCandidate, error) {
	value, err := l.releaseCommands.UpdateReleaseCandidateState(ctx, actor, id, state, reason, expectedRevision)
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) RegisterContainerImage(ctx context.Context, actor domain.Actor, in RegisterContainerImageInput) (domain.ContainerImage, error) {
	value, err := l.releaseCommands.RegisterContainerImage(ctx, actor, releaseapp.RegisterContainerImageInput{
		ArtifactID: in.ArtifactID, Repository: in.Repository, Tag: in.Tag, Digest: in.Digest, Platform: in.Platform,
	})
	return containerImageFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateSourceRepository(ctx context.Context, actor domain.Actor, in CreateRepositoryInput) (domain.SourceRepository, error) {
	in, err := prepareLocalSourceRepositoryCreation(ctx, actor, in)
	if err != nil {
		return domain.SourceRepository{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	existing, err := l.authorizeSourceRepositoryCreationLocked(actor, in)
	if err != nil {
		return domain.SourceRepository{}, err
	}
	if existing != "" {
		return l.repositories[existing], nil
	}
	repo := domain.SourceRepository{
		ID:            newID("repo"),
		TenantID:      actor.TenantID,
		ProjectID:     strings.TrimSpace(in.ProjectID),
		Provider:      in.Provider,
		FullName:      in.FullName,
		CloneURL:      strings.TrimSpace(in.CloneURL),
		DefaultBranch: strings.TrimSpace(in.DefaultBranch),
		SchemaVersion: domain.SourceRepositorySchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Source.InsertSourceRepository(ctx, repo); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(repo.CreatedAt, actor.TenantID, "source_repository.created", "source_repository", repo.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SourceRepository{}, err
		}
		l.repositories[repo.ID] = repo
		l.publishCommittedAuditEntryLocked(entry)
		return repo, nil
	}
	l.repositories[repo.ID] = repo
	_, _ = l.appendChainLocked(actor.TenantID, "source_repository.created", "source_repository", repo.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceRepository{}, err
	}
	return repo, nil
}

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

func matchesEvidenceSearch(item domain.EvidenceItem, in EvidenceSearchInput) bool {
	if in.ProductID != "" && item.ProductID != in.ProductID {
		return false
	}
	if in.ProjectID != "" && item.ProjectID != in.ProjectID {
		return false
	}
	if in.ReleaseID != "" && item.ReleaseID != in.ReleaseID {
		return false
	}
	if in.BuildID != "" && item.BuildID != in.BuildID {
		return false
	}
	if in.DeploymentID != "" && item.DeploymentID != in.DeploymentID {
		return false
	}
	if in.Type != "" && item.Type != in.Type {
		return false
	}
	if in.Subtype != "" && item.Subtype != in.Subtype {
		return false
	}
	if in.SourceSystem != "" && item.SourceSystem != in.SourceSystem {
		return false
	}
	if in.CollectorID != "" && item.CollectorID != in.CollectorID {
		return false
	}
	if in.VerificationStatus != "" && item.VerificationStatus != in.VerificationStatus {
		return false
	}
	if !in.CreatedAfter.IsZero() && item.CreatedAt.Before(in.CreatedAfter) {
		return false
	}
	if !in.CreatedBefore.IsZero() && item.CreatedAt.After(in.CreatedBefore) {
		return false
	}
	if in.Tag != "" && !containsString(item.Tags, in.Tag) {
		return false
	}
	if in.SubjectType != "" || in.SubjectID != "" {
		matched := false
		for _, ref := range item.SubjectRefs {
			if in.SubjectType != "" && ref.Type != in.SubjectType {
				continue
			}
			if in.SubjectID != "" && ref.ID != in.SubjectID && ref.Digest != in.SubjectID {
				continue
			}
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

func validLifecycleAction(action string) bool {
	switch action {
	case lifecycleAmendment, lifecycleRedaction, lifecycleTombstone, lifecycleRetentionMarker:
		return true
	default:
		return false
	}
}

func (l *Ledger) validateCandidateRefsLocked(tenantID, releaseID string, in CreateReleaseCandidateInput) error {
	for _, id := range in.BuildIDs {
		item, ok := l.buildRuns[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.ArtifactIDs {
		item, ok := l.artifacts[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	}
	for _, id := range in.SBOMIDs {
		item, ok := l.sboms[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.ScanIDs {
		item, ok := l.scans[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.VEXIDs {
		item, ok := l.vexDocuments[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.ContractIDs {
		item, ok := l.contracts[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.BundleIDs {
		item, ok := l.bundles[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	return nil
}

func validPullRequestState(state string) bool {
	switch state {
	case "open", "closed", "merged":
		return true
	default:
		return false
	}
}

func validDeploymentStatus(status string) bool {
	switch status {
	case deploymentStatusStarted, deploymentStatusSucceeded, deploymentStatusFailed, deploymentStatusRolledBack:
		return true
	default:
		return false
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
