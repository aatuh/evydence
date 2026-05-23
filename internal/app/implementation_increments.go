package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
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

type CreateArtifactSignatureInput struct {
	ArtifactID       string
	Algorithm        string
	KeyID            string
	Signature        string
	RawPayload       []byte
	PayloadMediaType string
}

type CreateRepositoryInput struct {
	ProjectID     string
	Provider      string
	FullName      string
	CloneURL      string
	DefaultBranch string
}

type RecordCommitInput struct {
	RepositoryID string
	SHA          string
	Author       string
	Message      string
	CommittedAt  time.Time
}

type UpsertBranchInput struct {
	RepositoryID   string
	Name           string
	HeadCommitID   string
	Protected      bool
	ProtectionHash string
}

type RecordPullRequestInput struct {
	RepositoryID   string
	Provider       string
	ProviderID     string
	Title          string
	State          string
	SourceBranch   string
	TargetBranch   string
	HeadCommitID   string
	ReviewDecision string
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

func (l *Ledger) SearchEvidence(ctx context.Context, actor domain.Actor, in EvidenceSearchInput) ([]domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	if in.Limit <= 0 || in.Limit > 200 {
		in.Limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.EvidenceItem{}
	for _, item := range l.evidence {
		if item.TenantID != actor.TenantID || !matchesEvidenceSearch(item, in) {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeEvidenceRead, refsForEvidence(item)) {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > in.Limit {
		out = out[:in.Limit]
	}
	return out, nil
}

func (l *Ledger) RecordEvidenceLifecycleEvent(ctx context.Context, actor domain.Actor, evidenceID string, in RecordEvidenceLifecycleInput) (domain.EvidenceLifecycleEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceLifecycleEvent{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.EvidenceLifecycleEvent{}, err
	}
	in.Action = strings.TrimSpace(in.Action)
	in.Reason = strings.TrimSpace(in.Reason)
	if !validLifecycleAction(in.Action) || in.Reason == "" {
		return domain.EvidenceLifecycleEvent{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.evidence[strings.TrimSpace(evidenceID)]
	if !ok || item.TenantID != actor.TenantID {
		return domain.EvidenceLifecycleEvent{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, refsForEvidence(item)); err != nil {
		return domain.EvidenceLifecycleEvent{}, err
	}
	if in.ReplacementID != "" {
		replacement, ok := l.evidence[strings.TrimSpace(in.ReplacementID)]
		if !ok || replacement.TenantID != actor.TenantID {
			return domain.EvidenceLifecycleEvent{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, refsForEvidence(replacement)); err != nil {
			return domain.EvidenceLifecycleEvent{}, err
		}
	}
	event := domain.EvidenceLifecycleEvent{
		ID:            newID("elc"),
		TenantID:      actor.TenantID,
		EvidenceID:    item.ID,
		Action:        in.Action,
		Reason:        in.Reason,
		Details:       cloneMap(in.Details),
		ReplacementID: strings.TrimSpace(in.ReplacementID),
		ActorID:       actorID(actor),
		SchemaVersion: domain.EvidenceLifecycleSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.lifecycle[event.ID] = event
	_, _ = l.appendChainLocked(actor.TenantID, "evidence."+event.Action, "evidence_item", item.ID, actorType(actor), actorID(actor), item.PayloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceLifecycleEvent{}, err
	}
	return event, nil
}

func (l *Ledger) ListEvidenceLifecycleEvents(ctx context.Context, actor domain.Actor, evidenceID string) ([]domain.EvidenceLifecycleEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.evidence[strings.TrimSpace(evidenceID)]
	if !ok || item.TenantID != actor.TenantID {
		return nil, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, refsForEvidence(item)); err != nil {
		return nil, err
	}
	out := []domain.EvidenceLifecycleEvent{}
	for _, event := range l.lifecycle {
		if event.TenantID == actor.TenantID && event.EvidenceID == item.ID {
			out = append(out, event)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (l *Ledger) CreateReleaseCandidate(ctx context.Context, actor domain.Actor, in CreateReleaseCandidateInput) (domain.ReleaseCandidate, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[strings.TrimSpace(in.ReleaseID)]
	if !ok || release.TenantID != actor.TenantID {
		return domain.ReleaseCandidate{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	if strings.TrimSpace(in.Name) == "" {
		return domain.ReleaseCandidate{}, ErrValidation
	}
	if err := l.validateCandidateRefsLocked(actor.TenantID, release.ID, in); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	candidate := domain.ReleaseCandidate{
		ID:            newID("rc"),
		TenantID:      actor.TenantID,
		ReleaseID:     release.ID,
		Name:          strings.TrimSpace(in.Name),
		State:         candidateOpen,
		BuildIDs:      sortedStrings(in.BuildIDs),
		ArtifactIDs:   sortedStrings(in.ArtifactIDs),
		SBOMIDs:       sortedStrings(in.SBOMIDs),
		ScanIDs:       sortedStrings(in.ScanIDs),
		VEXIDs:        sortedStrings(in.VEXIDs),
		ContractIDs:   sortedStrings(in.ContractIDs),
		BundleIDs:     sortedStrings(in.BundleIDs),
		SchemaVersion: domain.ReleaseCandidateSchemaVersion,
		CreatedAt:     l.now(),
	}
	hash, err := canonicalAnyHash(candidate)
	if err != nil {
		return domain.ReleaseCandidate{}, err
	}
	candidate.SnapshotHash = hash
	l.candidates[candidate.ID] = candidate
	_, _ = l.appendChainLocked(actor.TenantID, "release_candidate.created", "release_candidate", candidate.ID, "api_key", actor.KeyID, hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func (l *Ledger) GetReleaseCandidate(ctx context.Context, actor domain.Actor, id string) (domain.ReleaseCandidate, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	if err := require(actor, ScopeReleaseRead); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	candidate, ok := l.candidates[strings.TrimSpace(id)]
	if !ok || candidate.TenantID != actor.TenantID {
		return domain.ReleaseCandidate{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseRead, resourceRefs{ReleaseID: candidate.ReleaseID}); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func (l *Ledger) ListReleaseCandidates(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.ReleaseCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeReleaseRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.ReleaseCandidate{}
	for _, candidate := range l.candidates {
		if candidate.TenantID != actor.TenantID {
			continue
		}
		if releaseID != "" && candidate.ReleaseID != releaseID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeReleaseRead, resourceRefs{ReleaseID: candidate.ReleaseID}) {
			continue
		}
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (l *Ledger) UpdateReleaseCandidateState(ctx context.Context, actor domain.Actor, id, state, reason string) (domain.ReleaseCandidate, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	state, reason = strings.TrimSpace(state), strings.TrimSpace(reason)
	if reason == "" || (state != candidatePromoted && state != candidateRejected) {
		return domain.ReleaseCandidate{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	candidate, ok := l.candidates[strings.TrimSpace(id)]
	if !ok || candidate.TenantID != actor.TenantID {
		return domain.ReleaseCandidate{}, ErrNotFound
	}
	if candidate.State != candidateOpen {
		return domain.ReleaseCandidate{}, ErrConflict
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ReleaseID: candidate.ReleaseID}); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	now := l.now()
	candidate.State = state
	if state == candidatePromoted {
		candidate.PromotedAt = &now
	} else {
		candidate.RejectedAt = &now
	}
	l.candidates[candidate.ID] = candidate
	_, _ = l.appendChainLocked(actor.TenantID, "release_candidate."+state, "release_candidate", candidate.ID, "api_key", actor.KeyID, candidate.SnapshotHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func (l *Ledger) RegisterContainerImage(ctx context.Context, actor domain.Actor, in RegisterContainerImageInput) (domain.ContainerImage, error) {
	if err := ctx.Err(); err != nil {
		return domain.ContainerImage{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.ContainerImage{}, err
	}
	in.Repository, in.Digest = strings.TrimSpace(in.Repository), strings.TrimSpace(in.Digest)
	if in.Repository == "" || !validDigest(in.Digest) {
		return domain.ContainerImage{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.ArtifactID != "" {
		artifact, ok := l.artifacts[strings.TrimSpace(in.ArtifactID)]
		if !ok || artifact.TenantID != actor.TenantID || artifact.Digest != in.Digest {
			return domain.ContainerImage{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ArtifactID: artifact.ID}); err != nil {
			return domain.ContainerImage{}, err
		}
	}
	for _, existing := range l.images {
		if existing.TenantID == actor.TenantID && existing.Repository == in.Repository && existing.Digest == in.Digest {
			return existing, nil
		}
	}
	image := domain.ContainerImage{
		ID:            newID("img"),
		TenantID:      actor.TenantID,
		ArtifactID:    strings.TrimSpace(in.ArtifactID),
		Repository:    in.Repository,
		Tag:           strings.TrimSpace(in.Tag),
		Digest:        in.Digest,
		Platform:      strings.TrimSpace(in.Platform),
		SchemaVersion: domain.ContainerImageSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.images[image.ID] = image
	_, _ = l.appendChainLocked(actor.TenantID, "container_image.created", "container_image", image.ID, "api_key", actor.KeyID, image.Digest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ContainerImage{}, err
	}
	return image, nil
}

func (l *Ledger) CreateArtifactSignature(ctx context.Context, actor domain.Actor, in CreateArtifactSignatureInput) (domain.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactSignature{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.ArtifactSignature{}, err
	}
	in.ArtifactID, in.Algorithm, in.Signature = strings.TrimSpace(in.ArtifactID), strings.TrimSpace(in.Algorithm), strings.TrimSpace(in.Signature)
	if in.ArtifactID == "" || in.Algorithm == "" || in.Signature == "" {
		return domain.ArtifactSignature{}, ErrValidation
	}
	l.mu.Lock()
	artifact, ok := l.artifacts[in.ArtifactID]
	if !ok || artifact.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.ArtifactSignature{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ArtifactID: artifact.ID}); err != nil {
		l.mu.Unlock()
		return domain.ArtifactSignature{}, err
	}
	l.mu.Unlock()
	payloadHash, payloadRef := "", ""
	if len(in.RawPayload) > 0 {
		payloadHash = hashBytes(in.RawPayload)
		ref, err := l.storePayload(ctx, actor.TenantID, "artifact-signature", nonEmpty(in.PayloadMediaType, "application/octet-stream"), payloadHash, in.RawPayload)
		if err != nil {
			return domain.ArtifactSignature{}, err
		}
		payloadRef = ref
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sig := domain.ArtifactSignature{
		ID:                 newID("artsig"),
		TenantID:           actor.TenantID,
		ArtifactID:         artifact.ID,
		SubjectDigest:      artifact.Digest,
		Algorithm:          in.Algorithm,
		KeyID:              strings.TrimSpace(in.KeyID),
		Signature:          in.Signature,
		PayloadRef:         payloadRef,
		PayloadHash:        payloadHash,
		VerificationStatus: "recorded",
		SchemaVersion:      domain.ArtifactSignatureSchemaVersion,
		CreatedAt:          l.now(),
	}
	l.artifactSigs[sig.ID] = sig
	_, _ = l.appendChainLocked(actor.TenantID, "artifact_signature.created", "artifact_signature", sig.ID, "api_key", actor.KeyID, artifact.Digest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ArtifactSignature{}, err
	}
	return sig, nil
}

func (l *Ledger) GetArtifactSignature(ctx context.Context, actor domain.Actor, id string) (domain.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactSignature{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.ArtifactSignature{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sig, ok := l.artifactSigs[strings.TrimSpace(id)]
	if !ok || sig.TenantID != actor.TenantID {
		return domain.ArtifactSignature{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ArtifactID: sig.ArtifactID}); err != nil {
		return domain.ArtifactSignature{}, err
	}
	return sig, nil
}

func (l *Ledger) ListSourceRepositories(ctx context.Context, actor domain.Actor, projectID string) ([]domain.SourceRepository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeSourceRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.SourceRepository{}
	for _, repo := range l.repositories {
		if repo.TenantID != actor.TenantID {
			continue
		}
		if projectID != "" && repo.ProjectID != projectID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeSourceRead, resourceRefs{ProjectID: repo.ProjectID, SourceRepositoryID: repo.ID}) {
			continue
		}
		out = append(out, repo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (l *Ledger) CreateSourceRepository(ctx context.Context, actor domain.Actor, in CreateRepositoryInput) (domain.SourceRepository, error) {
	if err := ctx.Err(); err != nil {
		return domain.SourceRepository{}, err
	}
	if err := require(actor, ScopeSourceWrite); err != nil {
		return domain.SourceRepository{}, err
	}
	in.Provider, in.FullName = strings.TrimSpace(in.Provider), strings.TrimSpace(in.FullName)
	if in.Provider == "" || in.FullName == "" {
		return domain.SourceRepository{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.ProjectID != "" {
		project, ok := l.projects[strings.TrimSpace(in.ProjectID)]
		if !ok || project.TenantID != actor.TenantID {
			return domain.SourceRepository{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeSourceWrite, resourceRefs{ProductID: project.ProductID, ProjectID: project.ID}); err != nil {
			return domain.SourceRepository{}, err
		}
	}
	for _, existing := range l.repositories {
		if existing.TenantID == actor.TenantID && existing.Provider == in.Provider && existing.FullName == in.FullName {
			return existing, nil
		}
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
	l.repositories[repo.ID] = repo
	_, _ = l.appendChainLocked(actor.TenantID, "source_repository.created", "source_repository", repo.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceRepository{}, err
	}
	return repo, nil
}

func (l *Ledger) RecordSourceCommit(ctx context.Context, actor domain.Actor, in RecordCommitInput) (domain.SourceCommit, error) {
	if err := ctx.Err(); err != nil {
		return domain.SourceCommit{}, err
	}
	if err := require(actor, ScopeSourceWrite); err != nil {
		return domain.SourceCommit{}, err
	}
	in.RepositoryID, in.SHA = strings.TrimSpace(in.RepositoryID), strings.TrimSpace(in.SHA)
	if in.RepositoryID == "" || !validCommitSHA(in.SHA) {
		return domain.SourceCommit{}, ErrValidation
	}
	if in.CommittedAt.IsZero() {
		in.CommittedAt = l.now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	repo, ok := l.repositories[in.RepositoryID]
	if !ok || repo.TenantID != actor.TenantID {
		return domain.SourceCommit{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeSourceWrite, resourceRefs{ProjectID: repo.ProjectID, SourceRepositoryID: repo.ID}); err != nil {
		return domain.SourceCommit{}, err
	}
	for _, existing := range l.commits {
		if existing.TenantID == actor.TenantID && existing.RepositoryID == repo.ID && existing.SHA == in.SHA {
			return existing, nil
		}
	}
	messageHash := ""
	if strings.TrimSpace(in.Message) != "" {
		messageHash = hashBytes([]byte(in.Message))
	}
	commit := domain.SourceCommit{
		ID:            newID("commit"),
		TenantID:      actor.TenantID,
		RepositoryID:  repo.ID,
		SHA:           strings.ToLower(in.SHA),
		Author:        strings.TrimSpace(in.Author),
		MessageHash:   messageHash,
		CommittedAt:   in.CommittedAt.UTC(),
		SchemaVersion: domain.SourceCommitSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.commits[commit.ID] = commit
	_, _ = l.appendChainLocked(actor.TenantID, "source_commit.recorded", "source_commit", commit.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceCommit{}, err
	}
	return commit, nil
}

func (l *Ledger) UpsertSourceBranch(ctx context.Context, actor domain.Actor, in UpsertBranchInput) (domain.SourceBranch, error) {
	if err := ctx.Err(); err != nil {
		return domain.SourceBranch{}, err
	}
	if err := require(actor, ScopeSourceWrite); err != nil {
		return domain.SourceBranch{}, err
	}
	in.RepositoryID, in.Name = strings.TrimSpace(in.RepositoryID), strings.TrimSpace(in.Name)
	if in.RepositoryID == "" || in.Name == "" {
		return domain.SourceBranch{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	repo, ok := l.repositories[in.RepositoryID]
	if !ok || repo.TenantID != actor.TenantID {
		return domain.SourceBranch{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeSourceWrite, resourceRefs{ProjectID: repo.ProjectID, SourceRepositoryID: repo.ID}); err != nil {
		return domain.SourceBranch{}, err
	}
	if in.HeadCommitID != "" {
		commit, ok := l.commits[strings.TrimSpace(in.HeadCommitID)]
		if !ok || commit.TenantID != actor.TenantID || commit.RepositoryID != repo.ID {
			return domain.SourceBranch{}, ErrNotFound
		}
	}
	for id, existing := range l.branches {
		if existing.TenantID == actor.TenantID && existing.RepositoryID == repo.ID && existing.Name == in.Name {
			existing.HeadCommitID = strings.TrimSpace(in.HeadCommitID)
			existing.Protected = in.Protected
			existing.ProtectionHash = strings.TrimSpace(in.ProtectionHash)
			l.branches[id] = existing
			_, _ = l.appendChainLocked(actor.TenantID, "source_branch.updated", "source_branch", existing.ID, actorType(actor), actorID(actor), existing.ProtectionHash, "")
			if err := l.persistLocked(ctx); err != nil {
				return domain.SourceBranch{}, err
			}
			return existing, nil
		}
	}
	branch := domain.SourceBranch{
		ID:             newID("branch"),
		TenantID:       actor.TenantID,
		RepositoryID:   repo.ID,
		Name:           in.Name,
		HeadCommitID:   strings.TrimSpace(in.HeadCommitID),
		Protected:      in.Protected,
		ProtectionHash: strings.TrimSpace(in.ProtectionHash),
		SchemaVersion:  domain.SourceBranchSchemaVersion,
		CreatedAt:      l.now(),
	}
	l.branches[branch.ID] = branch
	_, _ = l.appendChainLocked(actor.TenantID, "source_branch.created", "source_branch", branch.ID, actorType(actor), actorID(actor), branch.ProtectionHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceBranch{}, err
	}
	return branch, nil
}

func (l *Ledger) RecordPullRequest(ctx context.Context, actor domain.Actor, in RecordPullRequestInput) (domain.PullRequest, error) {
	if err := ctx.Err(); err != nil {
		return domain.PullRequest{}, err
	}
	if err := require(actor, ScopeSourceWrite); err != nil {
		return domain.PullRequest{}, err
	}
	in.RepositoryID, in.ProviderID, in.Title, in.State = strings.TrimSpace(in.RepositoryID), strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.Title), strings.TrimSpace(in.State)
	if in.RepositoryID == "" || in.ProviderID == "" || in.Title == "" || !validPullRequestState(in.State) {
		return domain.PullRequest{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	repo, ok := l.repositories[in.RepositoryID]
	if !ok || repo.TenantID != actor.TenantID {
		return domain.PullRequest{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeSourceWrite, resourceRefs{ProjectID: repo.ProjectID, SourceRepositoryID: repo.ID}); err != nil {
		return domain.PullRequest{}, err
	}
	if in.HeadCommitID != "" {
		commit, ok := l.commits[strings.TrimSpace(in.HeadCommitID)]
		if !ok || commit.TenantID != actor.TenantID || commit.RepositoryID != repo.ID {
			return domain.PullRequest{}, ErrNotFound
		}
	}
	pr := domain.PullRequest{
		ID:             newID("pr"),
		TenantID:       actor.TenantID,
		RepositoryID:   repo.ID,
		Provider:       nonEmpty(in.Provider, repo.Provider),
		ProviderID:     in.ProviderID,
		Title:          in.Title,
		State:          in.State,
		SourceBranch:   strings.TrimSpace(in.SourceBranch),
		TargetBranch:   strings.TrimSpace(in.TargetBranch),
		HeadCommitID:   strings.TrimSpace(in.HeadCommitID),
		ReviewDecision: strings.TrimSpace(in.ReviewDecision),
		SchemaVersion:  domain.PullRequestSchemaVersion,
		CreatedAt:      l.now(),
	}
	l.pullRequests[pr.ID] = pr
	_, _ = l.appendChainLocked(actor.TenantID, "pull_request.recorded", "pull_request", pr.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PullRequest{}, err
	}
	return pr, nil
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
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
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
	})
	if err != nil {
		return domain.DeploymentEvent{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
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
		EvidenceID:    item.ID,
		SchemaVersion: domain.DeploymentEventSchemaVersion,
		CreatedAt:     l.now(),
	}
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

func (l *Ledger) UploadGitHubSourceSnapshot(ctx context.Context, actor domain.Actor, raw []byte) (map[string]any, error) {
	return l.uploadSourceSnapshot(ctx, actor, "github", raw)
}

func (l *Ledger) UploadGitLabSourceSnapshot(ctx context.Context, actor domain.Actor, raw []byte) (map[string]any, error) {
	return l.uploadSourceSnapshot(ctx, actor, "gitlab", raw)
}

type sourceSnapshot struct {
	ProjectID  string `json:"project_id"`
	Repository struct {
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	Commit *struct {
		SHA         string    `json:"sha"`
		Author      string    `json:"author"`
		Message     string    `json:"message"`
		CommittedAt time.Time `json:"committed_at"`
	} `json:"commit,omitempty"`
	Branch *struct {
		Name           string `json:"name"`
		Protected      bool   `json:"protected"`
		ProtectionHash string `json:"protection_hash"`
	} `json:"branch,omitempty"`
	PullRequest *struct {
		ProviderID     string `json:"provider_id"`
		Title          string `json:"title"`
		State          string `json:"state"`
		SourceBranch   string `json:"source_branch"`
		TargetBranch   string `json:"target_branch"`
		ReviewDecision string `json:"review_decision"`
	} `json:"pull_request,omitempty"`
}

func (l *Ledger) uploadSourceSnapshot(ctx context.Context, actor domain.Actor, provider string, raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return nil, ErrValidation
	}
	var snapshot sourceSnapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snapshot); err != nil {
		return nil, ErrValidation
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrValidation
	}
	repo, err := l.CreateSourceRepository(ctx, actor, CreateRepositoryInput{
		ProjectID:     snapshot.ProjectID,
		Provider:      provider,
		FullName:      snapshot.Repository.FullName,
		CloneURL:      snapshot.Repository.CloneURL,
		DefaultBranch: snapshot.Repository.DefaultBranch,
	})
	if err != nil {
		return nil, err
	}
	var commit domain.SourceCommit
	if snapshot.Commit != nil {
		commit, err = l.RecordSourceCommit(ctx, actor, RecordCommitInput{
			RepositoryID: repo.ID,
			SHA:          snapshot.Commit.SHA,
			Author:       snapshot.Commit.Author,
			Message:      snapshot.Commit.Message,
			CommittedAt:  snapshot.Commit.CommittedAt,
		})
		if err != nil {
			return nil, err
		}
	}
	var branch domain.SourceBranch
	if snapshot.Branch != nil {
		branch, err = l.UpsertSourceBranch(ctx, actor, UpsertBranchInput{
			RepositoryID:   repo.ID,
			Name:           snapshot.Branch.Name,
			HeadCommitID:   commit.ID,
			Protected:      snapshot.Branch.Protected,
			ProtectionHash: snapshot.Branch.ProtectionHash,
		})
		if err != nil {
			return nil, err
		}
	}
	var pr domain.PullRequest
	if snapshot.PullRequest != nil {
		pr, err = l.RecordPullRequest(ctx, actor, RecordPullRequestInput{
			RepositoryID:   repo.ID,
			Provider:       provider,
			ProviderID:     snapshot.PullRequest.ProviderID,
			Title:          snapshot.PullRequest.Title,
			State:          snapshot.PullRequest.State,
			SourceBranch:   snapshot.PullRequest.SourceBranch,
			TargetBranch:   snapshot.PullRequest.TargetBranch,
			HeadCommitID:   commit.ID,
			ReviewDecision: snapshot.PullRequest.ReviewDecision,
		})
		if err != nil {
			return nil, err
		}
	}
	return map[string]any{"repository": repo, "commit": commit, "branch": branch, "pull_request": pr}, nil
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
