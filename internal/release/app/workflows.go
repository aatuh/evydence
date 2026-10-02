package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const (
	buildProviderGitHubActions = "github_actions"
	buildProviderGitLabCI      = "gitlab_ci"

	buildStatusQueued    = "queued"
	buildStatusRunning   = "running"
	buildStatusPassed    = "passed"
	buildStatusFailed    = "failed"
	buildStatusCancelled = "cancelled"
)

type CreateBuildRunInput struct {
	ProjectID        string
	ReleaseID        string
	Provider         string
	CommitSHA        string
	Repository       string
	WorkflowRef      string
	RunID            string
	RunAttempt       int
	JobID            string
	GitHubActor      string
	Ref              string
	OIDCSubject      string
	Status           string
	StartedAt        time.Time
	FinishedAt       *time.Time
	ParametersHash   string
	EnvironmentHash  string
	ProviderMetadata map[string]any
	Outputs          []releasedomain.BuildOutput
}

func (s *Service) CreateBuildRun(ctx context.Context, actor identitydomain.Actor, input CreateBuildRunInput) (releasedomain.BuildRun, error) {
	commands, err := NewBuildCommands(BuildCommandConfig{
		Reader: s.reader, Authorizer: s.authorizer,
		Transactions: releaseBuildTransactions{runner: s.transactions},
		Clock:        s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	return commands.CreateBuildRun(ctx, actor, input)
}

func (s *Service) GetBuildRun(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.BuildRun, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.BuildRun{}, err
	}
	if err := s.authorize(ctx, actor, ScopeBuildRead, application.ResourceReferences{}, true); err != nil {
		return releasedomain.BuildRun{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	build, err := s.reader.GetBuildRun(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	if build.TenantID != actor.TenantID || build.ID != id {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	project, err := s.reader.GetProject(ctx, actor.TenantID, build.ProjectID)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, build.ReleaseID)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	if !projectBelongsToTenant(project, actor.TenantID, build.ProjectID) || !releaseBelongsToTenant(release, actor.TenantID, build.ReleaseID) || project.ProductID != release.ProductID {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	resources := application.ResourceReferences{ProductID: project.ProductID, ProjectID: project.ID, ReleaseID: release.ID, BuildID: build.ID}
	if err := s.authorize(ctx, actor, ScopeBuildRead, resources, false); err != nil {
		return releasedomain.BuildRun{}, err
	}
	return build, nil
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

func (s *Service) CreateReleaseCandidate(ctx context.Context, actor identitydomain.Actor, input CreateReleaseCandidateInput) (releasedomain.ReleaseCandidate, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	release, err := s.reader.GetRelease(ctx, actor.TenantID, input.ReleaseID)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, input.ReleaseID) {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	resources := application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, resources, false); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return releasedomain.ReleaseCandidate{}, ErrValidation
	}
	references := normalizeReleaseCandidateReferences(input)
	if err := s.candidateReferences.ValidateReleaseCandidateReferences(ctx, actor.TenantID, release.ID, cloneReleaseCandidateReferences(references)); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	for _, artifactID := range references.ArtifactIDs {
		if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{ArtifactID: artifactID}, false); err != nil {
			return releasedomain.ReleaseCandidate{}, err
		}
	}
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	commandAt := s.clock.Now().UTC()
	candidate := releasedomain.ReleaseCandidate{
		ID: s.ids.NewID("rc"), TenantID: actor.TenantID, ReleaseID: release.ID, Name: input.Name,
		Revision: 1, State: state, BuildIDs: references.BuildIDs, ArtifactIDs: references.ArtifactIDs,
		SBOMIDs: references.SBOMIDs, ScanIDs: references.ScanIDs, VEXIDs: references.VEXIDs,
		ContractIDs: references.ContractIDs, BundleIDs: references.BundleIDs,
		SchemaVersion: releasedomain.ReleaseCandidateSchemaVersion, CreatedAt: commandAt,
	}
	hash, err := s.canonicalizer.HashReleaseCandidate(ctx, cloneReleaseCandidate(candidate))
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if !validDigest(hash) {
		return releasedomain.ReleaseCandidate{}, ErrValidation
	}
	candidate.SnapshotHash = hash

	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		currentRelease, err := tx.Catalog().GetRelease(ctx, actor.TenantID, release.ID)
		if err != nil {
			return err
		}
		if !releaseBelongsToTenant(currentRelease, actor.TenantID, release.ID) {
			return ErrNotFound
		}
		if !sameReleaseCoordinates(currentRelease, release) {
			return ErrConflict
		}
		for _, buildID := range references.BuildIDs {
			build, err := tx.Builds().GetBuildRun(ctx, actor.TenantID, buildID)
			if err != nil {
				return err
			}
			if build.TenantID != actor.TenantID || build.ID != buildID {
				return ErrNotFound
			}
			if build.ReleaseID != release.ID {
				return ErrConflict
			}
		}
		for _, artifactID := range references.ArtifactIDs {
			artifact, err := tx.Catalog().GetArtifact(ctx, actor.TenantID, artifactID)
			if err != nil {
				return err
			}
			if !artifactBelongsToTenant(artifact, actor.TenantID, artifactID) {
				return ErrNotFound
			}
		}
		if err := tx.Catalog().InsertReleaseCandidate(ctx, candidate); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, commandAt, "release_candidate.created", "release_candidate", candidate.ID, candidate.SnapshotHash))
		return err
	})
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func (s *Service) GetReleaseCandidate(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.ReleaseCandidate, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseRead, application.ResourceReferences{}, true); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	candidate, err := s.reader.GetReleaseCandidate(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if candidate.TenantID != actor.TenantID || candidate.ID != id {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, candidate.ReleaseID)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, candidate.ReleaseID) {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	resources := application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}
	if err := s.authorize(ctx, actor, ScopeReleaseRead, resources, false); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func (s *Service) ListReleaseCandidates(ctx context.Context, actor identitydomain.Actor, releaseID string) ([]releasedomain.ReleaseCandidate, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseRead, application.ResourceReferences{}, true); err != nil {
		return nil, err
	}
	releaseID = strings.TrimSpace(releaseID)
	candidates, err := s.reader.ListReleaseCandidates(ctx, actor.TenantID, releaseID)
	if err != nil {
		return nil, err
	}
	result := make([]releasedomain.ReleaseCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.TenantID != actor.TenantID || (releaseID != "" && candidate.ReleaseID != releaseID) {
			continue
		}
		release, err := s.reader.GetRelease(ctx, actor.TenantID, candidate.ReleaseID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !releaseBelongsToTenant(release, actor.TenantID, candidate.ReleaseID) {
			continue
		}
		resources := application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}
		if err := s.authorize(ctx, actor, ScopeReleaseRead, resources, false); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return nil, err
		}
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *Service) UpdateReleaseCandidateState(ctx context.Context, actor identitydomain.Actor, id, state, reason string, expectedRevision int64) (releasedomain.ReleaseCandidate, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	state = strings.TrimSpace(state)
	reason = strings.TrimSpace(reason)
	if reason == "" || (state != releasedomain.ReleaseCandidateStatePromotedValue && state != releasedomain.ReleaseCandidateStateRejectedValue) || expectedRevision < 1 {
		return releasedomain.ReleaseCandidate{}, ErrValidation
	}
	id = strings.TrimSpace(id)
	candidate, err := s.reader.GetReleaseCandidate(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if candidate.TenantID != actor.TenantID || candidate.ID != id {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, candidate.ReleaseID)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, candidate.ReleaseID) {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	resources := application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, resources, false); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if candidate.Revision != expectedRevision {
		return releasedomain.ReleaseCandidate{}, NewVersionConflict(candidate.Revision)
	}
	if candidate.State.String() != releasedomain.ReleaseCandidateStateOpenValue {
		return releasedomain.ReleaseCandidate{}, ErrConflict
	}
	nextState, _ := releasedomain.ParseReleaseCandidateState(state)
	commandAt := s.clock.Now().UTC()
	var updated releasedomain.ReleaseCandidate
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := tx.Catalog().GetReleaseCandidate(ctx, actor.TenantID, candidate.ID)
		if err != nil {
			return err
		}
		if current.TenantID != actor.TenantID || current.ID != candidate.ID {
			return ErrNotFound
		}
		if current.ReleaseID != candidate.ReleaseID {
			return ErrConflict
		}
		currentRelease, err := tx.Catalog().GetRelease(ctx, actor.TenantID, current.ReleaseID)
		if err != nil {
			return err
		}
		if !releaseBelongsToTenant(currentRelease, actor.TenantID, current.ReleaseID) {
			return ErrNotFound
		}
		if !sameReleaseCoordinates(currentRelease, release) {
			return ErrConflict
		}
		if current.Revision != expectedRevision {
			return NewVersionConflict(current.Revision)
		}
		if current.State.String() != releasedomain.ReleaseCandidateStateOpenValue {
			return ErrConflict
		}
		updated = current
		updated.State = nextState
		updated.Revision++
		if state == releasedomain.ReleaseCandidateStatePromotedValue {
			at := commandAt
			updated.PromotedAt = &at
		} else {
			at := commandAt
			updated.RejectedAt = &at
		}
		if err := tx.Catalog().UpdateReleaseCandidateState(ctx, updated, expectedRevision, releasedomain.ReleaseCandidateStateOpenValue); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, commandAt, "release_candidate."+state, "release_candidate", updated.ID, updated.SnapshotHash))
		return err
	})
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return updated, nil
}

type RegisterContainerImageInput struct {
	ArtifactID string
	Repository string
	Tag        string
	Digest     string
	Platform   string
}

func (s *Service) RegisterContainerImage(ctx context.Context, actor identitydomain.Actor, input RegisterContainerImageInput) (releasedomain.ContainerImage, error) {
	commands, err := NewContainerImageCommands(ContainerImageCommandConfig{
		Reader: s.reader, Authorizer: s.authorizer,
		Transactions: releaseContainerImageTransactions{s.transactions}, Clock: s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.ContainerImage{}, err
	}
	return commands.RegisterContainerImage(ctx, actor, input)
}

func normalizeBuildInput(input CreateBuildRunInput) (releasedomain.BuildRun, error) {
	for _, text := range []string{input.ProjectID, input.ReleaseID, input.Provider, input.CommitSHA, input.Repository, input.WorkflowRef, input.RunID, input.JobID, input.GitHubActor, input.Ref, input.OIDCSubject, input.Status, input.ParametersHash, input.EnvironmentHash} {
		if !validBuildText(text) {
			return releasedomain.BuildRun{}, ErrValidation
		}
	}
	if err := validateBuildMetadata(input.ProviderMetadata); err != nil {
		return releasedomain.BuildRun{}, err
	}
	build := releasedomain.BuildRun{
		ProjectID: strings.TrimSpace(input.ProjectID), ReleaseID: strings.TrimSpace(input.ReleaseID),
		Provider: strings.TrimSpace(input.Provider), CommitSHA: strings.TrimSpace(input.CommitSHA),
		Repository: strings.TrimSpace(input.Repository), WorkflowRef: strings.TrimSpace(input.WorkflowRef),
		RunID: strings.TrimSpace(input.RunID), RunAttempt: input.RunAttempt, JobID: strings.TrimSpace(input.JobID),
		Actor: strings.TrimSpace(input.GitHubActor), Ref: strings.TrimSpace(input.Ref), OIDCSubject: strings.TrimSpace(input.OIDCSubject),
		Status: strings.TrimSpace(input.Status), StartedAt: input.StartedAt.UTC(), FinishedAt: input.FinishedAt,
		ParametersHash: strings.TrimSpace(input.ParametersHash), EnvironmentHash: strings.TrimSpace(input.EnvironmentHash),
		SourceIdentity: cloneAnyMap(input.ProviderMetadata), Outputs: normalizeBuildOutputs(input.Outputs),
	}
	if build.ProjectID == "" || build.ReleaseID == "" || build.Provider == "" || build.CommitSHA == "" || build.Status == "" || build.StartedAt.IsZero() {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if !validCommitSHA(build.CommitSHA) || !validBuildStatus(build.Status) {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if build.ParametersHash != "" && !validDigest(build.ParametersHash) {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if build.EnvironmentHash != "" && !validDigest(build.EnvironmentHash) {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if build.Provider == buildProviderGitHubActions && (build.Repository == "" || build.WorkflowRef == "" || build.RunID == "" || build.RunAttempt <= 0) {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if build.Provider == buildProviderGitLabCI && (build.Repository == "" || build.RunID == "") {
		return releasedomain.BuildRun{}, ErrValidation
	}
	for _, output := range build.Outputs {
		if !validDigest(output.Digest) {
			return releasedomain.BuildRun{}, ErrValidation
		}
	}
	return build, nil
}

func validBuildText(text string) bool {
	return utf8.ValidString(text) && !strings.ContainsRune(text, 0)
}

// Inspect encoded metadata using structured JSON tokens. PostgreSQL cannot
// store NUL characters in text or JSONB; unsupported/cyclic Go values must be
// rejected before repository reads, not reported as backend failures.
func validateBuildMetadata(metadata map[string]any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return ErrValidation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return ErrValidation
		}
		if text, ok := token.(string); ok && !validBuildText(text) {
			return ErrValidation
		}
	}
}

func normalizeBuildOutputs(outputs []releasedomain.BuildOutput) []releasedomain.BuildOutput {
	result := make([]releasedomain.BuildOutput, 0, len(outputs))
	for _, output := range outputs {
		result = append(result, releasedomain.BuildOutput{ArtifactID: strings.TrimSpace(output.ArtifactID), Digest: strings.TrimSpace(output.Digest)})
	}
	return result
}

func validCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validBuildStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case buildStatusQueued, buildStatusRunning, buildStatusPassed, buildStatusFailed, buildStatusCancelled:
		return true
	default:
		return false
	}
}

func buildSourceIdentity(build releasedomain.BuildRun, actor identitydomain.Actor) map[string]any {
	source := "api"
	if actor.CollectorID != "" {
		source = "collector"
	}
	identity := map[string]any{"source": source, "provider": build.Provider, "commit_sha": build.CommitSHA, "oidc_verified": false}
	if actor.CollectorID != "" {
		identity["collector_id"] = actor.CollectorID
	}
	if build.Repository != "" {
		identity["repository"] = build.Repository
	}
	if build.WorkflowRef != "" {
		identity["workflow_ref"] = build.WorkflowRef
	}
	if build.RunID != "" {
		identity["run_id"] = build.RunID
	}
	if build.RunAttempt > 0 {
		identity["run_attempt"] = build.RunAttempt
	}
	if build.JobID != "" {
		identity["job_id"] = build.JobID
	}
	if build.Actor != "" {
		identity["actor"] = build.Actor
	}
	if build.Ref != "" {
		identity["ref"] = build.Ref
	}
	if build.OIDCSubject != "" {
		identity["oidc_subject"] = build.OIDCSubject
	}
	for key, value := range build.SourceIdentity {
		if _, exists := identity[key]; !exists {
			identity[key] = value
		}
	}
	return identity
}

func auditActor(actor identitydomain.Actor) (string, string) {
	if actor.CollectorID != "" {
		return "collector", actor.CollectorID
	}
	if actor.UserID != "" {
		return "human_user", actor.UserID
	}
	return "api_key", actor.KeyID
}

func normalizeReleaseCandidateReferences(input CreateReleaseCandidateInput) ReleaseCandidateReferences {
	return ReleaseCandidateReferences{
		BuildIDs: sortedTrimmedStrings(input.BuildIDs), ArtifactIDs: sortedTrimmedStrings(input.ArtifactIDs),
		SBOMIDs: sortedTrimmedStrings(input.SBOMIDs), ScanIDs: sortedTrimmedStrings(input.ScanIDs),
		VEXIDs: sortedTrimmedStrings(input.VEXIDs), ContractIDs: sortedTrimmedStrings(input.ContractIDs),
		BundleIDs: sortedTrimmedStrings(input.BundleIDs),
	}
}

func cloneReleaseCandidateReferences(references ReleaseCandidateReferences) ReleaseCandidateReferences {
	return ReleaseCandidateReferences{
		BuildIDs: append([]string(nil), references.BuildIDs...), ArtifactIDs: append([]string(nil), references.ArtifactIDs...),
		SBOMIDs: append([]string(nil), references.SBOMIDs...), ScanIDs: append([]string(nil), references.ScanIDs...),
		VEXIDs: append([]string(nil), references.VEXIDs...), ContractIDs: append([]string(nil), references.ContractIDs...),
		BundleIDs: append([]string(nil), references.BundleIDs...),
	}
}

func cloneReleaseCandidate(candidate releasedomain.ReleaseCandidate) releasedomain.ReleaseCandidate {
	candidate.BuildIDs = append([]string(nil), candidate.BuildIDs...)
	candidate.ArtifactIDs = append([]string(nil), candidate.ArtifactIDs...)
	candidate.SBOMIDs = append([]string(nil), candidate.SBOMIDs...)
	candidate.ScanIDs = append([]string(nil), candidate.ScanIDs...)
	candidate.VEXIDs = append([]string(nil), candidate.VEXIDs...)
	candidate.ContractIDs = append([]string(nil), candidate.ContractIDs...)
	candidate.BundleIDs = append([]string(nil), candidate.BundleIDs...)
	return candidate
}

func sortedTrimmedStrings(values []string) []string {
	result := append([]string(nil), values...)
	for i := range result {
		result[i] = strings.TrimSpace(result[i])
	}
	sort.Strings(result)
	return result
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func productBelongsToTenant(product releasedomain.Product, tenantID, id string) bool {
	return product.TenantID == tenantID && product.ID == id
}

func projectBelongsToTenant(project releasedomain.Project, tenantID, id string) bool {
	return project.TenantID == tenantID && project.ID == id
}

func releaseBelongsToTenant(release releasedomain.Release, tenantID, id string) bool {
	return release.TenantID == tenantID && release.ID == id
}

func artifactBelongsToTenant(artifact releasedomain.Artifact, tenantID, id string) bool {
	return artifact.TenantID == tenantID && artifact.ID == id
}

func sameProductCoordinates(left, right releasedomain.Product) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.Slug == right.Slug
}

func sameProjectCoordinates(left, right releasedomain.Project) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.ProductID == right.ProductID
}

func sameReleaseCoordinates(left, right releasedomain.Release) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.ProductID == right.ProductID && left.Version == right.Version
}

func sameArtifactCoordinates(left, right releasedomain.Artifact) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.Digest == right.Digest
}
