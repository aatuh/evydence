package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// Historical aggregate workflow tests retain their original bodies.
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
	Outputs          []domain.BuildOutput
}

func (l *Ledger) CreateBuildRun(ctx context.Context, actor domain.Actor, in CreateBuildRunInput) (domain.BuildRun, error) {
	outputs := make([]releasedomain.BuildOutput, 0, len(in.Outputs))
	for _, output := range in.Outputs {
		outputs = append(outputs, releasedomain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	value, err := l.legacyReleaseCommands().CreateBuildRun(ctx, actor, releaseapp.CreateBuildRunInput{
		ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, Provider: in.Provider, CommitSHA: in.CommitSHA,
		Repository: in.Repository, WorkflowRef: in.WorkflowRef, RunID: in.RunID, RunAttempt: in.RunAttempt,
		JobID: in.JobID, GitHubActor: in.GitHubActor, Ref: in.Ref, OIDCSubject: in.OIDCSubject,
		Status: in.Status, StartedAt: in.StartedAt, FinishedAt: cloneTimePtr(in.FinishedAt),
		ParametersHash: in.ParametersHash, EnvironmentHash: in.EnvironmentHash,
		ProviderMetadata: cloneIdentityAnyMap(in.ProviderMetadata), Outputs: outputs,
	})
	return buildRunFromReleaseContext(value), fromReleaseContextError(err)
}

// UploadBuildAttestation is retained as an HTTP compatibility facade.
// Deprecated: use the focused release application service.
func (l *Ledger) UploadBuildAttestation(ctx context.Context, actor domain.Actor, buildID string, raw []byte) (domain.BuildAttestation, error) {
	value, err := l.legacyReleaseCommands().UploadBuildAttestation(ctx, actor, buildID, raw)
	return buildAttestationFromReleaseContext(value), fromReleaseContextError(err)
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

func (l *Ledger) CreateReleaseCandidate(ctx context.Context, actor domain.Actor, in CreateReleaseCandidateInput) (domain.ReleaseCandidate, error) {
	value, err := l.legacyReleaseCommands().CreateReleaseCandidate(ctx, actor, releaseapp.CreateReleaseCandidateInput{
		ReleaseID: in.ReleaseID, Name: in.Name, BuildIDs: append([]string(nil), in.BuildIDs...),
		ArtifactIDs: append([]string(nil), in.ArtifactIDs...), SBOMIDs: append([]string(nil), in.SBOMIDs...),
		ScanIDs: append([]string(nil), in.ScanIDs...), VEXIDs: append([]string(nil), in.VEXIDs...),
		ContractIDs: append([]string(nil), in.ContractIDs...), BundleIDs: append([]string(nil), in.BundleIDs...),
	})
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) UpdateReleaseCandidateState(ctx context.Context, actor domain.Actor, id, state, reason string, expectedRevision int64) (domain.ReleaseCandidate, error) {
	value, err := l.legacyReleaseCommands().UpdateReleaseCandidateState(ctx, actor, id, state, reason, expectedRevision)
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) RegisterContainerImage(ctx context.Context, actor domain.Actor, in RegisterContainerImageInput) (domain.ContainerImage, error) {
	value, err := l.legacyReleaseCommands().RegisterContainerImage(ctx, actor, releaseapp.RegisterContainerImageInput{
		ArtifactID: in.ArtifactID, Repository: in.Repository, Tag: in.Tag, Digest: in.Digest, Platform: in.Platform,
	})
	return containerImageFromReleaseContext(value), fromReleaseContextError(err)
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
