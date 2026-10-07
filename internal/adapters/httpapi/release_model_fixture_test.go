package httpapi

import (
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func releaseFixtureModel(value domain.Release) (releasedomain.Release, error) {
	return domain.ReleaseToContextModel(value)
}

func candidateFixtureModel(value domain.ReleaseCandidate) (releasedomain.ReleaseCandidate, error) {
	state, err := releasedomain.ParseReleaseCandidateState(value.State)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, app.ErrValidation
	}
	return releasedomain.ReleaseCandidate{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Name: value.Name, Revision: value.Revision, State: state, BuildIDs: value.BuildIDs, ArtifactIDs: value.ArtifactIDs, SBOMIDs: value.SBOMIDs, ScanIDs: value.ScanIDs, VEXIDs: value.VEXIDs, ContractIDs: value.ContractIDs, BundleIDs: value.BundleIDs, SnapshotHash: value.SnapshotHash, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt, PromotedAt: value.PromotedAt, RejectedAt: value.RejectedAt}, nil
}

func buildFixtureModel(value domain.BuildRun) releasedomain.BuildRun {
	outputs := make([]releasedomain.BuildOutput, 0, len(value.Outputs))
	for _, output := range value.Outputs {
		outputs = append(outputs, releasedomain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return releasedomain.BuildRun{ID: value.ID, TenantID: value.TenantID, ProjectID: value.ProjectID, ReleaseID: value.ReleaseID, CollectorID: value.CollectorID, Provider: value.Provider, CommitSHA: value.CommitSHA, Repository: value.Repository, WorkflowRef: value.WorkflowRef, RunID: value.RunID, RunAttempt: value.RunAttempt, JobID: value.JobID, Actor: value.Actor, Ref: value.Ref, OIDCSubject: value.OIDCSubject, Status: value.Status, StartedAt: value.StartedAt, FinishedAt: value.FinishedAt, ParametersHash: value.ParametersHash, EnvironmentHash: value.EnvironmentHash, SourceIdentity: value.SourceIdentity, Outputs: outputs, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}

func artifactFixtureModel(value domain.Artifact) releasedomain.Artifact {
	return releasedomain.Artifact{ID: value.ID, TenantID: value.TenantID, Name: value.Name, MediaType: value.MediaType, Digest: value.Digest, Size: value.Size, CreatedAt: value.CreatedAt}
}
