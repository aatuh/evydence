package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func buildRunFromQuery(build releasedomain.BuildRun) domain.BuildRun {
	result := domain.BuildRun{
		ID: build.ID, TenantID: build.TenantID, ProjectID: build.ProjectID,
		ReleaseID: build.ReleaseID, CollectorID: build.CollectorID,
		Provider: build.Provider, CommitSHA: build.CommitSHA, Repository: build.Repository,
		WorkflowRef: build.WorkflowRef, RunID: build.RunID, RunAttempt: build.RunAttempt,
		JobID: build.JobID, Actor: build.Actor, Ref: build.Ref, OIDCSubject: build.OIDCSubject,
		Status: build.Status, StartedAt: build.StartedAt, FinishedAt: build.FinishedAt,
		ParametersHash: build.ParametersHash, EnvironmentHash: build.EnvironmentHash,
		SourceIdentity: build.SourceIdentity, SchemaVersion: build.SchemaVersion, CreatedAt: build.CreatedAt,
	}
	for _, output := range build.Outputs {
		result.Outputs = append(result.Outputs, domain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return result
}
