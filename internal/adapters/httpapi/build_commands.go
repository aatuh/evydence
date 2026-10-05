package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// BuildCommands exposes creation only, without unrelated release commands,
// attestation ingestion or cached catalog state.
type BuildCommands interface {
	AuthorizeBuildCreation(context.Context, identitydomain.Actor, releaseapp.CreateBuildRunInput) error
	CreateBuildRun(context.Context, identitydomain.Actor, releaseapp.CreateBuildRunInput) (releasedomain.BuildRun, error)
}

func decodeBuildCreation(body []byte) (releaseapp.CreateBuildRunInput, error) {
	var req struct {
		ProjectID        string               `json:"project_id"`
		ReleaseID        string               `json:"release_id"`
		Provider         string               `json:"provider"`
		CommitSHA        string               `json:"commit_sha"`
		Repository       string               `json:"repository"`
		WorkflowRef      string               `json:"workflow_ref"`
		RunID            string               `json:"run_id"`
		RunAttempt       int                  `json:"run_attempt"`
		JobID            string               `json:"job_id"`
		GitHubActor      string               `json:"actor"`
		Ref              string               `json:"ref"`
		OIDCSubject      string               `json:"oidc_subject"`
		Status           string               `json:"status"`
		StartedAt        time.Time            `json:"started_at"`
		FinishedAt       *time.Time           `json:"finished_at"`
		ParametersHash   string               `json:"parameters_hash"`
		EnvironmentHash  string               `json:"environment_hash"`
		ProviderMetadata map[string]any       `json:"provider_metadata"`
		Outputs          []domain.BuildOutput `json:"outputs"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.CreateBuildRunInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "project_id", "release_id", "provider", "commit_sha", "repository", "workflow_ref", "run_id", "run_attempt", "job_id", "actor", "ref", "oidc_subject", "status", "started_at", "finished_at", "parameters_hash", "environment_hash", "provider_metadata", "outputs"); err != nil {
		return releaseapp.CreateBuildRunInput{}, err
	}
	if err := validateNonNullableArrayItems(body, "outputs"); err != nil {
		return releaseapp.CreateBuildRunInput{}, err
	}
	var objects struct {
		Outputs []json.RawMessage `json:"outputs"`
	}
	if err := json.Unmarshal(body, &objects); err != nil {
		return releaseapp.CreateBuildRunInput{}, app.ErrValidation
	}
	for _, out := range objects.Outputs {
		if err := validateExactNonNullableObjectFields(out, "artifact_id", "digest"); err != nil {
			return releaseapp.CreateBuildRunInput{}, err
		}
	}
	outputs := make([]releasedomain.BuildOutput, 0, len(req.Outputs))
	for _, out := range req.Outputs {
		outputs = append(outputs, releasedomain.BuildOutput{ArtifactID: out.ArtifactID, Digest: out.Digest})
	}
	in := releaseapp.CreateBuildRunInput{ProjectID: req.ProjectID, ReleaseID: req.ReleaseID, Provider: req.Provider, CommitSHA: req.CommitSHA, Repository: req.Repository, WorkflowRef: req.WorkflowRef, RunID: req.RunID, RunAttempt: req.RunAttempt, JobID: req.JobID, GitHubActor: req.GitHubActor, Ref: req.Ref, OIDCSubject: req.OIDCSubject, Status: req.Status, StartedAt: req.StartedAt, FinishedAt: req.FinishedAt, ParametersHash: req.ParametersHash, EnvironmentHash: req.EnvironmentHash, ProviderMetadata: req.ProviderMetadata, Outputs: outputs}
	_, err := releaseapp.NormalizeBuildCreationInput(in)
	return in, mapBuildAttestationCommandError(err)
}

func localBuildCreationInput(in releaseapp.CreateBuildRunInput) app.CreateBuildRunInput {
	outputs := make([]domain.BuildOutput, 0, len(in.Outputs))
	for _, out := range in.Outputs {
		outputs = append(outputs, domain.BuildOutput{ArtifactID: out.ArtifactID, Digest: out.Digest})
	}
	return app.CreateBuildRunInput{ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, Provider: in.Provider, CommitSHA: in.CommitSHA, Repository: in.Repository, WorkflowRef: in.WorkflowRef, RunID: in.RunID, RunAttempt: in.RunAttempt, JobID: in.JobID, GitHubActor: in.GitHubActor, Ref: in.Ref, OIDCSubject: in.OIDCSubject, Status: in.Status, StartedAt: in.StartedAt, FinishedAt: in.FinishedAt, ParametersHash: in.ParametersHash, EnvironmentHash: in.EnvironmentHash, ProviderMetadata: in.ProviderMetadata, Outputs: outputs}
}

func (s *Server) createBuild(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.CreateBuildRunInput
	if s.buildCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeBuildCreation(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.buildCommands.AuthorizeBuildCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.buildCommands.CreateBuildRun(ctx, a, in)
			return http.StatusCreated, buildRunFromQuery(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.CreateBuildRun(ctx, a, localBuildCreationInput(in))
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeBuildCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeBuildCreation(r.Context(), a, in)
	})
}
