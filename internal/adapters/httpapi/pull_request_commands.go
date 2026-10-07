package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func decodePullRequestRecording(body []byte) (integrationapp.RecordPullRequestInput, error) {
	var req struct {
		RepositoryID   string `json:"repository_id"`
		Provider       string `json:"provider"`
		ProviderID     string `json:"provider_id"`
		Title          string `json:"title"`
		State          string `json:"state"`
		SourceBranch   string `json:"source_branch"`
		TargetBranch   string `json:"target_branch"`
		HeadCommitID   string `json:"head_commit_id"`
		ReviewDecision string `json:"review_decision"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return integrationapp.RecordPullRequestInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "repository_id", "provider", "provider_id", "title", "state", "source_branch", "target_branch", "head_commit_id", "review_decision"); err != nil {
		return integrationapp.RecordPullRequestInput{}, err
	}
	in, err := integrationapp.NormalizePullRequestInput(integrationapp.RecordPullRequestInput{RepositoryID: req.RepositoryID, Provider: req.Provider, ProviderID: req.ProviderID, Title: req.Title, State: req.State, SourceBranch: req.SourceBranch, TargetBranch: req.TargetBranch, HeadCommitID: req.HeadCommitID, ReviewDecision: req.ReviewDecision})
	return in, mapSourceRepositoryCommandError(err)
}

func (s *Server) recordPullRequest(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in integrationapp.RecordPullRequestInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodePullRequestRecording(body)
		if err != nil {
			return err
		}
		return mapSourceRepositoryCommandError(s.pullRequestCommands.AuthorizePullRequestRecording(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.pullRequestCommands.RecordPullRequest(ctx, a, in)
		return http.StatusCreated, pullRequestFromCommand(v), mapSourceRepositoryCommandError(err)
	})
}

func pullRequestFromCommand(v integrationdomain.PullRequest) domain.PullRequest {
	return domain.PullRequest{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, Provider: v.Provider, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, HeadCommitID: v.HeadCommitID, ReviewDecision: v.ReviewDecision, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
