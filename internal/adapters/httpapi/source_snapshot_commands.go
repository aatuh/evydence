package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func (s *Server) recordSourceSnapshot(ctx requestContext, actor domain.Actor, provider string, body []byte) (int, any, error) {
	in, err := decodeSourceSnapshot(body)
	if err != nil {
		return 0, nil, err
	}
	v, err := s.sourceSnapshotCommands.RecordSourceSnapshot(ctx, actor, provider, in)
	if err != nil {
		return 0, nil, mapSourceRepositoryCommandError(err)
	}
	return http.StatusCreated, map[string]any{"repository": sourceRepositoryFromQuery(v.Repository), "commit": sourceCommitFromCommand(v.Commit), "branch": sourceBranchFromCommand(v.Branch), "pull_request": pullRequestFromCommand(v.PullRequest)}, nil
}

func decodeSourceSnapshot(body []byte) (integrationapp.SourceSnapshotInput, error) {
	var req struct {
		ProjectID  string `json:"project_id"`
		Repository *struct {
			FullName      string `json:"full_name"`
			CloneURL      string `json:"clone_url"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
		Commit *struct {
			SHA         string    `json:"sha"`
			Author      string    `json:"author"`
			Message     string    `json:"message"`
			CommittedAt time.Time `json:"committed_at"`
		} `json:"commit"`
		Branch *struct {
			Name           string `json:"name"`
			Protected      bool   `json:"protected"`
			ProtectionHash string `json:"protection_hash"`
		} `json:"branch"`
		PullRequest *struct {
			ProviderID     string `json:"provider_id"`
			Title          string `json:"title"`
			State          string `json:"state"`
			SourceBranch   string `json:"source_branch"`
			TargetBranch   string `json:"target_branch"`
			ReviewDecision string `json:"review_decision"`
		} `json:"pull_request"`
	}
	if err := decodeJSON(body, &req); err != nil {
		return integrationapp.SourceSnapshotInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "project_id", "repository", "commit", "branch", "pull_request"); err != nil {
		return integrationapp.SourceSnapshotInput{}, err
	}
	if req.Repository == nil {
		return integrationapp.SourceSnapshotInput{}, app.ErrValidation
	}
	var objects map[string]json.RawMessage
	if err := json.Unmarshal(body, &objects); err != nil {
		return integrationapp.SourceSnapshotInput{}, app.ErrValidation
	}
	for object, fields := range map[string][]string{
		"repository":   {"full_name", "clone_url", "default_branch"},
		"commit":       {"sha", "author", "message", "committed_at"},
		"branch":       {"name", "protected", "protection_hash"},
		"pull_request": {"provider_id", "title", "state", "source_branch", "target_branch", "review_decision"},
	} {
		if raw, ok := objects[object]; ok {
			if err := validateNonNullableObjectFields(raw, fields...); err != nil {
				return integrationapp.SourceSnapshotInput{}, err
			}
		}
	}
	in := integrationapp.SourceSnapshotInput{ProjectID: req.ProjectID, Repository: integrationapp.SourceSnapshotRepositoryInput{FullName: req.Repository.FullName, CloneURL: req.Repository.CloneURL, DefaultBranch: req.Repository.DefaultBranch}}
	if v := req.Commit; v != nil {
		in.Commit = &integrationapp.SourceSnapshotCommitInput{SHA: v.SHA, Author: v.Author, Message: v.Message, CommittedAt: v.CommittedAt}
	}
	if v := req.Branch; v != nil {
		in.Branch = &integrationapp.SourceSnapshotBranchInput{Name: v.Name, Protected: v.Protected, ProtectionHash: v.ProtectionHash}
	}
	if v := req.PullRequest; v != nil {
		in.PullRequest = &integrationapp.SourceSnapshotPullRequestInput{ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, ReviewDecision: v.ReviewDecision}
	}
	return in, nil
}
