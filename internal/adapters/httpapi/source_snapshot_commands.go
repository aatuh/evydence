package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func (s *Server) recordSourceSnapshot(w http.ResponseWriter, r *http.Request, provider string) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in integrationapp.SourceSnapshotInput
	decode := func(body []byte) error {
		var err error
		in, err = decodeSourceSnapshot(body)
		if err != nil {
			return err
		}
		return mapSourceRepositoryCommandError(integrationapp.ValidateSourceSnapshotRequest(provider, in))
	}
	if s.sourceSnapshotCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			if err := decode(body); err != nil {
				return err
			}
			if err := integrationapp.ValidateSourceSnapshotKeys(a.TenantID, provider, in); err != nil {
				return mapSourceRepositoryCommandError(err)
			}
			return mapSourceRepositoryCommandError(s.sourceSnapshotCommands.AuthorizeSourceSnapshot(ctx, a, provider, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.sourceSnapshotCommands.RecordSourceSnapshot(ctx, a, provider, in)
			return http.StatusCreated, sourceSnapshotPublic(v), mapSourceRepositoryCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		var v map[string]any
		var err error
		if provider == "github" {
			v, err = s.ledger.UploadGitHubSourceSnapshot(ctx, a, body)
		} else {
			v, err = s.ledger.UploadGitLabSourceSnapshot(ctx, a, body)
		}
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if err := decode(body); err != nil {
			return nil, err
		}
		if err := integrationapp.ValidateSourceSnapshotKeys(a.TenantID, provider, in); err != nil {
			return nil, mapSourceRepositoryCommandError(err)
		}
		return body, s.ledger.AuthorizeSourceRepositoryCreation(r.Context(), a, localSourceRepositoryInput(integrationapp.CreateSourceRepositoryInput{ProjectID: in.ProjectID, Provider: provider, FullName: in.Repository.FullName, CloneURL: in.Repository.CloneURL, DefaultBranch: in.Repository.DefaultBranch}))
	})
}

func sourceSnapshotPublic(v integrationapp.SourceSnapshotResult) map[string]any {
	return map[string]any{"repository": sourceRepositoryFromQuery(v.Repository), "commit": sourceCommitFromCommand(v.Commit), "branch": sourceBranchFromCommand(v.Branch), "pull_request": pullRequestFromCommand(v.PullRequest)}
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
	if err := decodeMembershipJSON(body, &req); err != nil {
		return integrationapp.SourceSnapshotInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "project_id", "repository", "commit", "branch", "pull_request"); err != nil {
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
			if err := validateExactNonNullableObjectFields(raw, fields...); err != nil {
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
