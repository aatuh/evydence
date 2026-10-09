package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func decodeSourceCommitRecording(body []byte) (integrationapp.RecordSourceCommitInput, error) {
	var req struct {
		RepositoryID string    `json:"repository_id"`
		SHA          string    `json:"sha"`
		Author       string    `json:"author"`
		Message      string    `json:"message"`
		CommittedAt  time.Time `json:"committed_at"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return integrationapp.RecordSourceCommitInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "repository_id", "sha", "author", "message", "committed_at"); err != nil {
		return integrationapp.RecordSourceCommitInput{}, err
	}
	in, err := integrationapp.NormalizeSourceCommitInput(integrationapp.RecordSourceCommitInput{RepositoryID: req.RepositoryID, SHA: req.SHA, Author: req.Author, Message: req.Message, CommittedAt: req.CommittedAt})
	return in, mapSourceRepositoryCommandError(err)
}

func (s *Server) recordSourceCommit(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in integrationapp.RecordSourceCommitInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSourceCommitRecording(body)
		if err != nil {
			return err
		}
		return mapSourceRepositoryCommandError(s.sourceCommitCommands.AuthorizeSourceCommitRecording(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.sourceCommitCommands.RecordSourceCommit(ctx, a, in)
		return http.StatusCreated, sourceCommitFromCommand(v), mapSourceRepositoryCommandError(err)
	})
}

func sourceCommitFromCommand(v integrationdomain.SourceCommit) domain.SourceCommit {
	return domain.SourceCommit{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, SHA: v.SHA, Author: v.Author, MessageHash: v.MessageHash, CommittedAt: v.CommittedAt, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
