package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func decodeSourceBranchUpsert(body []byte) (integrationapp.UpsertSourceBranchInput, error) {
	var req struct {
		RepositoryID   string `json:"repository_id"`
		Name           string `json:"name"`
		HeadCommitID   string `json:"head_commit_id"`
		Protected      bool   `json:"protected"`
		ProtectionHash string `json:"protection_hash"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return integrationapp.UpsertSourceBranchInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "repository_id", "name", "head_commit_id", "protected", "protection_hash"); err != nil {
		return integrationapp.UpsertSourceBranchInput{}, err
	}
	in, err := integrationapp.NormalizeSourceBranchInput(integrationapp.UpsertSourceBranchInput{RepositoryID: req.RepositoryID, Name: req.Name, HeadCommitID: req.HeadCommitID, Protected: req.Protected, ProtectionHash: req.ProtectionHash})
	return in, mapSourceRepositoryCommandError(err)
}

func (s *Server) upsertSourceBranch(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in integrationapp.UpsertSourceBranchInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSourceBranchUpsert(body)
		if err != nil {
			return err
		}
		if err := integrationapp.ValidateSourceBranchKey(a.TenantID, in); err != nil {
			return mapSourceRepositoryCommandError(err)
		}
		return mapSourceRepositoryCommandError(s.sourceBranchCommands.AuthorizeSourceBranchUpsert(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.sourceBranchCommands.UpsertSourceBranch(ctx, a, in)
		return http.StatusCreated, sourceBranchFromCommand(v), mapSourceRepositoryCommandError(err)
	})
}

func sourceBranchFromCommand(v integrationdomain.SourceBranch) domain.SourceBranch {
	return domain.SourceBranch{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, Name: v.Name, HeadCommitID: v.HeadCommitID, Protected: v.Protected, ProtectionHash: v.ProtectionHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
