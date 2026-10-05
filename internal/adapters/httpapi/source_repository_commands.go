package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func decodeSourceRepositoryCreation(body []byte) (integrationapp.CreateSourceRepositoryInput, error) {
	var req struct {
		ProjectID     string `json:"project_id"`
		Provider      string `json:"provider"`
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return integrationapp.CreateSourceRepositoryInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "project_id", "provider", "full_name", "clone_url", "default_branch"); err != nil {
		return integrationapp.CreateSourceRepositoryInput{}, err
	}
	in, err := integrationapp.NormalizeSourceRepositoryInput(integrationapp.CreateSourceRepositoryInput{ProjectID: req.ProjectID, Provider: req.Provider, FullName: req.FullName, CloneURL: req.CloneURL, DefaultBranch: req.DefaultBranch})
	return in, mapSourceRepositoryCommandError(err)
}

func localSourceRepositoryInput(in integrationapp.CreateSourceRepositoryInput) app.CreateRepositoryInput {
	return app.CreateRepositoryInput{ProjectID: in.ProjectID, Provider: in.Provider, FullName: in.FullName, CloneURL: in.CloneURL, DefaultBranch: in.DefaultBranch}
}

func (s *Server) createSourceRepository(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in integrationapp.CreateSourceRepositoryInput
	if s.sourceRepositoryCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeSourceRepositoryCreation(body)
			if err != nil {
				return err
			}
			if err := integrationapp.ValidateSourceRepositoryKey(a.TenantID, in); err != nil {
				return mapSourceRepositoryCommandError(err)
			}
			return mapSourceRepositoryCommandError(s.sourceRepositoryCommands.AuthorizeSourceRepositoryCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.sourceRepositoryCommands.CreateSourceRepository(ctx, a, in)
			return http.StatusCreated, sourceRepositoryFromQuery(v), mapSourceRepositoryCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ledger.CreateSourceRepository(ctx, a, localSourceRepositoryInput(in))
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeSourceRepositoryCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.ledger.AuthorizeSourceRepositoryCreation(r.Context(), a, localSourceRepositoryInput(in))
	})
}

func mapSourceRepositoryCommandError(err error) error {
	switch {
	case errors.Is(err, integrationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, integrationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, integrationapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
