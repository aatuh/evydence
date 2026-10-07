package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ControlTemplateCommands interface {
	AuthorizeControlTemplateInstallation(context.Context, identitydomain.Actor, string) error
	InstallControlFrameworkTemplatePack(context.Context, identitydomain.Actor, string) (riskdomain.ControlFramework, error)
}

// Validate before durable replay reservation: the decoded route path itself
// is part of the PostgreSQL idempotency key, so NUL/invalid UTF-8 must not reach
// that storage boundary even when the owning command would reject the slug.
func validateControlTemplateSlug(slug string) error {
	_, err := riskapp.NormalizeControlTemplateSlug(slug)
	return mapControlCommandError(err)
}

func decodeControlTemplateInstallBody(body []byte) error {
	if !utf8.Valid(body) {
		return app.ErrValidation
	}
	// Preserve omitted/blank bodies and their exact byte fingerprints.
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := decodeMembershipJSON(body, &struct{}{}); err != nil {
		return err
	}
	return validateExactNonNullableObjectFields(body)
}

func (s *Server) installControlFrameworkTemplatePack(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := validateControlTemplateSlug(r.PathValue("slug")); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		if err := decodeControlTemplateInstallBody(body); err != nil {
			return err
		}
		return mapControlCommandError(s.controlTemplateCommands.AuthorizeControlTemplateInstallation(ctx, a, r.PathValue("slug")))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.controlTemplateCommands.InstallControlFrameworkTemplatePack(ctx, a, r.PathValue("slug"))
		return http.StatusCreated, controlFrameworkFromQuery(v), mapControlCommandError(err)
	})
}
