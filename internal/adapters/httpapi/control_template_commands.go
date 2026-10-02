package httpapi

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ControlTemplateCommands interface {
	InstallControlFrameworkTemplatePack(context.Context, identitydomain.Actor, string) (riskdomain.ControlFramework, error)
}

// Validate before durable replay reservation: the decoded route path itself
// is part of the PostgreSQL idempotency key, so NUL/invalid UTF-8 must not reach
// that storage boundary even when the owning command would reject the slug.
func validateControlTemplateSlug(slug string) error {
	slug = strings.TrimSpace(slug)
	if len(slug) > 1024 || !utf8.ValidString(slug) || strings.ContainsRune(slug, 0) {
		return app.ErrValidation
	}
	return nil
}
