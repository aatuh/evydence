package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Unchanged historical policy creation: test-only characterization oracle.

type CreateRedactionProfileInput struct {
	Name           string
	Description    string
	Preset         string
	AllowedTypes   []string
	ExcludedFields []string
}

func (l *Ledger) CreateRedactionProfile(ctx context.Context, actor domain.Actor, in CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	value, err := l.packageCommands.CreateRedactionProfile(ctx, actor, packageapp.CreateRedactionProfileInput{
		Name: in.Name, Description: in.Description, Preset: in.Preset,
		AllowedTypes: append([]string(nil), in.AllowedTypes...), ExcludedFields: append([]string(nil), in.ExcludedFields...),
	})
	return redactionProfileFromPackageContext(value), fromPackageContextError(err)
}
