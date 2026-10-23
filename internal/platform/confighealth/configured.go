package confighealth

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/platform/config"
)

// NewConfigured observes desired-source freshness against immutable startup
// settings. Source capture follows the shared schema; no settings are reloaded.
// The caller owns the source's lifetime and must honor the supplied context.
func NewConfigured(ctx context.Context, settings config.Configuration, current func(context.Context) (config.Environment, error)) (func(context.Context) error, error) {
	if current == nil || (settings.Role() != config.API && settings.Role() != config.Worker) {
		return nil, errConfigurationUnavailable
	}
	identity := settings.SourceIdentity()
	revision, path := settings.Runtime().ConfigurationRevision, settings.Runtime().ConfigurationRevisionFile
	probe := func(ctx context.Context) error {
		if ctx == nil {
			return errConfigurationUnavailable
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		snapshot, err := current(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				return context.Canceled
			case errors.Is(err, context.DeadlineExceeded):
				return context.DeadlineExceeded
			default:
				return errConfigurationUnavailable
			}
		}
		if !identity.MatchesSource(snapshot) {
			return errConfigurationUnavailable
		}
		matchesRevision := path == "" || configurationRevisionMatches(path, revision)
		if err := ctx.Err(); err != nil {
			return err
		}
		if !matchesRevision {
			return errConfigurationUnavailable
		}
		return ctx.Err()
	}
	if err := probe(ctx); err != nil {
		return nil, err
	}
	return probe, nil
}
