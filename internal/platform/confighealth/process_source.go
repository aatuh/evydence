package confighealth

import (
	"context"
	"os"

	"github.com/aatuh/evydence/internal/platform/config"
)

// ProcessSource observes the desired process source for cached health refreshes.
// Operational settings remain the immutable startup snapshot; this does no reload.
func ProcessSource(ctx context.Context) (config.Environment, error) {
	if ctx == nil {
		return config.Environment{}, errConfigurationUnavailable
	}
	if err := ctx.Err(); err != nil {
		return config.Environment{}, err
	}
	environment, err := config.Capture(os.Environ())
	if ctx.Err() != nil {
		return config.Environment{}, ctx.Err()
	}
	return environment, err
}
