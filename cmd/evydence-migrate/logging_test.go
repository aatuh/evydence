package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestMigrationLoggingConfigurationFailsBeforeRuntime(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "host=PRIVATE_DATABASE")
	t.Setenv("EVYDENCE_LOG_FORMAT", "CANARY_SECRET")
	err := run()
	if !errors.Is(err, config.ErrInvalidValue) || strings.Contains(err.Error(), "CANARY_SECRET") {
		t.Fatal("logging was not safely validated before runtime")
	}
}
