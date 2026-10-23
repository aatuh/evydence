package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestAPILoggingConfigurationFailsBeforeRuntime(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "host=PRIVATE_DB")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_LOG_LEVEL", "CANARY_SECRET")
	err := runWithContext(t.Context())
	if !errors.Is(err, config.ErrInvalidValue) || strings.Contains(err.Error(), "CANARY_SECRET") {
		t.Fatal("logging was not safely validated before runtime")
	}
}
