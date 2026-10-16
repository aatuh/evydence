package main

import (
	"strings"
	"testing"
)

func TestAPILoggingConfigurationFailsBeforeRuntime(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	t.Setenv("EVYDENCE_LOG_LEVEL", "CANARY_SECRET")
	err := runWithContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_LOG_LEVEL") || strings.Contains(err.Error(), "CANARY_SECRET") {
		t.Fatal("logging was not safely validated before runtime")
	}
}
