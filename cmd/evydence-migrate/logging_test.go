package main

import (
	"strings"
	"testing"
)

func TestMigrationLoggingConfigurationFailsBeforeRuntime(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	t.Setenv("EVYDENCE_LOG_FORMAT", "CANARY_SECRET")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_LOG_FORMAT") || strings.Contains(err.Error(), "CANARY_SECRET") {
		t.Fatal("logging was not safely validated before runtime")
	}
}
