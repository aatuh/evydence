package main

import (
	"strings"
	"testing"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_DATABASE_URL") {
		t.Fatalf("err=%v, want database URL requirement", err)
	}
}

func TestEnvDefault(t *testing.T) {
	t.Setenv("EVYDENCE_MIGRATIONS_DIR_TEST", " custom ")
	if got := envDefault("EVYDENCE_MIGRATIONS_DIR_TEST", "migrations"); got != "custom" {
		t.Fatalf("configured envDefault = %q", got)
	}
	if got := envDefault("EVYDENCE_MISSING_MIGRATIONS_DIR_TEST", "migrations"); got != "migrations" {
		t.Fatalf("fallback envDefault = %q", got)
	}
}
