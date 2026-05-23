package main

import (
	"strings"
	"testing"
)

func TestValidateRuntimeConfigRejectsProductionBootstrapSecretPrinting(t *testing.T) {
	err := validateRuntimeConfig(true, "postgres://example", "not-default", "external", true)
	if err == nil {
		t.Fatal("expected production bootstrap secret printing to be rejected")
	}
	if !strings.Contains(err.Error(), "EVYDENCE_PRINT_BOOTSTRAP_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigAllowsLocalBootstrapSecretPrinting(t *testing.T) {
	if err := validateRuntimeConfig(false, "", "", "", true); err != nil {
		t.Fatalf("local config should allow explicit bootstrap secret printing: %v", err)
	}
}
