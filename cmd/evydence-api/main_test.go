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

func TestValidateRuntimeConfigRejectsProductionDefaults(t *testing.T) {
	tests := []struct {
		name       string
		database   string
		pepper     string
		signing    string
		wantSubstr string
	}{
		{name: "missing database", database: "", pepper: "not-default", signing: "external", wantSubstr: "EVYDENCE_DATABASE_URL"},
		{name: "missing pepper", database: "postgres://example", pepper: "", signing: "external", wantSubstr: "EVYDENCE_API_KEY_PEPPER"},
		{name: "default pepper", database: "postgres://example", pepper: "local-dev-pepper-change-me", signing: "external", wantSubstr: "EVYDENCE_API_KEY_PEPPER"},
		{name: "local signing", database: "postgres://example", pepper: "not-default", signing: "local", wantSubstr: "EVYDENCE_SIGNING_KEY_MODE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRuntimeConfig(true, tt.database, tt.pepper, tt.signing, false)
			if err == nil || !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("err=%v, want %q", err, tt.wantSubstr)
			}
		})
	}
}

func TestEnvDefaultAndObjectStoreSelection(t *testing.T) {
	t.Setenv("EVYDENCE_TEST_VALUE", "  configured  ")
	if got := envDefault("EVYDENCE_TEST_VALUE", "fallback"); got != "configured" {
		t.Fatalf("envDefault configured = %q", got)
	}
	if got := envDefault("EVYDENCE_MISSING_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envDefault fallback = %q", got)
	}

	t.Setenv("EVYDENCE_OBJECT_STORE", "filesystem")
	t.Setenv("EVYDENCE_OBJECT_DIR", t.TempDir())
	store, description, err := openObjectStore(t.Context())
	if err != nil {
		t.Fatalf("filesystem object store: %v", err)
	}
	if store == nil || !strings.Contains(description, "filesystem root") {
		t.Fatalf("store=%T description=%q", store, description)
	}

	t.Setenv("EVYDENCE_OBJECT_STORE", "unknown")
	if _, _, err := openObjectStore(t.Context()); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported object store err=%v", err)
	}
}

func TestOpenObjectStoreRejectsIncompleteS3Config(t *testing.T) {
	t.Setenv("EVYDENCE_OBJECT_STORE", "s3")
	t.Setenv("EVYDENCE_S3_ENDPOINT", "localhost:9000")
	if _, _, err := openObjectStore(t.Context()); err == nil {
		t.Fatal("expected incomplete S3 config to be rejected")
	}
}
