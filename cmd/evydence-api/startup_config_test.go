package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

func apiCapturedEnvironment(t *testing.T, extra ...string) config.Environment {
	t.Helper()
	values := map[string]string{"ENV": "development", "EVYDENCE_RUNTIME_PROFILE": "postgres", "EVYDENCE_DATABASE_URL": "host=PRIVATE_DB sslmode=disable", "EVYDENCE_API_KEY_PEPPER": "PRIVATE_PEPPER"}
	for _, entry := range extra {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	e, err := config.Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAPIProcessUsesCapturedTypedSettingsAndPreparedDatabase(t *testing.T) {
	e := apiCapturedEnvironment(t, "EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS=7", "EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS=3600", "EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS=300", "EVYDENCE_BOOTSTRAP_TENANT= Tenant ", "EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=3")
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED")
	t.Setenv("EVYDENCE_API_KEY_PEPPER", "PRIVATE_CHANGED")
	t.Setenv("EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS", "PRIVATE_INVALID")
	t.Setenv("PGSERVICE", "")
	var output bytes.Buffer
	want := errors.New("PRIVATE_RUNTIME_FAILURE")
	called := false
	err := runAPIProcess(t.Context(), e, &output, func(_ context.Context, settings config.Configuration, database postgres.PreparedPoolConfig) error {
		called = true
		a := settings.API()
		http := httpRuntimeConfigFromSettings(a)
		session := sessionPolicyFromSettings(a)
		runtime := apiRuntimeConfigFromSettings(settings, database)
		bootstrap := tenantBootstrapInputFromSettings(a)
		if settings.Role() != config.API || a.KeyPepper.Reveal() != "PRIVATE_PEPPER" || http.ReadHeaderTimeout != 7*time.Second || session.MaximumLifetime != time.Hour || session.IdleTimeout != 5*time.Minute || bootstrap.TenantName != " Tenant " || !runtime.WorkerOwnedParsers || runtime.CleanupTimeout != 3*time.Second || !database.IsPrepared() || !database.Matches("host=PRIVATE_DB sslmode=disable") || !runtime.DatabaseConfiguration.Matches(runtime.DatabaseURL) {
			t.Fatal("API startup used ambient values or lost typed settings")
		}
		return want
	})
	if !called || !errors.Is(err, want) || strings.Contains(output.String(), "PRIVATE") || strings.Count(output.String(), "\n") != 2 || !strings.Contains(output.String(), `"result_code":"failed"`) {
		t.Fatal("API lifecycle lost its result or exposed configuration")
	}
}

func TestAPIProcessRejectsConfigurationBeforeProviderStartup(t *testing.T) {
	for _, tc := range []struct {
		extra []string
		want  error
	}{
		{[]string{"EVYDENCE_HTTP_READ_TIMEOUT_SECONDS=0"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS=60", "EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS=61"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_OBJECT_STORE=PRIVATE_INVALID"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_OBJECT_STORE=s3", "EVYDENCE_S3_ENDPOINT=s3.amazonaws.com", "EVYDENCE_S3_REGION=us-east-1", "EVYDENCE_S3_BUCKET=evidence", "EVYDENCE_S3_ACCESS_KEY_ID=PRIVATE_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY=PRIVATE_KEY"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_SIGNING_EXECUTOR_TOKEN=PRIVATE\nTOKEN"}, config.ErrInvalidValue},
		{[]string{"ENV=production", "EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE"}, config.ErrUnknownOption},
		{[]string{"EVYDENCE_SIGNING_KEY_MODE=aws-kms"}, config.ErrMissingValue},
		{[]string{"ENV=production", "EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-test-1", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_KEY", "EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST=true"}, config.ErrUnsafeProduction},
		{[]string{"EVYDENCE_DATABASE_URL_FILE=/PRIVATE_MISSING/file"}, config.ErrConflictingSecretSources},
	} {
		var output bytes.Buffer
		called := false
		err := runAPIProcess(t.Context(), apiCapturedEnvironment(t, tc.extra...), &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
			called = true
			return nil
		})
		if called || !errors.Is(err, tc.want) || strings.Contains(output.String(), "PRIVATE") || strings.Count(output.String(), "\n") != 1 || !strings.Contains(output.String(), `"result_code":"rejected"`) {
			t.Fatal("invalid API configuration reached provider startup or leaked input", err)
		}
	}
}

func TestAPIProcessRejectsNativeResolutionBeforeProviders(t *testing.T) {
	t.Setenv("PGSERVICE", "PRIVATE_SERVICE")
	t.Setenv("PGSERVICEFILE", "/PRIVATE_MISSING/file")
	var output bytes.Buffer
	called := false
	err := runAPIProcess(t.Context(), apiCapturedEnvironment(t, "PGSERVICE=PRIVATE_SERVICE", "PGSERVICEFILE=/PRIVATE_MISSING/file"), &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
		called = true
		return nil
	})
	if called || !errors.Is(err, postgres.ErrInvalidConfiguration) || strings.Contains(output.String(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"rejected"`) {
		t.Fatal("native PostgreSQL resolution happened after provider startup", err)
	}
}

func TestAPIProcessPreservesCancellationBeforeSecretResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	called := false
	err := runAPIProcess(ctx, apiCapturedEnvironment(t, "EVYDENCE_DATABASE_URL=", "EVYDENCE_DATABASE_URL_FILE=/PRIVATE_MISSING/file"), &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
		called = true
		return nil
	})
	if called || !errors.Is(err, context.Canceled) || strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("cancellation reached file/provider startup or exposed input", err)
	}
}

func TestConfiguredAPIProvidersIgnoreChangedProjectEnvironment(t *testing.T) {
	settings, err := config.Parse(apiCapturedEnvironment(t, "EVYDENCE_SIGNING_EXECUTOR_URL=https://signer.example.test/sign", "EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64="+base64.StdEncoding.EncodeToString(make([]byte, 32)), "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://identity.example.test/validate", "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL=https://proof.example.test/proof"), config.API)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"EVYDENCE_SIGNING_EXECUTOR_URL", "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL", "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL"} {
		t.Setenv(name, "PRIVATE_INVALID")
	}
	var owner wiring.OwnedResources
	t.Cleanup(func() {
		if err := owner.Close(context.Background(), time.Second); err != nil {
			t.Error("fixture provider cleanup failed")
		}
	})
	signer, err := openSigningExecutorConfigured(t.Context(), settings.Providers())
	if err != nil || signer == nil {
		t.Fatal("signer reread ambient project configuration", err)
	}
	ownNewProvider(&owner, "signer", signer)
	validator, err := openProviderIdentityValidatorConfigured(settings.Providers())
	if err != nil || validator == nil {
		t.Fatal("identity validator reread ambient project configuration", err)
	}
	ownNewProvider(&owner, "identity", validator)
	fetcher, err := openTransparencyProofFetcherConfigured(settings.Providers())
	if err != nil || fetcher == nil {
		t.Fatal("transparency fetcher reread ambient project configuration", err)
	}
	ownNewProvider(&owner, "transparency", fetcher)
	if err := owner.Close(t.Context(), time.Second); err != nil {
		t.Fatal("fixture provider cleanup failed")
	}
}
