//go:build unix

package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func preparedSecretEnvironment(t *testing.T, extra ...string) Environment {
	t.Helper()
	entries := []string{"ENV=production", "EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-test-1", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_KEY_ID"}
	entries = append(entries, extra...)
	e, err := Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPrepareAndResolveRequiredSecretFiles(t *testing.T) {
	dir := t.TempDir()
	database, pepper := filepath.Join(dir, "PRIVATE_DATABASE"), filepath.Join(dir, "PRIVATE_PEPPER")
	e := preparedSecretEnvironment(t, "EVYDENCE_DATABASE_URL_FILE="+database, "EVYDENCE_API_KEY_PEPPER_FILE="+pepper)
	input, err := Prepare(e, API)
	if err != nil {
		t.Fatal("preflight accessed nonexistent secret files", err)
	}
	if cfg, err := Parse(e, API); !errors.Is(err, ErrUnresolvedSecretReference) || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("inline-only Parse silently ignored file alternatives", err)
	}
	if cfg, err := Resolve(context.Background(), input, false); err != nil || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("disabled resolution accessed a file or returned startup settings", err)
	}
	writePrivateSecret(t, database, "host=PRIVATE_DATABASE dbname=evidence\n")
	writePrivateSecret(t, pepper, " PRIVATE_PEPPER_VALUE\n")
	cfg, err := Resolve(context.Background(), input, true)
	if err != nil || cfg.Role() != API || !cfg.Production() || cfg.Runtime().DatabaseURL.Reveal() != "host=PRIVATE_DATABASE dbname=evidence" || cfg.API().KeyPepper.Reveal() != "PRIVATE_PEPPER_VALUE" {
		t.Fatal("resolved secret values did not pass complete typed validation", err)
	}
	if !cfg.SourceIdentity().MatchesSource(e) {
		t.Fatal("secret materialization replaced the captured source identity")
	}
	for _, value := range []any{input, &input, cfg, cfg.API(), cfg.Runtime()} {
		data, err := json.Marshal(value)
		if err != nil || strings.Contains(string(data), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("preflight/resolved settings leaked source data", err)
		}
	}
}

func TestPrepareRejectsInvalidConfigurationBeforeFileResolution(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "PRIVATE_MISSING")
	for _, tc := range []struct {
		extra []string
		want  error
	}{
		{[]string{"EVYDENCE_HTTP_READ_TIMEOUT_SECONDS=PRIVATE_INVALID"}, ErrInvalidValue},
		{[]string{"EVYDENCE_API_KEY_PEPPER=PRIVATE_INLINE"}, ErrConflictingSecretSources},
		{[]string{"EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE"}, ErrUnknownOption},
	} {
		extra := append([]string{"EVYDENCE_DATABASE_URL_FILE=" + missing, "EVYDENCE_API_KEY_PEPPER_FILE=" + missing}, tc.extra...)
		input, err := Prepare(preparedSecretEnvironment(t, extra...), API)
		if !errors.Is(err, tc.want) || !reflect.DeepEqual(input, PreparedInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid preflight returned partial input or filesystem diagnostics", err)
		}
	}
}

func TestResolveRevalidatesLoadedSecretsAndReturnsNoPartialSettings(t *testing.T) {
	dir := t.TempDir()
	database, pepper := filepath.Join(dir, "PRIVATE_DB"), filepath.Join(dir, "PRIVATE_PEPPER")
	e := preparedSecretEnvironment(t, "EVYDENCE_DATABASE_URL_FILE="+database, "EVYDENCE_API_KEY_PEPPER_FILE="+pepper)
	input, err := Prepare(e, API)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ database, pepper string }{{"PRIVATE_BAD_DSN", "PRIVATE_GOOD"}, {"host=db", "local-dev-pepper-change-me"}} {
		writePrivateSecret(t, database, tc.database)
		writePrivateSecret(t, pepper, tc.pepper)
		cfg, err := Resolve(context.Background(), input, true)
		if !errors.Is(err, ErrSecretResolution) || !reflect.DeepEqual(cfg, Configuration{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("loaded malformed/unsafe secret returned settings or leaked its value", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if cfg, err := Resolve(ctx, input, true); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("cancelled resolution returned settings", err)
	}
	if cfg, err := Resolve(context.Background(), PreparedInput{}, true); err == nil || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("zero unvalidated input authorized resolution", err)
	}
}

func TestResolveSkipsInactiveProviderSecretFilesAndOwnsCapture(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "PRIVATE_UNUSED")
	e := preparedSecretEnvironment(t, "EVYDENCE_DATABASE_URL=host=PRIVATE_DB", "EVYDENCE_API_KEY_PEPPER=PRIVATE_PEPPER", "EVYDENCE_S3_ACCESS_KEY_ID_FILE="+missing, "EVYDENCE_S3_SECRET_ACCESS_KEY_FILE="+missing, "EVYDENCE_SIGNING_EXECUTOR_URL=https://gateway.invalid/sign", "EVYDENCE_SIGNING_EXECUTOR_TOKEN_FILE="+missing)
	input, err := Prepare(e, API)
	if err != nil {
		t.Fatal(err)
	}
	e.values["EVYDENCE_DATABASE_URL"] = "PRIVATE_CAPTURE_MUTATION"
	cfg, err := Resolve(context.Background(), input, true)
	if err != nil || cfg.Runtime().DatabaseURL.Reveal() != "host=PRIVATE_DB" || cfg.Storage().Kind != "filesystem" || cfg.Storage().S3AccessKeyID.IsSet() {
		t.Fatal("inactive reference was read or prepared input shared caller state", err)
	}
}

func TestResolveActiveObjectStoreFilesPreserveCredentialBytes(t *testing.T) {
	dir := t.TempDir()
	id, key := filepath.Join(dir, "PRIVATE_ID"), filepath.Join(dir, "PRIVATE_KEY")
	writePrivateSecret(t, id, " PRIVATE_ID ")
	writePrivateSecret(t, key, "PRIVATE_KEY\n")
	for _, role := range []Role{API, Worker, WorkerReplay, WorkerReconcile} {
		e := preparedSecretEnvironment(t, "EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_API_KEY_PEPPER=PRIVATE_PEPPER", "EVYDENCE_OBJECT_STORE=s3", "EVYDENCE_S3_ENDPOINT=storage.internal:9000", "EVYDENCE_S3_BUCKET=evidence", "EVYDENCE_S3_ACCESS_KEY_ID_FILE="+id, "EVYDENCE_S3_SECRET_ACCESS_KEY_FILE="+key)
		input, err := Prepare(e, role)
		if err != nil {
			t.Fatal("preflight did not defer required object-store credentials", err)
		}
		cfg, err := Resolve(context.Background(), input, true)
		if err != nil || cfg.Storage().S3AccessKeyID.Reveal() != " PRIVATE_ID " || cfg.Storage().S3SecretAccessKey.Reveal() != "PRIVATE_KEY\n" {
			t.Fatal("file resolution normalized opaque S3 credential bytes", err)
		}
	}
}

func TestResolveGatewayActivationAndHeaderValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PRIVATE_TOKEN")
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		option string
		extra  []string
		read   func(Configuration) Secret
	}{
		{"EVYDENCE_SIGNING_EXECUTOR_TOKEN_FILE", []string{"EVYDENCE_SIGNING_KEY_MODE=external", "EVYDENCE_SIGNING_EXECUTOR_URL=https://gateway.invalid/sign", "EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64=" + publicKey}, func(c Configuration) Secret { return c.Providers().SigningExecutorToken }},
		{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN_FILE", []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://gateway.invalid/validate"}, func(c Configuration) Secret { return c.Providers().ProviderValidationGatewayToken }},
		{"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN_FILE", []string{"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL=https://gateway.invalid/proof"}, func(c Configuration) Secret { return c.Providers().TransparencyProofGatewayToken }},
	} {
		extra := []string{"EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_API_KEY_PEPPER=PRIVATE_PEPPER", tc.option + "=" + path}
		// Replace the helper's signing-mode entry instead of capturing duplicates.
		e := preparedSecretEnvironment(t, extra...)
		for _, entry := range tc.extra {
			name, value, _ := strings.Cut(entry, "=")
			e.values[name] = value
		}
		input, err := Prepare(e, API)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{" PRIVATE_TOKEN\n", "PRIVATE INVALID_TOKEN"} {
			writePrivateSecret(t, path, raw)
			cfg, err := Resolve(context.Background(), input, true)
			if strings.Contains(raw, "INVALID") {
				if !errors.Is(err, ErrSecretResolution) || !reflect.DeepEqual(cfg, Configuration{}) {
					t.Fatal("file-backed header token bypassed validation", err)
				}
			} else if err != nil || tc.read(cfg).Reveal() != "PRIVATE_TOKEN" {
				t.Fatal("active gateway secret was not resolved", err)
			}
		}
	}
}

func TestResolveRoleScopeAndCombinedLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PRIVATE_SECRET")
	for _, tc := range []struct {
		role   Role
		option string
		value  string
		read   func(Configuration) Secret
	}{
		{Migrate, "EVYDENCE_DATABASE_URL_FILE", "host=PRIVATE_DB", func(c Configuration) Secret { return c.Runtime().DatabaseURL }},
		{CLI, "EVYDENCE_API_KEY_FILE", "PRIVATE_API_KEY", func(c Configuration) Secret { return c.CLI().APIKey }},
	} {
		e, err := Capture([]string{tc.option + "=" + path})
		if err != nil {
			t.Fatal(err)
		}
		input, err := Prepare(e, tc.role)
		if err != nil {
			t.Fatal(err)
		}
		writePrivateSecret(t, path, tc.value)
		cfg, err := Resolve(context.Background(), input, true)
		if err != nil || tc.read(cfg).Reveal() != tc.value {
			t.Fatal("role-scoped secret was not resolved", err)
		}
	}
	id, key := filepath.Join(dir, "PRIVATE_ID"), filepath.Join(dir, "PRIVATE_KEY")
	writePrivateSecret(t, id, strings.Repeat("a", maxEnvironmentBytes/2+1))
	writePrivateSecret(t, key, strings.Repeat("b", maxEnvironmentBytes/2+1))
	e := preparedSecretEnvironment(t, "EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_API_KEY_PEPPER=PRIVATE_PEPPER", "EVYDENCE_OBJECT_STORE=minio", "EVYDENCE_S3_ENDPOINT=storage.internal:9000", "EVYDENCE_S3_BUCKET=evidence", "EVYDENCE_S3_ACCESS_KEY_ID_FILE="+id, "EVYDENCE_S3_SECRET_ACCESS_KEY_FILE="+key)
	input, err := Prepare(e, API)
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err := Resolve(context.Background(), input, true); !errors.Is(err, ErrSecretResolution) || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("combined secret materialization exceeded the input budget", err)
	}
	for _, ctx := range []context.Context{nil} {
		if cfg, err := Resolve(ctx, input, false); !errors.Is(err, ErrSecretResolution) || !reflect.DeepEqual(cfg, Configuration{}) {
			t.Fatal("nil context accepted", err)
		}
	}
}
