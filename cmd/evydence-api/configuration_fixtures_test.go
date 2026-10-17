package main

import (
	"context"
	"encoding/base64"
	"os"
	"strings"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

// These are valid fixture inputs, not production defaults. Component tests keep
// their environmental setup while exercising the shared parser and typed ports.
// Harness-only connection/S3 variables are not production command options.
func apiTestEnvironment(extra ...string) (config.Environment, error) {
	values := map[string]string{"ENV": "development", "EVYDENCE_RUNTIME_PROFILE": "postgres", "EVYDENCE_DATABASE_URL": "host=PRIVATE_DB sslmode=disable", "EVYDENCE_API_KEY_PEPPER": "PRIVATE_PEPPER"}
	for _, entry := range extra {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "EVYDENCE_TEST_") {
			values[name] = value
		}
	}
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	return config.Capture(entries)
}

func apiFixtureSettings(ctx context.Context) (config.Configuration, error) {
	environment, err := apiTestEnvironment(os.Environ()...)
	if err != nil {
		return config.Configuration{}, err
	}
	input, err := config.Prepare(environment, config.API)
	if err != nil {
		return config.Configuration{}, err
	}
	return config.Resolve(ctx, input, true)
}

func validAPIPolicyFixture(production bool) []string {
	environment := "development"
	if production {
		environment = "production"
	}
	return []string{"ENV=" + environment, "EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-test-1", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_KEY",
		"EVYDENCE_GCP_KMS_KEY_NAME=projects/project/locations/global/keyRings/ledger/cryptoKeys/key/cryptoKeyVersions/1",
		"EVYDENCE_AZURE_KEY_VAULT_URL=https://vault.example.test", "EVYDENCE_AZURE_KEY_VAULT_KEY_NAME=key", "EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION=v1",
		"EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64=" + base64.StdEncoding.EncodeToString(make([]byte, 32))}
}

func validateRuntimeConfig(production bool, databaseURL, pepper, signingKeyMode, signingExecutorURL string, printSecret bool) error {
	extra := validAPIPolicyFixture(production)
	printing := "false"
	if printSecret {
		printing = "true"
	}
	extra = append(extra, "EVYDENCE_DATABASE_URL="+databaseURL, "EVYDENCE_API_KEY_PEPPER="+pepper, "EVYDENCE_SIGNING_KEY_MODE="+signingKeyMode,
		"EVYDENCE_SIGNING_EXECUTOR_URL="+signingExecutorURL, "EVYDENCE_PRINT_BOOTSTRAP_SECRET="+printing)
	e, err := apiTestEnvironment(extra...)
	if err != nil {
		return err
	}
	_, err = config.Parse(e, config.API)
	return err
}

func validateAPIWriterMode(production bool, mode, replicas string) error {
	extra := append(validAPIPolicyFixture(production), "EVYDENCE_API_WRITER_MODE="+mode, "EVYDENCE_API_WRITER_REPLICAS="+replicas)
	e, err := apiTestEnvironment(extra...)
	if err != nil {
		return err
	}
	_, err = config.Parse(e, config.API)
	return err
}

func httpRuntimeConfigFromEnv() (httpRuntimeConfig, error) {
	settings, err := apiFixtureSettings(context.Background())
	if err != nil {
		return httpRuntimeConfig{}, err
	}
	return httpRuntimeConfigFromSettings(settings.API()), nil
}
func sessionPolicyFromEnv() (identitydomain.SessionPolicy, error) {
	settings, err := apiFixtureSettings(context.Background())
	if err != nil {
		return identitydomain.SessionPolicy{}, err
	}
	return sessionPolicyFromSettings(settings.API()), nil
}
func openSigningExecutor(ctx context.Context) (app.SigningExecutor, error) {
	settings, err := apiFixtureSettings(ctx)
	if err != nil {
		return nil, err
	}
	return openSigningExecutorConfigured(ctx, settings.Providers())
}
func openProviderIdentityValidator() (app.ProviderIdentityValidator, error) {
	settings, err := apiFixtureSettings(context.Background())
	if err != nil {
		return nil, err
	}
	return openProviderIdentityValidatorConfigured(settings.Providers())
}
func openTransparencyProofFetcher() (app.TransparencyProofFetcher, error) {
	settings, err := apiFixtureSettings(context.Background())
	if err != nil {
		return nil, err
	}
	return openTransparencyProofFetcherConfigured(settings.Providers())
}
func openCosignVerifier() (app.CosignPolicyVerifier, error) {
	settings, err := apiFixtureSettings(context.Background())
	if err != nil {
		return nil, err
	}
	return openCosignVerifierConfigured(settings.Providers())
}
func openObjectStore(ctx context.Context) (app.ObjectStore, string, error) {
	settings, err := apiFixtureSettings(ctx)
	if err != nil {
		return nil, "", err
	}
	return wiring.OpenObjectStore(ctx, apiRuntimeConfigFromSettings(settings, postgres.PreparedPoolConfig{}).ObjectStore)
}

const maxSigstoreTrustConfigBytes = 1 << 20
