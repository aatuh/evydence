package main

import (
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func TestValidateRuntimeConfigRejectsProductionBootstrapSecretPrinting(t *testing.T) {
	err := validateRuntimeConfig(true, "postgres://example", "not-default", "external", "", true)
	if err == nil {
		t.Fatal("expected production bootstrap secret printing to be rejected")
	}
	if !strings.Contains(err.Error(), "EVYDENCE_PRINT_BOOTSTRAP_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigAllowsLocalBootstrapSecretPrinting(t *testing.T) {
	if err := validateRuntimeConfig(false, "", "", "", "", true); err != nil {
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
			err := validateRuntimeConfig(true, tt.database, tt.pepper, tt.signing, "", false)
			if err == nil || !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("err=%v, want %q", err, tt.wantSubstr)
			}
		})
	}
}

func TestValidateRuntimeConfigAllowsProductionAWSKMSMode(t *testing.T) {
	if err := validateRuntimeConfig(true, "postgres://example", "not-default", "aws-kms", "", false); err != nil {
		t.Fatalf("aws-kms production mode should be accepted: %v", err)
	}
}

func TestValidateRuntimeConfigAllowsGatewayBackedKMSModesWithExecutor(t *testing.T) {
	for _, mode := range []string{"gcp-kms", "azure-key-vault", "pkcs11-hsm"} {
		t.Run(mode, func(t *testing.T) {
			if err := validateRuntimeConfig(true, "postgres://example", "not-default", mode, "https://signer.example.test/sign", false); err != nil {
				t.Fatalf("%s production gateway mode should be accepted: %v", mode, err)
			}
		})
	}
}

func TestValidateRuntimeConfigRejectsGatewayBackedKMSModesWithoutExecutor(t *testing.T) {
	for _, mode := range []string{"gcp-kms", "azure-key-vault", "pkcs11-hsm"} {
		t.Run(mode, func(t *testing.T) {
			err := validateRuntimeConfig(true, "postgres://example", "not-default", mode, "", false)
			if err == nil || !strings.Contains(err.Error(), "EVYDENCE_SIGNING_EXECUTOR_URL") {
				t.Fatalf("%s missing gateway err=%v", mode, err)
			}
		})
	}
}

func TestValidateAPIWriterModeAllowsProductionSingleWriter(t *testing.T) {
	if err := validateAPIWriterMode(true, "single", "1"); err != nil {
		t.Fatalf("single writer production mode should be accepted: %v", err)
	}
	if err := validateAPIWriterMode(true, "", ""); err != nil {
		t.Fatalf("default writer mode should be accepted: %v", err)
	}
}

func TestValidateAPIWriterModeRejectsProductionMultiWriter(t *testing.T) {
	err := validateAPIWriterMode(true, "multi", "1")
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_API_WRITER_MODE") {
		t.Fatalf("multi-writer production mode err=%v", err)
	}
}

func TestValidateAPIWriterModeRejectsProductionReplicaCountAboveOne(t *testing.T) {
	err := validateAPIWriterMode(true, "single", "2")
	if err == nil || !strings.Contains(err.Error(), "one API writer replica") {
		t.Fatalf("production replica count err=%v", err)
	}
}

func TestValidateAPIWriterModeRejectsInvalidReplicaCount(t *testing.T) {
	for _, value := range []string{"0", "-1", "not-a-number"} {
		t.Run(value, func(t *testing.T) {
			err := validateAPIWriterMode(false, "multi", value)
			if err == nil || !strings.Contains(err.Error(), "EVYDENCE_API_WRITER_REPLICAS") {
				t.Fatalf("invalid replica count err=%v", err)
			}
		})
	}
}

func TestValidateAPIWriterModeAllowsLocalExperimentalMode(t *testing.T) {
	if err := validateAPIWriterMode(false, "multi", "3"); err != nil {
		t.Fatalf("local experimental writer mode should not be production-blocked: %v", err)
	}
}

func TestPostgresLoadModeDefaultsToRelationalOnlyInProduction(t *testing.T) {
	mode, err := postgres.ResolveLoadMode("", true)
	if err != nil {
		t.Fatalf("resolve production load mode: %v", err)
	}
	if mode != postgres.LoadModeRelationalOnly {
		t.Fatalf("production load mode = %q, want %q", mode, postgres.LoadModeRelationalOnly)
	}

	mode, err = postgres.ResolveLoadMode("", false)
	if err != nil {
		t.Fatalf("resolve local load mode: %v", err)
	}
	if mode != postgres.LoadModeSnapshotPreferred {
		t.Fatalf("local load mode = %q, want %q", mode, postgres.LoadModeSnapshotPreferred)
	}

	if err := postgres.ValidateProductionLoadMode(postgres.LoadModeRelationalPreferred); err == nil || !strings.Contains(err.Error(), "EVYDENCE_POSTGRES_LOAD_MODE") {
		t.Fatalf("relational-preferred production validation err=%v", err)
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

func TestIntEnvParsesRateLimitConfiguration(t *testing.T) {
	t.Setenv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", "25")
	if got := intEnv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", 0); got != 25 {
		t.Fatalf("configured int env = %d", got)
	}
	t.Setenv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", "-1")
	if got := intEnv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", 7); got != 7 {
		t.Fatalf("negative int env fallback = %d", got)
	}
}

func TestBoolEnvRequiresExplicitTrue(t *testing.T) {
	t.Setenv("EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS", " true ")
	if !boolEnv("EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS") {
		t.Fatal("expected explicit true env to be enabled")
	}
	t.Setenv("EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS", "yes")
	if boolEnv("EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS") {
		t.Fatal("expected non-true env value to be disabled")
	}
}

func TestOpenObjectStoreRejectsIncompleteS3Config(t *testing.T) {
	t.Setenv("EVYDENCE_OBJECT_STORE", "s3")
	t.Setenv("EVYDENCE_S3_ENDPOINT", "localhost:9000")
	if _, _, err := openObjectStore(t.Context()); err == nil {
		t.Fatal("expected incomplete S3 config to be rejected")
	}
}

func TestOpenSigningExecutorRequiresHTTPSUnlessLocalOverride(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_URL", "http://signer.example.test/sign")
	if _, err := openSigningExecutor(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("remote http signer err=%v, want https rejection", err)
	}
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_URL", "http://127.0.0.1/sign")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST", "true")
	signer, err := openSigningExecutor()
	if err != nil {
		t.Fatalf("localhost signer should be accepted: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestOpenSigningExecutorUsesGatewayForNonAWSKMSModes(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "gcp-kms")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_URL", "http://127.0.0.1/sign")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST", "true")
	signer, err := openSigningExecutor()
	if err != nil {
		t.Fatalf("gcp-kms gateway signer should be accepted: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestOpenSigningExecutorRequiresGatewayForNonAWSKMSModes(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "azure-key-vault")
	if _, err := openSigningExecutor(); err == nil || !strings.Contains(err.Error(), "EVYDENCE_SIGNING_EXECUTOR_URL") {
		t.Fatalf("missing gateway err=%v", err)
	}
}

func TestOpenSigningExecutorRejectsIncompleteAWSKMSConfig(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "aws-kms")
	t.Setenv("EVYDENCE_AWS_REGION", "eu-north-1")
	if _, err := openSigningExecutor(); err == nil {
		t.Fatal("expected missing AWS KMS key id to be rejected")
	}
}

func TestOpenProviderIdentityValidatorUsesGatewayWhenConfigured(t *testing.T) {
	t.Setenv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL", "http://127.0.0.1/provider")
	t.Setenv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST", "true")
	validator, err := openProviderIdentityValidator()
	if err != nil {
		t.Fatalf("provider validation gateway should be accepted: %v", err)
	}
	if validator == nil {
		t.Fatal("expected provider validator")
	}
}

func TestOpenProviderIdentityValidatorRequiresHTTPSForRemoteGateway(t *testing.T) {
	t.Setenv("EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL", "http://provider.example.test/validate")
	if _, err := openProviderIdentityValidator(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("remote http provider validator err=%v, want https rejection", err)
	}
}

func TestOpenTransparencyProofFetcherUsesGatewayWhenConfigured(t *testing.T) {
	t.Setenv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL", "http://127.0.0.1/proof")
	t.Setenv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST", "true")
	fetcher, err := openTransparencyProofFetcher()
	if err != nil {
		t.Fatalf("transparency proof gateway should be accepted: %v", err)
	}
	if fetcher == nil {
		t.Fatal("expected transparency proof fetcher")
	}
}

func TestOpenTransparencyProofFetcherRequiresHTTPSForRemoteGateway(t *testing.T) {
	t.Setenv("EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL", "http://transparency.example.test/proof")
	if _, err := openTransparencyProofFetcher(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("remote http transparency gateway err=%v, want https rejection", err)
	}
}
