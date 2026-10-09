package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func TestValidateRuntimeConfigRejectsProductionBootstrapSecretPrinting(t *testing.T) {
	err := validateRuntimeConfig(true, "postgres://example", "not-default", "external", "https://signer.example.test/sign", true)
	if err == nil {
		t.Fatal("expected production bootstrap secret printing to be rejected")
	}
	if !strings.Contains(err.Error(), "EVYDENCE_PRINT_BOOTSTRAP_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRequiresExplicitRuntimeProfileBeforeOpeningStorage(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "")
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://operator:private-password@127.0.0.1:1/evydence?connect_timeout=1")
	err := runWithContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_RUNTIME_PROFILE") || strings.Contains(err.Error(), "private-password") {
		t.Fatalf("missing runtime profile error = %v", err)
	}
}

func TestLocalMemoryProfileRejectsRemoteObjectStoreBeforeConnecting(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	t.Setenv("EVYDENCE_OBJECT_STORE", "s3")
	t.Setenv("EVYDENCE_S3_ENDPOINT", "127.0.0.1:1")
	err := runWithContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "retired") || !strings.Contains(err.Error(), "EVYDENCE_RUNTIME_PROFILE") {
		t.Fatalf("unsafe local-memory object-store error = %v", err)
	}
}

func TestRetiredMemoryProfileStopsBeforeProviderConfigurationAndBootstrap(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "external")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_URL", "invalid-provider-private-value")
	t.Setenv("EVYDENCE_PRINT_BOOTSTRAP_SECRET", "true")
	for _, databaseURL := range []string{"", "postgres://operator:private-password@127.0.0.1:1/evydence"} {
		t.Setenv("EVYDENCE_DATABASE_URL", databaseURL)
		err := runWithContext(t.Context())
		if err == nil || !strings.Contains(err.Error(), "retired") || !strings.Contains(err.Error(), "EVYDENCE_DATABASE_URL") {
			t.Fatalf("retired profile reached later startup configuration: %v", err)
		}
		if strings.Contains(err.Error(), "private-password") || strings.Contains(err.Error(), "invalid-provider-private-value") {
			t.Fatal("retirement error exposed configuration values")
		}
	}
}

func TestValidateRuntimeConfigAllowsLocalBootstrapSecretPrinting(t *testing.T) {
	if err := validateRuntimeConfig(false, "", "", "", "", true); err != nil {
		t.Fatalf("local config should allow explicit bootstrap secret printing: %v", err)
	}
}

func TestValidateOutboundHTTPConfigRejectsProductionLoopbackOverrides(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv(outboundLocalhostOverrideNames[0], "true")
	err := validateOutboundHTTPConfig(true)
	if err == nil || !strings.Contains(err.Error(), outboundLocalhostOverrideNames[0]) {
		t.Fatalf("err=%v, want production localhost override rejection", err)
	}
	if outboundLocalhostAllowed(outboundLocalhostOverrideNames[0]) {
		t.Fatal("production must not enable a loopback outbound override")
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

func TestValidateRuntimeConfigAllowsDirectCloudKMSModesWithoutGateway(t *testing.T) {
	for _, mode := range []string{"gcp-kms", "azure-key-vault"} {
		t.Run(mode, func(t *testing.T) {
			if err := validateRuntimeConfig(true, "postgres://example", "not-default", mode, "", false); err != nil {
				t.Fatalf("%s direct mode should pass runtime config validation: %v", mode, err)
			}
		})
	}
}

func TestValidateRuntimeConfigRejectsPKCS11ModeWithoutGateway(t *testing.T) {
	err := validateRuntimeConfig(true, "postgres://example", "not-default", "pkcs11-hsm", "", false)
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_SIGNING_EXECUTOR_URL") {
		t.Fatalf("pkcs11 missing gateway err=%v", err)
	}
}

func TestValidateRuntimeConfigRejectsExternalSigningWithoutGateway(t *testing.T) {
	err := validateRuntimeConfig(true, "postgres://example", "not-default", "external", "", false)
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_SIGNING_EXECUTOR_URL") {
		t.Fatalf("external signing without gateway err=%v", err)
	}
}

func TestSigningConfigurationReadinessRequiresExecutor(t *testing.T) {
	if err := signingConfigurationReadiness(nil)(t.Context()); err == nil {
		t.Fatal("expected missing signing executor to fail readiness")
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

func TestHTTPRuntimeConfigUsesValidatedIngressDefaults(t *testing.T) {
	t.Setenv("EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", "120")
	t.Setenv("EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE", "30")
	t.Setenv("EVYDENCE_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 2001:db8::/32")
	config, err := httpRuntimeConfigFromEnv()
	if err != nil {
		t.Fatalf("httpRuntimeConfigFromEnv: %v", err)
	}
	if config.ReadHeaderTimeout != 5*time.Second || config.ReadTimeout != 30*time.Second || config.WriteTimeout != 60*time.Second || config.IdleTimeout != 120*time.Second || config.ShutdownTimeout != 30*time.Second {
		t.Fatalf("unexpected timeout config: %#v", config)
	}
	if config.MaxHeaderBytes != 16<<10 || config.MaxURLBytes != 8<<10 || config.MaxInFlightRequests != 256 || config.MaxConcurrentUploads != 8 || config.RateLimitBucketCapacity != 10_000 {
		t.Fatalf("unexpected ingress bounds: %#v", config)
	}
	if config.RateLimitRequestsPerMinute != 120 || config.ExpensiveTenantRequestsPerMinute != 30 || len(config.TrustedProxyCIDRs) != 2 {
		t.Fatalf("unexpected limiter config: %#v", config)
	}
	server := newHTTPServer(":0", http.NotFoundHandler(), config)
	if server.ReadHeaderTimeout != config.ReadHeaderTimeout || server.ReadTimeout != config.ReadTimeout || server.WriteTimeout != config.WriteTimeout || server.IdleTimeout != config.IdleTimeout || server.MaxHeaderBytes != config.MaxHeaderBytes {
		t.Fatalf("http.Server does not preserve configured limits: %#v", server)
	}
}

func TestHTTPRuntimeConfigRejectsInvalidBoundsAndProxyCIDRs(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "zero read timeout", key: "EVYDENCE_HTTP_READ_TIMEOUT_SECONDS", value: "0"},
		{name: "oversized header limit", key: "EVYDENCE_HTTP_MAX_HEADER_BYTES", value: "1048577"},
		{name: "invalid proxy CIDR", key: "EVYDENCE_TRUSTED_PROXY_CIDRS", value: "not-a-cidr"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(testCase.key, testCase.value)
			if _, err := httpRuntimeConfigFromEnv(); err == nil || !strings.Contains(err.Error(), testCase.key) {
				t.Fatalf("err=%v, want validation mentioning %s", err, testCase.key)
			}
		})
	}
}

func TestServeHTTPOnListenerGracefullyStopsOnCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := newHTTPServer(listener.Addr().String(), http.NotFoundHandler(), httpRuntimeConfig{ShutdownTimeout: time.Second})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serveHTTPOnListener(ctx, server, listener, time.Second) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveHTTPOnListener: %v", err)
	}
}

func TestHTTPServerIngressLimitsRejectOversizedAndSlowHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := newHTTPServer(listener.Addr().String(), http.NotFoundHandler(), httpRuntimeConfig{
		ReadHeaderTimeout: 50 * time.Millisecond,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
		ShutdownTimeout:   time.Second,
		MaxHeaderBytes:    1 << 10,
	})
	done := make(chan error, 1)
	go func() { done <- serveHTTPOnListener(ctx, server, listener, time.Second) }()

	oversized, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial oversized request: %v", err)
	}
	_, _ = fmt.Fprintf(oversized, "GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: %s\r\n\r\n", strings.Repeat("a", 16<<10))
	response, err := http.ReadResponse(bufio.NewReader(oversized), &http.Request{Method: http.MethodGet})
	_ = oversized.Close()
	if err != nil {
		t.Fatalf("read oversized-header response: %v", err)
	}
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized-header status=%d, want %d", response.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
	_ = response.Body.Close()

	slow, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial slow request: %v", err)
	}
	_, _ = fmt.Fprint(slow, "GET / HTTP/1.1\r\nHost: example.test")
	if err := slow.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set slow request deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := slow.Read(buffer); err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("slow header connection was not rejected before the test deadline: %v", err)
		}
	}
	_ = slow.Close()

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveHTTPOnListener: %v", err)
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

func TestOpenCosignVerifierRequiresBoundedVersionedTrustMaterial(t *testing.T) {
	if verifier, err := openCosignVerifier(); err != nil || verifier != nil {
		t.Fatalf("empty optional Cosign config verifier=%T err=%v", verifier, err)
	}
	t.Setenv("EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", base64.StdEncoding.EncodeToString([]byte("{}")))
	if _, err := openCosignVerifier(); err == nil || !strings.Contains(err.Error(), "TRUST_ROOT_VERSION") {
		t.Fatalf("missing trust-root version err=%v", err)
	}
	t.Setenv("EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION", "test-root.v1")
	t.Setenv("EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", "%%%")
	if _, err := openCosignVerifier(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("malformed trust-root encoding err=%v", err)
	}
	t.Setenv("EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", strings.Repeat("A", base64.StdEncoding.EncodedLen(maxSigstoreTrustConfigBytes)+1))
	if _, err := openCosignVerifier(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("oversized trust-root encoding err=%v", err)
	}

	root, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "verification", "sigstore", "testdata", "official-scaffolding.trusted-root.json"))
	if err != nil {
		t.Fatalf("read Sigstore fixture root: %v", err)
	}
	t.Setenv("EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", base64.StdEncoding.EncodeToString(root))
	if verifier, err := openCosignVerifier(); err != nil || verifier == nil {
		t.Fatalf("valid trust-root config verifier=%T err=%v", verifier, err)
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
	if _, err := openSigningExecutor(t.Context()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("remote http signer err=%v, want https rejection", err)
	}
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_URL", "http://127.0.0.1/sign")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST", "true")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	signer, err := openSigningExecutor(t.Context())
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
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	signer, err := openSigningExecutor(t.Context())
	if err != nil {
		t.Fatalf("gcp-kms gateway signer should be accepted: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestOpenSigningExecutorRequiresGatewayForNonAWSKMSModes(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "pkcs11-hsm")
	if _, err := openSigningExecutor(t.Context()); err == nil || !strings.Contains(err.Error(), "EVYDENCE_SIGNING_EXECUTOR_URL") {
		t.Fatalf("missing gateway err=%v", err)
	}
}

func TestOpenSigningExecutorConfiguresDirectGCPKMS(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "gcp-kms")
	t.Setenv("EVYDENCE_GCP_KMS_ENDPOINT", "https://kms.example.test")
	t.Setenv("EVYDENCE_GCP_KMS_ACCESS_TOKEN", "access-token")
	signer, err := openSigningExecutor(t.Context())
	if err != nil {
		t.Fatalf("gcp-kms direct signer should be accepted: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestOpenSigningExecutorConfiguresDirectAzureKeyVault(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "azure-key-vault")
	t.Setenv("EVYDENCE_AZURE_KEY_VAULT_URL", "https://vault.example.test")
	t.Setenv("EVYDENCE_AZURE_KEY_VAULT_KEY_NAME", "evydence")
	t.Setenv("EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION", "v1")
	signer, err := openSigningExecutor(t.Context())
	if err != nil {
		t.Fatalf("azure-key-vault direct signer should be accepted: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestOpenSigningExecutorRejectsIncompleteAWSKMSConfig(t *testing.T) {
	t.Setenv("EVYDENCE_SIGNING_KEY_MODE", "aws-kms")
	t.Setenv("EVYDENCE_AWS_REGION", "eu-north-1")
	if _, err := openSigningExecutor(t.Context()); err == nil {
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
