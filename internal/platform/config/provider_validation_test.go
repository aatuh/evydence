package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func signingKeySetting() string {
	return "EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64=" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
}

func TestRoleInputRejectsUnsafeProviderConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		production bool
		extra      []string
		want       error
	}{
		{"relative-gateway", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=/PRIVATE_PATH"}, ErrInvalidValue},
		{"credential-in-url", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://user:PRIVATE_PASSWORD@example.invalid"}, ErrInvalidValue},
		{"http-remote-gateway", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=http://provider.invalid/verify"}, ErrInvalidValue},
		{"http-remote-with-local-override", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=http://provider.invalid/verify", "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST=true"}, ErrInvalidValue},
		{"private-gateway", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://10.0.0.1/verify"}, ErrInvalidValue},
		{"metadata-gateway", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://169.254.169.254/verify"}, ErrInvalidValue},
		{"fragment-gateway", false, []string{"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL=https://provider.invalid/proof#PRIVATE_FRAGMENT"}, ErrInvalidValue},
		{"zero-port", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://provider.invalid:0"}, ErrInvalidValue},
		{"port-overflow", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://provider.invalid:65536"}, ErrInvalidValue},
		{"invalid-query-encoding", false, []string{"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL=https://provider.invalid/verify?x=%ZZ"}, ErrInvalidValue},
		{"inactive-kms-http", false, []string{"EVYDENCE_AWS_KMS_ENDPOINT=http://PRIVATE_KMS.invalid"}, ErrInvalidValue},
		{"kms-query", false, []string{"EVYDENCE_GCP_KMS_ENDPOINT=https://cloudkms.googleapis.com?PRIVATE_QUERY=1"}, ErrInvalidValue},
		{"azure-algorithm", false, []string{"EVYDENCE_AZURE_KEY_VAULT_ALGORITHM=PRIVATE_ALGORITHM"}, ErrInvalidValue},
		{"short-gateway-public-key", false, []string{"EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64=eHl6"}, ErrInvalidValue},
		{"gateway-token-newline", false, []string{"EVYDENCE_SIGNING_EXECUTOR_TOKEN=PRIVATE_TOKEN\r\nInjected: value"}, ErrInvalidValue},
		{"missing-external-gateway", false, []string{"EVYDENCE_SIGNING_KEY_MODE=external"}, ErrMissingValue},
		{"missing-hsm-gateway", false, []string{"EVYDENCE_SIGNING_KEY_MODE=pkcs11-hsm"}, ErrMissingValue},
		{"missing-gateway-key", false, []string{"EVYDENCE_SIGNING_EXECUTOR_URL=https://sign.invalid/sign"}, ErrMissingValue},
		{"missing-aws-region", false, []string{"EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_KEY_ID"}, ErrMissingValue},
		{"missing-aws-key", false, []string{"EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-test-1"}, ErrMissingValue},
		{"missing-gcp-key", false, []string{"EVYDENCE_SIGNING_KEY_MODE=gcp-kms"}, ErrMissingValue},
		{"invalid-gcp-key", false, []string{"EVYDENCE_GCP_KMS_KEY_NAME=projects/p/cryptoKeyVersions/../PRIVATE_KEY"}, ErrInvalidValue},
		{"missing-azure-vault", false, []string{"EVYDENCE_SIGNING_KEY_MODE=azure-key-vault", "EVYDENCE_AZURE_KEY_VAULT_KEY_NAME=key", "EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION=version"}, ErrMissingValue},
		{"invalid-azure-segment", false, []string{"EVYDENCE_AZURE_KEY_VAULT_KEY_NAME=PRIVATE/KEY"}, ErrInvalidValue},
		{"production-local-signing", true, []string{"EVYDENCE_SIGNING_KEY_MODE=local"}, ErrUnsafeProduction},
		{"production-implicit-signing", true, []string{"EVYDENCE_SIGNING_KEY_MODE="}, ErrUnsafeProduction},
		{"orphan-readiness-url", false, []string{"EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=https://sign.invalid/ready"}, ErrMissingValue},
		{"cross-origin-readiness", false, []string{"EVYDENCE_SIGNING_EXECUTOR_URL=https://sign.invalid/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=https://other.invalid/ready", signingKeySetting()}, ErrInvalidValue},
		{"cross-port-readiness", false, []string{"EVYDENCE_SIGNING_EXECUTOR_URL=https://sign.invalid:8443/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=https://sign.invalid/ready", signingKeySetting()}, ErrInvalidValue},
		{"cross-scheme-readiness", false, []string{"EVYDENCE_SIGNING_EXECUTOR_URL=https://127.0.0.1/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=http://127.0.0.1/ready", "EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST=true", signingKeySetting()}, ErrInvalidValue},
		{"readiness-query-delimiter", false, []string{"EVYDENCE_SIGNING_EXECUTOR_URL=https://sign.invalid/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=https://sign.invalid/ready?", signingKeySetting()}, ErrInvalidValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := parseRoleInput(roleEnvironment(t, API, tc.production, tc.extra...), API)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(input, parsedInput{}) {
				t.Fatal("invalid provider configuration returned usable or partial input", err)
			}
			if strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
				t.Fatal("provider diagnostic exposed configuration input")
			}
		})
	}
}

func TestRoleInputAcceptsProviderConfigurationWithoutStartingProviders(t *testing.T) {
	for _, tc := range []struct {
		production bool
		extra      []string
	}{
		{false, []string{"EVYDENCE_SIGNING_EXECUTOR_URL=https://sign.invalid/sign?v=1", signingKeySetting()}},
		{false, []string{"EVYDENCE_SIGNING_KEY_MODE=external", "EVYDENCE_SIGNING_EXECUTOR_URL=http://127.0.0.1:8443/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=http://127.0.0.1:8443/ready", "EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST=true", signingKeySetting()}},
		{false, []string{"EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-test-1", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_NONEXISTENT_KEY", "EVYDENCE_AWS_KMS_ENDPOINT=https://127.0.0.1:1"}},
		{false, []string{"EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-test-1", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_NONEXISTENT_KEY", "EVYDENCE_SIGNING_EXECUTOR_URL=https://inactive.invalid/sign"}},
		{false, []string{"EVYDENCE_SIGNING_KEY_MODE=gcp-kms", "EVYDENCE_GCP_KMS_KEY_NAME=projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"}},
		{false, []string{"EVYDENCE_SIGNING_KEY_MODE=azure-key-vault", "EVYDENCE_AZURE_KEY_VAULT_URL=https://vault.invalid", "EVYDENCE_AZURE_KEY_VAULT_KEY_NAME=key", "EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION=version"}},
		{true, []string{"EVYDENCE_SIGNING_KEY_MODE=external", "EVYDENCE_SIGNING_EXECUTOR_URL=https://SIGN.invalid/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL=https://sign.invalid:443/ready", signingKeySetting()}},
		// Existing signing-only gateway configurations remain constructible;
		// operational readiness still needs its separately configured endpoint.
		{true, []string{"EVYDENCE_SIGNING_KEY_MODE=external", "EVYDENCE_SIGNING_EXECUTOR_URL=https://sign.invalid/sign", signingKeySetting()}},
	} {
		if _, err := parseRoleInput(roleEnvironment(t, API, tc.production, tc.extra...), API); err != nil {
			t.Fatal("provider parsing performed I/O or rejected a valid profile", err)
		}
	}
	input, err := parseRoleInput(roleEnvironment(t, API, false, "EVYDENCE_AZURE_KEY_VAULT_API_VERSION= "), API)
	if err != nil || projectInput(input).Providers().AzureKeyVaultAPIVersion != "7.4" {
		t.Fatal("blank provider setting bypassed its code-owned default", err)
	}
}

func TestEndpointPoliciesRejectMalformedHTTPURLs(t *testing.T) {
	for _, d := range Definitions() {
		if d.EndpointPolicy == "" {
			continue
		}
		role := API
		if d.Roles&CLI != 0 {
			role = CLI
		}
		for _, raw := range []string{
			"relative/PRIVATE_PATH", "https://user:PRIVATE_PASSWORD@example.invalid",
			"https://example.invalid:", "https://example.invalid:65536",
			"https://[invalid]/PRIVATE_PATH", "https://[::1%25lo]/PRIVATE_PATH",
			"https://example.invalid#", "https://example.invalid/%ZZ",
		} {
			t.Run(d.Name, func(t *testing.T) {
				input, err := parseRoleInput(roleEnvironment(t, role, false, d.Name+"="+raw), role)
				if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, parsedInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
					t.Fatal("malformed HTTP endpoint was accepted or disclosed input", err)
				}
			})
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8080", "https://api.invalid/private-prefix"} {
		if _, err := parseRoleInput(roleEnvironment(t, CLI, false, "EVYDENCE_API_URL="+raw), CLI); err != nil {
			t.Fatal("self-hosted CLI endpoint was rejected or contacted", err)
		}
	}
}

func TestRoleInputPreservesWhitespaceContracts(t *testing.T) {
	input, err := parseRoleInput(roleEnvironment(t, CLI, false, "EVYDENCE_BUILD_STATUS= "), CLI)
	if err != nil || projectInput(input).CLI().BuildStatus != "passed" {
		t.Fatal("blank CLI setting bypassed its code-owned default", err)
	}
	input, err = parseRoleInput(roleEnvironment(t, API, false, "EVYDENCE_S3_ACCESS_KEY_ID= PRIVATE_ID ", "EVYDENCE_S3_SECRET_ACCESS_KEY= PRIVATE_KEY "), API)
	if err != nil {
		t.Fatal(err)
	}
	s := projectInput(input).Storage()
	if s.S3AccessKeyID.Reveal() != " PRIVATE_ID " || s.S3SecretAccessKey.Reveal() != " PRIVATE_KEY " {
		t.Fatal("S3 credentials lost their exact bytes")
	}
}
