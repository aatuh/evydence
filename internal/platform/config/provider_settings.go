package config

import (
	"slices"
	"time"
)

// ProviderSettings is a value copy. Slice accessors return owned copies.
// Formatting and JSON redact the entire settings value.
type ProviderSettings struct {
	redactedValue
	AWSKMSEndpoint                                  string        `env:"EVYDENCE_AWS_KMS_ENDPOINT"`
	AWSKMSKeyID                                     string        `env:"EVYDENCE_AWS_KMS_KEY_ID"`
	AWSKMSSigningAlgorithm                          string        `env:"EVYDENCE_AWS_KMS_SIGNING_ALGORITHM"`
	AWSKMSTimeout                                   time.Duration `env:"EVYDENCE_AWS_KMS_TIMEOUT_SECONDS"`
	AWSRegion                                       string        `env:"EVYDENCE_AWS_REGION"`
	AzureKeyVaultAlgorithm                          string        `env:"EVYDENCE_AZURE_KEY_VAULT_ALGORITHM"`
	AzureKeyVaultAPIVersion                         string        `env:"EVYDENCE_AZURE_KEY_VAULT_API_VERSION"`
	AzureKeyVaultKeyName                            string        `env:"EVYDENCE_AZURE_KEY_VAULT_KEY_NAME"`
	AzureKeyVaultKeyVersion                         string        `env:"EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION"`
	AzureKeyVaultTimeout                            time.Duration `env:"EVYDENCE_AZURE_KEY_VAULT_TIMEOUT_SECONDS"`
	AzureKeyVaultURL                                string        `env:"EVYDENCE_AZURE_KEY_VAULT_URL"`
	GCPKMSEndpoint                                  string        `env:"EVYDENCE_GCP_KMS_ENDPOINT"`
	GCPKMSKeyName                                   string        `env:"EVYDENCE_GCP_KMS_KEY_NAME"`
	GCPKMSTimeout                                   time.Duration `env:"EVYDENCE_GCP_KMS_TIMEOUT_SECONDS"`
	OIDCDiscoveryAllowInsecureLocalhost             bool          `env:"EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST"`
	OIDCDiscoveryTimeout                            time.Duration `env:"EVYDENCE_OIDC_DISCOVERY_TIMEOUT_SECONDS"`
	OIDCUserInfoAllowInsecureLocalhost              bool          `env:"EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST"`
	OIDCUserInfoTimeout                             time.Duration `env:"EVYDENCE_OIDC_USERINFO_TIMEOUT_SECONDS"`
	ProviderValidationGatewayAllowInsecureLocalhost bool          `env:"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST"`
	ProviderValidationGatewayTimeout                time.Duration `env:"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TIMEOUT_SECONDS"`
	ProviderValidationGatewayToken                  Secret        `env:"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN"`
	ProviderValidationGatewayURL                    string        `env:"EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL"`
	SigningExecutorAllowInsecureLocalhost           bool          `env:"EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST"`
	signingExecutorPublicKey                        []byte        `env:"EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64"`
	SigningExecutorReadinessURL                     string        `env:"EVYDENCE_SIGNING_EXECUTOR_READINESS_URL"`
	SigningExecutorTimeout                          time.Duration `env:"EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS"`
	SigningExecutorToken                            Secret        `env:"EVYDENCE_SIGNING_EXECUTOR_TOKEN"`
	SigningExecutorURL                              string        `env:"EVYDENCE_SIGNING_EXECUTOR_URL"`
	SigningKeyMode                                  string        `env:"EVYDENCE_SIGNING_KEY_MODE"`
	sigstoreTrustedPublicKeyPEM                     []byte        `env:"EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64"`
	sigstoreTrustRootJSON                           []byte        `env:"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64"`
	SigstoreTrustRootVersion                        string        `env:"EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION"`
	TransparencyFetchAllowInsecureLocalhost         bool          `env:"EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST"`
	TransparencyFetchTimeout                        time.Duration `env:"EVYDENCE_TRANSPARENCY_FETCH_TIMEOUT_SECONDS"`
	TransparencyProofGatewayAllowInsecureLocalhost  bool          `env:"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST"`
	TransparencyProofGatewayTimeout                 time.Duration `env:"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TIMEOUT_SECONDS"`
	TransparencyProofGatewayToken                   Secret        `env:"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN"`
	TransparencyProofGatewayURL                     string        `env:"EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL"`
}

func (s ProviderSettings) SigningExecutorPublicKey() []byte {
	return slices.Clone(s.signingExecutorPublicKey)
}

func (s ProviderSettings) SigstoreTrustedPublicKeyPEM() []byte {
	return slices.Clone(s.sigstoreTrustedPublicKeyPEM)
}

func (s ProviderSettings) SigstoreTrustRootJSON() []byte {
	return slices.Clone(s.sigstoreTrustRootJSON)
}
