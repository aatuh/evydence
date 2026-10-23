package config

import (
	"crypto/ed25519"
	"net/url"
	"strings"
	"unicode"
)

func validateSigningInput(input parsedInput) error {
	if input.role != API {
		return nil
	}
	v := input.values
	for _, name := range []string{"EVYDENCE_SIGNING_EXECUTOR_TOKEN", "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN", "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN", "EVYDENCE_AWS_REGION", "EVYDENCE_AWS_KMS_KEY_ID", "EVYDENCE_AZURE_KEY_VAULT_API_VERSION"} {
		if strings.ContainsFunc(strings.TrimSpace(v[name].text), func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return ErrInvalidValue
		}
	}
	key := v["EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64"].bytes
	if len(key) != 0 && len(key) != ed25519.PublicKeySize {
		return ErrInvalidValue
	}
	gcpKey := strings.TrimSpace(v["EVYDENCE_GCP_KMS_KEY_NAME"].text)
	if gcpKey != "" && !validGCPKeyName(gcpKey) {
		return ErrInvalidValue
	}
	for _, name := range []string{"EVYDENCE_AZURE_KEY_VAULT_KEY_NAME", "EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION"} {
		if text := strings.TrimSpace(v[name].text); text != "" && !validKeySegment(text) {
			return ErrInvalidValue
		}
	}
	mode := strings.ReplaceAll(v["EVYDENCE_SIGNING_KEY_MODE"].text, "-", "_")
	gateway := strings.TrimSpace(v["EVYDENCE_SIGNING_EXECUTOR_URL"].text)
	native := false
	switch mode {
	case "aws_kms":
		native = true
		if strings.TrimSpace(v["EVYDENCE_AWS_REGION"].text) == "" || strings.TrimSpace(v["EVYDENCE_AWS_KMS_KEY_ID"].text) == "" {
			return ErrMissingValue
		}
	case "gcp_kms":
		native = true
		if gcpKey == "" {
			return ErrMissingValue
		}
	case "azure_key_vault":
		native = true
		if strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_URL"].text) == "" || strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_KEY_NAME"].text) == "" || strings.TrimSpace(v["EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION"].text) == "" {
			return ErrMissingValue
		}
	case "external", "pkcs11_hsm":
		if gateway == "" {
			return ErrMissingValue
		}
	}
	if gateway != "" && !native && len(key) == 0 {
		return ErrMissingValue
	}
	readiness := strings.TrimSpace(v["EVYDENCE_SIGNING_EXECUTOR_READINESS_URL"].text)
	if readiness == "" {
		return nil // Preserve signing-only construction; this does not assert readiness.
	}
	if gateway == "" {
		return ErrMissingValue
	}
	// Both URLs already passed schema endpoint validation. Discard parser causes
	// even here so the diagnostic cannot contain supplied credentials or paths.
	signingURL, err := url.Parse(gateway)
	if err != nil {
		return ErrInvalidValue
	}
	readinessURL, err := url.Parse(readiness)
	if err != nil || signingURL.Scheme != readinessURL.Scheme || !strings.EqualFold(signingURL.Hostname(), readinessURL.Hostname()) || endpointPort(signingURL) != endpointPort(readinessURL) {
		return ErrInvalidValue
	}
	return nil
}

func endpointPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func validGCPKeyName(value string) bool {
	parts := strings.SplitN(value, "/", 11)
	if len(parts) != 10 {
		return false
	}
	for i, label := range []string{"projects", "locations", "keyRings", "cryptoKeys", "cryptoKeyVersions"} {
		if parts[i*2] != label || !validKeySegment(parts[i*2+1]) {
			return false
		}
	}
	return true
}

func validKeySegment(value string) bool {
	if value == "" || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return value != "."
}
