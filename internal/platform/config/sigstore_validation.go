package config

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

// SigstoreLibraryVersion identifies the pinned verifier in new receipts.
const SigstoreLibraryVersion = "sigstore-go.v1.3.0"

const (
	maxSigstoreTrustBytes   = 1 << 20
	maxSigstoreVersionBytes = 256
)

// SigstoreTrustMaterial owns parsed public trust data and redacts implicit
// formatting. Material exposes it explicitly to the offline verification adapter.
type SigstoreTrustMaterial struct {
	redactedValue
	material root.TrustedMaterial
	version  string
}

func (t SigstoreTrustMaterial) Material() root.TrustedMaterial { return t.material }
func (t SigstoreTrustMaterial) Version() string                { return t.version }

// ParseSigstoreTrustMaterial parses supplied bytes without files, network,
// environment, TUF refresh, or provider discovery. Library causes are discarded
// because malformed operator input can appear in their diagnostics.
func ParseSigstoreTrustMaterial(rootJSON, keyPEM []byte, version string) (SigstoreTrustMaterial, error) {
	if len(rootJSON) > maxSigstoreTrustBytes || len(keyPEM) > maxSigstoreTrustBytes || !validSigstoreVersion(version) {
		return SigstoreTrustMaterial{}, ErrInvalidValue
	}
	version = strings.TrimSpace(version)
	if (len(rootJSON) == 0 && len(keyPEM) == 0) || version == "" {
		return SigstoreTrustMaterial{}, ErrMissingValue
	}
	material := root.TrustedMaterialCollection{}
	if len(rootJSON) > 0 {
		trustedRoot, err := root.NewTrustedRootFromJSON(slices.Clone(rootJSON))
		if err != nil {
			return SigstoreTrustMaterial{}, ErrInvalidValue
		}
		material = append(material, trustedRoot)
	}
	if len(keyPEM) > 0 {
		key, err := parseSigstorePublicKey(keyPEM)
		if err != nil {
			return SigstoreTrustMaterial{}, err
		}
		material = append(material, key)
	}
	return SigstoreTrustMaterial{material: material, version: version}, nil
}

func parseSigstorePublicKey(encoded []byte) (root.TrustedMaterial, error) {
	encoded = bytes.TrimSpace(slices.Clone(encoded))
	// pem.Decode can skip an invalid first block and return a later valid block.
	// Check framing before decoding so no leading material can be ignored.
	if !bytes.HasPrefix(encoded, []byte("-----BEGIN PUBLIC KEY-----")) || bytes.Count(encoded, []byte("-----BEGIN ")) != 1 || bytes.Count(encoded, []byte("-----END ")) != 1 {
		return nil, ErrInvalidValue
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidValue
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidValue
	}
	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
	if err != nil {
		return nil, ErrInvalidValue
	}
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
	}), nil
}

func validateSigstoreInput(input parsedInput) error {
	if input.role != API {
		return nil
	}
	v := input.values
	version := v["EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION"].text
	if !validSigstoreVersion(version) {
		return ErrInvalidValue
	}
	rootJSON := v["EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64"].bytes
	keyPEM := v["EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64"].bytes
	if len(rootJSON) == 0 && len(keyPEM) == 0 {
		return nil // A version label alone does not enable verification.
	}
	_, err := ParseSigstoreTrustMaterial(rootJSON, keyPEM, version)
	return err
}

func validSigstoreVersion(version string) bool {
	return len(version) <= maxSigstoreVersionBytes && utf8.ValidString(version) && !strings.ContainsFunc(version, unicode.IsControl)
}
