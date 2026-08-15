// Package sigstore verifies offline Sigstore bundles against operator-provided
// trust material. It deliberately never downloads trust data or attempts an
// implicit online fallback during verification.
package sigstore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const LibraryVersion = "sigstore-go.v1.1.4"

var (
	ErrVerificationFailed            = errors.New("sigstore verification failed")
	ErrOnlineVerificationUnavailable = errors.New("online sigstore verification is unavailable")
)

type VerificationMode = app.CosignVerificationMode

const (
	VerificationModeKeyless = app.CosignVerificationModeKeyless
	VerificationModeKey     = app.CosignVerificationModeKey
)

// Config contains only public verification material. Trusted root and public
// keys are operator configuration, never caller input or persisted receipts.
type Config struct {
	TrustedRootJSON     []byte
	TrustRootVersion    string
	TrustedPublicKeyPEM []byte
}

type Request = app.CosignVerificationRequest

// Receipt intentionally excludes raw bundles, certificates, public-key bytes,
// provider endpoints, and underlying verification errors.
type Receipt = app.CosignVerificationReceipt

type Verifier struct {
	trustedMaterial  root.TrustedMaterial
	trustRootVersion string
}

func New(cfg Config) (*Verifier, error) {
	material := root.TrustedMaterialCollection{}
	if len(cfg.TrustedRootJSON) > 0 {
		trustedRoot, err := root.NewTrustedRootFromJSON(cfg.TrustedRootJSON)
		if err != nil {
			return nil, fmt.Errorf("parse configured Sigstore trusted root: %w", err)
		}
		material = append(material, trustedRoot)
	}
	if len(cfg.TrustedPublicKeyPEM) > 0 {
		keyMaterial, err := trustedPublicKeyMaterial(cfg.TrustedPublicKeyPEM)
		if err != nil {
			return nil, err
		}
		material = append(material, keyMaterial)
	}
	if len(material) == 0 || strings.TrimSpace(cfg.TrustRootVersion) == "" {
		return nil, errors.New("configured Sigstore trust material and trust-root version are required")
	}
	return &Verifier{trustedMaterial: material, trustRootVersion: strings.TrimSpace(cfg.TrustRootVersion)}, nil
}

func trustedPublicKeyMaterial(encoded []byte) (root.TrustedMaterial, error) {
	block, _ := pem.Decode(encoded)
	if block == nil || len(block.Bytes) == 0 {
		return nil, errors.New("configured Sigstore public key is not PEM")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse configured Sigstore public key: %w", err)
	}
	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("load configured Sigstore public key verifier: %w", err)
	}
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
	}), nil
}

func (v *Verifier) VerifyCosign(ctx context.Context, req app.CosignVerificationRequest) (app.CosignVerificationReceipt, error) {
	receipt := Receipt{LibraryVersion: LibraryVersion, TrustRootVersion: v.trustRootVersion}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	if !req.Offline {
		receipt.Limitations = []string{"The configured verifier only supports explicit offline bundles; an online-required profile was not downgraded."}
		return receipt, ErrOnlineVerificationUnavailable
	}
	if err := validateRequest(req); err != nil {
		return failedReceipt(receipt, "verification_input", "invalid verification policy input"), ErrVerificationFailed
	}
	entity := &bundle.Bundle{}
	if err := entity.UnmarshalJSON(req.Bundle); err != nil {
		return failedReceipt(receipt, "sigstore_bundle", "bundle is malformed or unsupported"), ErrVerificationFailed
	}
	digest, err := decodeSHA256Digest(req.ArtifactDigest)
	if err != nil {
		return failedReceipt(receipt, "subject_digest", "artifact digest is invalid"), ErrVerificationFailed
	}
	options := []verify.VerifierOption{verify.WithTransparencyLog(1)}
	if req.Mode == VerificationModeKeyless {
		options = append(options, verify.WithObserverTimestamps(1))
	} else {
		// Key-signed bundles have no Fulcio certificate to time-bind. Rekor
		// inclusion remains mandatory, but requiring a certificate observer
		// timestamp would incorrectly reject valid key-based bundles.
		options = append(options, verify.WithNoObserverTimestamps())
	}
	verifier, err := verify.NewVerifier(v.trustedMaterial, options...)
	if err != nil {
		return failedReceipt(receipt, "verification_configuration", "configured trust material cannot establish the required verification policy"), ErrVerificationFailed
	}
	policyOptions := []verify.PolicyOption{}
	if req.Mode == VerificationModeKey {
		policyOptions = append(policyOptions, verify.WithKey())
	} else {
		identity, err := verify.NewShortCertificateIdentity(req.ExpectedIssuer, "", req.ExpectedIdentity, "")
		if err != nil {
			return failedReceipt(receipt, "certificate_identity_policy", "expected identity policy is invalid"), ErrVerificationFailed
		}
		policyOptions = append(policyOptions, verify.WithCertificateIdentity(identity))
	}
	result, err := verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), policyOptions...))
	if err != nil {
		return failedReceipt(receipt, "cryptographic_verification", "signature, trust, identity, certificate, digest, or transparency verification failed"), ErrVerificationFailed
	}
	receipt.Checks = verifiedChecks(req.Mode)
	if result.VerifiedIdentity != nil {
		receipt.CertificateIdentity = result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
		receipt.CertificateIssuer = result.VerifiedIdentity.Issuer.Issuer
	}
	return receipt, nil
}

func validateRequest(req Request) error {
	if len(req.Bundle) == 0 || len(req.Bundle) > 4<<20 || req.Mode == "" {
		return errors.New("missing or oversized bundle")
	}
	switch req.Mode {
	case VerificationModeKeyless:
		if strings.TrimSpace(req.ExpectedIdentity) == "" || strings.TrimSpace(req.ExpectedIssuer) == "" {
			return errors.New("keyless verification requires expected identity and issuer")
		}
	case VerificationModeKey:
		if strings.TrimSpace(req.ExpectedIdentity) != "" || strings.TrimSpace(req.ExpectedIssuer) != "" {
			return errors.New("key verification does not accept certificate identity policy")
		}
	default:
		return errors.New("unsupported verification mode")
	}
	return nil
}

func decodeSHA256Digest(value string) ([]byte, error) {
	prefix, encoded, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok || prefix != "sha256" || len(encoded) != 64 {
		return nil, errors.New("expected sha256 digest")
	}
	return hex.DecodeString(encoded)
}

func verifiedChecks(mode VerificationMode) []domain.VerifyCheck {
	checks := []domain.VerifyCheck{
		{Name: "sigstore_bundle", Result: "passed", Detail: "supported signed bundle was parsed"},
		{Name: "subject_digest", Result: "passed", Detail: "bundle subject digest matches the stored artifact digest"},
		{Name: "cryptographic_signature", Result: "passed", Detail: "bundle signature bytes verify against trusted signing material"},
		{Name: "rekor_inclusion_proof", Result: "passed", Detail: "embedded Rekor inclusion proof and observer timestamp verify"},
		{Name: "trust_root_version", Result: "passed", Detail: "configured operator trust-root version was used"},
		{Name: "sigstore_library", Result: "passed", Detail: LibraryVersion},
	}
	if mode == VerificationModeKeyless {
		checks = append(checks,
			domain.VerifyCheck{Name: "fulcio_trust_root", Result: "passed", Detail: "Fulcio certificate chain verifies to configured trust material"},
			domain.VerifyCheck{Name: "certificate_validity", Result: "passed", Detail: "certificate validity verifies at the signed observer timestamp"},
			domain.VerifyCheck{Name: "certificate_identity_policy", Result: "passed", Detail: "certificate identity and issuer match caller-supplied policy"},
		)
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "trusted_public_key", Result: "passed", Detail: "configured key-based trust material verified the signature"})
	}
	return checks
}

func failedReceipt(receipt Receipt, name, detail string) Receipt {
	receipt.Checks = []domain.VerifyCheck{{Name: name, Result: "failed", Detail: detail}}
	return receipt
}
