package app

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type oidcJWTHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}

type oidcJWTClaims struct {
	Issuer        string `json:"iss"`
	Audience      any    `json:"aud"`
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	ExpiresAt     int64  `json:"exp"`
	NotBefore     int64  `json:"nbf,omitempty"`
	IssuedAt      int64  `json:"iat,omitempty"`
}

func verifyOIDCIDToken(provider domain.SSOProvider, expectedSubject, token string, now time.Time) ([]domain.VerifyCheck, error) {
	checks := []domain.VerifyCheck{}
	if len(token) > 16*1024 {
		return []domain.VerifyCheck{{Name: "id_token_size", Result: "failed"}}, ErrVerificationFailed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return []domain.VerifyCheck{{Name: "id_token_shape", Result: "failed"}}, ErrVerificationFailed
	}
	headerBody, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
	}
	var header oidcJWTHeader
	if err := json.Unmarshal(headerBody, &header); err != nil {
		return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
	}
	if (header.Alg != "EdDSA" && header.Alg != "RS256") || strings.TrimSpace(header.KID) == "" {
		return []domain.VerifyCheck{{Name: "id_token_algorithm", Result: "failed"}}, ErrVerificationFailed
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return []domain.VerifyCheck{{Name: "id_token_signature", Result: "failed"}}, ErrVerificationFailed
	}
	unsigned := parts[0] + "." + parts[1]
	if err := verifyOIDCJWTSignature(provider.JWKS, header, []byte(unsigned), signature); err != nil {
		return []domain.VerifyCheck{{Name: "id_token_signature", Result: "failed"}}, ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "id_token_signature", Result: "passed"})
	claimsBody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return checksWithFailure(checks, "id_token_claims"), ErrVerificationFailed
	}
	var claims oidcJWTClaims
	if err := json.Unmarshal(claimsBody, &claims); err != nil {
		return checksWithFailure(checks, "id_token_claims"), ErrVerificationFailed
	}
	if claims.Issuer != provider.Issuer {
		return checksWithFailure(checks, "issuer"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "issuer", Result: "passed"})
	if !audienceContains(claims.Audience, provider.ClientID) {
		return checksWithFailure(checks, "audience"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "audience", Result: "passed"})
	if claims.Subject == "" || claims.Subject != expectedSubject {
		return checksWithFailure(checks, "subject"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "subject", Result: "passed"})
	if claims.ExpiresAt == 0 || !time.Unix(claims.ExpiresAt, 0).After(now) {
		return checksWithFailure(checks, "expiry"), ErrVerificationFailed
	}
	if claims.NotBefore != 0 && time.Unix(claims.NotBefore, 0).After(now.Add(time.Minute)) {
		return checksWithFailure(checks, "not_before"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "token_time", Result: "passed"})
	if claims.Email != "" && !claims.EmailVerified {
		return checksWithFailure(checks, "email_verified"), ErrVerificationFailed
	}
	if claims.Email != "" {
		checks = append(checks, domain.VerifyCheck{Name: "email_verified", Result: "passed"})
	}
	return checks, nil
}

func oidcJWKEd25519Key(jwks map[string]any, kid string) (ed25519.PublicKey, error) {
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return nil, errors.New("jwks missing keys")
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok || key["kid"] != kid || key["kty"] != "OKP" || key["crv"] != "Ed25519" {
			continue
		}
		x, _ := key["x"].(string)
		pub, err := base64.RawURLEncoding.DecodeString(x)
		if err == nil && len(pub) == ed25519.PublicKeySize {
			return ed25519.PublicKey(pub), nil
		}
	}
	return nil, errors.New("matching jwk not found")
}

func verifyOIDCJWTSignature(jwks map[string]any, header oidcJWTHeader, unsigned, signature []byte) error {
	switch header.Alg {
	case "EdDSA":
		if len(signature) != ed25519.SignatureSize {
			return errors.New("invalid ed25519 signature size")
		}
		key, err := oidcJWKEd25519Key(jwks, header.KID)
		if err != nil {
			return err
		}
		if !ed25519.Verify(key, unsigned, signature) {
			return errors.New("invalid ed25519 signature")
		}
		return nil
	case "RS256":
		key, err := oidcJWKRSAKey(jwks, header.KID)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(unsigned)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature)
	default:
		return errors.New("unsupported jwt algorithm")
	}
}

func oidcJWKRSAKey(jwks map[string]any, kid string) (*rsa.PublicKey, error) {
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return nil, errors.New("jwks missing keys")
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok || key["kid"] != kid || key["kty"] != "RSA" {
			continue
		}
		nValue, _ := key["n"].(string)
		eValue, _ := key["e"].(string)
		modulusBytes, err := base64.RawURLEncoding.DecodeString(nValue)
		if err != nil || len(modulusBytes) == 0 {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(eValue)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 8 {
			continue
		}
		exponent := 0
		for _, b := range exponentBytes {
			exponent = exponent<<8 + int(b)
		}
		if exponent < 3 {
			continue
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: exponent}, nil
	}
	return nil, errors.New("matching rsa jwk not found")
}

func checksWithFailure(checks []domain.VerifyCheck, name string) []domain.VerifyCheck {
	return append(checks, domain.VerifyCheck{Name: name, Result: "failed"})
}

func audienceContains(audience any, expected string) bool {
	switch got := audience.(type) {
	case string:
		return got == expected
	case []any:
		for _, item := range got {
			if value, ok := item.(string); ok && value == expected {
				return true
			}
		}
	}
	return false
}

type samlAssertionDocument struct {
	XMLName    xml.Name                `xml:"Assertion"`
	Issuer     string                  `xml:"Issuer"`
	Subject    samlAssertionSubject    `xml:"Subject"`
	Conditions samlAssertionConditions `xml:"Conditions"`
	Signature  samlAssertionSignature  `xml:"Signature"`
}

type samlAssertionSubject struct {
	NameID string `xml:"NameID"`
}

type samlAssertionConditions struct {
	NotBefore    string                  `xml:"NotBefore,attr"`
	NotOnOrAfter string                  `xml:"NotOnOrAfter,attr"`
	Audience     samlAudienceRestriction `xml:"AudienceRestriction"`
}

type samlAudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type samlAssertionSignature struct {
	Algorithm      string `xml:"Algorithm,attr"`
	SignatureValue string `xml:"SignatureValue"`
}

func verifySAMLAssertion(provider domain.SSOProvider, expectedSubject, assertion string, now time.Time) ([]domain.VerifyCheck, error) {
	if len(assertion) > 128*1024 {
		return []domain.VerifyCheck{{Name: "saml_assertion_size", Result: "failed"}}, ErrVerificationFailed
	}
	if len(provider.SAMLSigningCertificates) == 0 {
		return []domain.VerifyCheck{{Name: "saml_signing_certificate", Result: "failed"}}, ErrVerificationFailed
	}
	var doc samlAssertionDocument
	decoder := xml.NewDecoder(strings.NewReader(assertion))
	decoder.Strict = true
	if err := decoder.Decode(&doc); err != nil {
		return []domain.VerifyCheck{{Name: "saml_assertion_shape", Result: "failed"}}, ErrVerificationFailed
	}
	checks := []domain.VerifyCheck{{Name: "saml_assertion_shape", Result: "passed"}}
	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(doc.Conditions.NotBefore))
	if err != nil {
		return checksWithFailure(checks, "saml_assertion_time"), ErrVerificationFailed
	}
	notOnOrAfter, err := time.Parse(time.RFC3339, strings.TrimSpace(doc.Conditions.NotOnOrAfter))
	if err != nil {
		return checksWithFailure(checks, "saml_assertion_time"), ErrVerificationFailed
	}
	signatureValue, err := base64.StdEncoding.DecodeString(strings.TrimSpace(doc.Signature.SignatureValue))
	if err != nil || strings.TrimSpace(doc.Signature.Algorithm) != "rsa-sha256" {
		return checksWithFailure(checks, "saml_assertion_signature"), ErrVerificationFailed
	}
	payload := samlAssertionSignaturePayload(strings.TrimSpace(doc.Issuer), strings.TrimSpace(doc.Conditions.Audience.Audience), strings.TrimSpace(doc.Subject.NameID), notBefore.UTC().Format(time.RFC3339), notOnOrAfter.UTC().Format(time.RFC3339))
	if err := verifySAMLAssertionSignature(provider.SAMLSigningCertificates, []byte(payload), signatureValue); err != nil {
		return checksWithFailure(checks, "saml_assertion_signature"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "saml_assertion_signature", Result: "passed"})
	if strings.TrimSpace(doc.Issuer) != provider.Issuer {
		return checksWithFailure(checks, "issuer"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "issuer", Result: "passed"})
	if strings.TrimSpace(doc.Conditions.Audience.Audience) != provider.ClientID {
		return checksWithFailure(checks, "audience"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "audience", Result: "passed"})
	if strings.TrimSpace(doc.Subject.NameID) == "" || strings.TrimSpace(doc.Subject.NameID) != expectedSubject {
		return checksWithFailure(checks, "subject"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "subject", Result: "passed"})
	if notBefore.After(now.Add(time.Minute)) || !notOnOrAfter.After(now) {
		return checksWithFailure(checks, "saml_assertion_time"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "saml_assertion_time", Result: "passed"})
	return checks, nil
}

func samlAssertionSignaturePayload(issuer, audience, subject, notBefore, notOnOrAfter string) string {
	return strings.Join([]string{issuer, audience, subject, notBefore, notOnOrAfter}, "\n")
}

func verifySAMLAssertionSignature(certs []string, payload, signature []byte) error {
	sum := sha256.Sum256(payload)
	for _, raw := range certs {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature) == nil {
			return nil
		}
	}
	return errors.New("no configured saml signing certificate verified assertion")
}
