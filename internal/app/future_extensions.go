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
	Alg           string          `json:"alg"`
	KID           string          `json:"kid"`
	Typ           json.RawMessage `json:"typ"`
	Critical      json.RawMessage `json:"crit"`
	Base64Payload json.RawMessage `json:"b64"`
}

type oidcJWTClaims struct {
	Issuer          string          `json:"iss"`
	Audience        any             `json:"aud"`
	Subject         string          `json:"sub"`
	Email           string          `json:"email"`
	EmailVerified   bool            `json:"email_verified"`
	ExpiresAt       int64           `json:"exp"`
	NotBefore       int64           `json:"nbf,omitempty"`
	IssuedAt        int64           `json:"iat,omitempty"`
	AuthorizedParty json.RawMessage `json:"azp,omitempty"`
	Nonce           string          `json:"nonce,omitempty"`
}

func verifyOIDCIDToken(provider domain.SSOProvider, expectedSubject, token string, now time.Time) ([]domain.VerifyCheck, error) {
	checks := []domain.VerifyCheck{}
	if strings.TrimSpace(provider.Issuer) == "" || strings.TrimSpace(provider.ClientID) == "" || expectedSubject == "" || now.IsZero() {
		return []domain.VerifyCheck{{Name: "id_token_context", Result: "failed"}}, ErrVerificationFailed
	}
	if len(token) > 16*1024 {
		return []domain.VerifyCheck{{Name: "id_token_size", Result: "failed"}}, ErrVerificationFailed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return []domain.VerifyCheck{{Name: "id_token_shape", Result: "failed"}}, ErrVerificationFailed
	}
	headerBody, err := decodeOIDCSegment(parts[0])
	if err != nil {
		return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
	}
	var header oidcJWTHeader
	if err := decodeOIDCObject(headerBody, &header); err != nil {
		return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
	}
	if (header.Alg != "EdDSA" && header.Alg != "RS256") || strings.TrimSpace(header.KID) == "" || len(header.KID) > 256 || len(header.Critical) != 0 {
		return []domain.VerifyCheck{{Name: "id_token_algorithm", Result: "failed"}}, ErrVerificationFailed
	}
	if len(header.Typ) != 0 {
		var typ string
		if json.Unmarshal(header.Typ, &typ) != nil || (!strings.EqualFold(typ, "JWT") && !strings.EqualFold(typ, "application/jwt")) {
			return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
		}
	}
	if len(header.Base64Payload) != 0 {
		var encoded bool
		if json.Unmarshal(header.Base64Payload, &encoded) != nil || !encoded {
			return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
		}
	}
	signature, err := decodeOIDCSegment(parts[2])
	if err != nil {
		return []domain.VerifyCheck{{Name: "id_token_signature", Result: "failed"}}, ErrVerificationFailed
	}
	unsigned := parts[0] + "." + parts[1]
	if err := verifyOIDCJWTSignature(provider.JWKS, header, []byte(unsigned), signature); err != nil {
		return []domain.VerifyCheck{{Name: "id_token_signature", Result: "failed"}}, ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "id_token_signature", Result: "passed"})
	claimsBody, err := decodeOIDCSegment(parts[1])
	if err != nil {
		return checksWithFailure(checks, "id_token_claims"), ErrVerificationFailed
	}
	var claims oidcJWTClaims
	if err := decodeOIDCObject(claimsBody, &claims); err != nil {
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
	if len(claims.AuthorizedParty) != 0 {
		var party string
		if json.Unmarshal(claims.AuthorizedParty, &party) != nil || party != provider.ClientID {
			return checksWithFailure(checks, "authorized_party"), ErrVerificationFailed
		}
	}
	checks = append(checks, domain.VerifyCheck{Name: "authorized_party", Result: "passed"})
	if claims.Subject == "" || claims.Subject != expectedSubject {
		return checksWithFailure(checks, "subject"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "subject", Result: "passed"})
	if claims.ExpiresAt <= 0 || claims.ExpiresAt > 253402300799 || !time.Unix(claims.ExpiresAt, 0).After(now) {
		return checksWithFailure(checks, "expiry"), ErrVerificationFailed
	}
	if claims.IssuedAt <= 0 || claims.IssuedAt >= claims.ExpiresAt || time.Unix(claims.IssuedAt, 0).After(now.Add(time.Minute)) {
		return checksWithFailure(checks, "issued_at"), ErrVerificationFailed
	}
	if claims.NotBefore < 0 || claims.NotBefore >= claims.ExpiresAt || claims.NotBefore != 0 && time.Unix(claims.NotBefore, 0).After(now.Add(time.Minute)) {
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
	key, err := oidcVerificationJWK(jwks, kid, "EdDSA", "OKP")
	if err != nil {
		return nil, err
	}
	if key["crv"] != "Ed25519" {
		return nil, errors.New("unsupported OIDC key curve")
	}
	x, ok := key["x"].(string)
	if !ok || len(x) != 43 {
		return nil, errors.New("invalid OIDC public key")
	}
	pub, err := decodeOIDCSegment(x)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid OIDC public key")
	}
	return ed25519.PublicKey(pub), nil
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
	key, err := oidcVerificationJWK(jwks, kid, "RS256", "RSA")
	if err != nil {
		return nil, err
	}
	nValue, nOK := key["n"].(string)
	eValue, eOK := key["e"].(string)
	if !nOK || !eOK || len(nValue) > 1366 || len(eValue) > 6 {
		return nil, errors.New("invalid OIDC RSA key")
	}
	modulusBytes, err := decodeOIDCSegment(nValue)
	if err != nil || len(modulusBytes) == 0 || modulusBytes[0] == 0 {
		return nil, errors.New("invalid OIDC RSA modulus")
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || modulus.Bit(0) == 0 {
		return nil, errors.New("unsupported OIDC RSA modulus")
	}
	exponentBytes, err := decodeOIDCSegment(eValue)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 || exponentBytes[0] == 0 {
		return nil, errors.New("invalid OIDC RSA exponent")
	}
	var exponent int64
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int64(b)
	}
	if exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
		return nil, errors.New("invalid OIDC RSA exponent")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent)}, nil
}

func checksWithFailure(checks []domain.VerifyCheck, name string) []domain.VerifyCheck {
	return append(checks, domain.VerifyCheck{Name: name, Result: "failed"})
}

func audienceContains(audience any, expected string) bool {
	switch got := audience.(type) {
	case string:
		return got == expected
	case []any:
		// The configured profile trusts exactly one client; no other audiences
		// are implicitly trusted by sharing the same signing provider.
		if len(got) != 1 {
			return false
		}
		value, ok := got[0].(string)
		return ok && value == expected
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
