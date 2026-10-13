// Package saml verifies Evydence's bounded, request-correlated SAML assertion
// profile using configured public certificate pins and standard XML Signature.
package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type Verifier struct{}

var _ identityapp.CredentialVerifier = Verifier{}

const unspecifiedNameID = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

func nameIDFormat(value string) (string, bool) {
	if value == "" {
		value = unspecifiedNameID
	}
	switch value {
	case unspecifiedNameID, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
		return value, true
	default:
		return "", false
	}
}

func failure(name string) (identityapp.CredentialVerificationResult, error) {
	return identityapp.CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: name, Result: "failed"}}}, identityapp.ErrVerificationFailed
}

func (Verifier) Verify(ctx context.Context, in identityapp.CredentialVerificationRequest) (identityapp.CredentialVerificationResult, error) {
	if ctx == nil {
		return identityapp.CredentialVerificationResult{}, identityapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return identityapp.CredentialVerificationResult{}, err
	}
	u, err := url.Parse(in.SAMLRecipient)
	_, supportedFormat := nameIDFormat(in.SAMLNameIDFormat)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !supportedFormat || !xmlID.MatchString(in.SAMLRequestID) || in.Provider.Type != "saml" || in.Provider.ID == "" || in.Provider.TenantID == "" || in.Provider.Issuer == "" || in.Provider.ClientID == "" || in.Subject == "" || len(in.Subject) > 1024 || in.Now.IsZero() || in.Now.Year() < 1 || in.Now.Year() > 9999 {
		return failure("saml_assertion_context")
	}
	root, err := boundedXML(ctx, in.SAMLAssertion)
	if err != nil {
		if ctx.Err() != nil {
			return identityapp.CredentialVerificationResult{}, ctx.Err()
		}
		return failure("saml_assertion_shape")
	}
	if !named(root, assertionNamespace, "Assertion") || !allowedAttrs(root, "ID", "Version", "IssueInstant") || !xmlID.MatchString(literalAttribute(root, "ID")) || literalAttribute(root, "Version") != "2.0" || signatureProfile(root) != nil {
		return failure("saml_assertion_signature")
	}
	certs, err := certificatePins(in.Provider.SAMLSigningCertificates, in.Now)
	if err != nil {
		return failure("saml_signing_certificate")
	}
	selected, err := selectedCertificate(root, certs)
	if err != nil {
		return failure("saml_signing_certificate")
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	validation.Clock = dsig.NewFakeClockAt(in.Now)
	literalRootIDFirst(root)
	validated, err := validation.Validate(root)
	if err != nil {
		return failure("saml_assertion_signature")
	}
	if err := ctx.Err(); err != nil {
		return identityapp.CredentialVerificationResult{}, err
	}
	// Never read claims from root: only the library's verified referenced bytes
	// can become identity, group or request-binding authority.
	result, err := assertionClaims(validated, in)
	if err != nil {
		return failure("saml_assertion_bindings")
	}
	// Certificate validity is a proof deadline, not an ongoing session policy.
	// The exchange rechecks this ceiling after locks, writes and commit.
	if selected.NotAfter.Before(result.ExpiresAt) {
		result.ExpiresAt = selected.NotAfter.UTC()
	}
	if !result.ExpiresAt.After(result.IssuedAt) {
		return failure("saml_signing_certificate")
	}
	for _, name := range []string{"saml_assertion_signature", "issuer", "audience", "subject", "saml_assertion_time", "saml_recipient", "saml_response_correlation"} {
		result.Checks = append(result.Checks, identitydomain.VerificationCheck{Name: name, Result: "passed"})
	}
	if err := ctx.Err(); err != nil {
		return identityapp.CredentialVerificationResult{}, err
	}
	return result, nil
}

func selectedCertificate(root *etree.Element, pins []*x509.Certificate) (*x509.Certificate, error) {
	children := root.ChildElements()
	if len(children) < 2 || !named(children[1], dsig.Namespace, "Signature") {
		return nil, errProfile
	}
	parts, err := exactChildren(children[1], dsig.Namespace, "SignedInfo", "SignatureValue", "KeyInfo")
	if err != nil {
		return nil, err
	}
	data, err := exactChildren(parts[2], dsig.Namespace, "X509Data")
	if err != nil {
		return nil, err
	}
	encoded, err := exactChildren(data[0], dsig.Namespace, "X509Certificate")
	if err != nil {
		return nil, err
	}
	raw, err := base64Value(encoded[0], 0)
	if err != nil {
		return nil, err
	}
	for _, pin := range pins {
		if bytes.Equal(raw, pin.Raw) {
			return pin, nil
		}
	}
	return nil, errProfile
}

func certificatePins(values []string, now time.Time) ([]*x509.Certificate, error) {
	if len(values) == 0 || len(values) > 5 {
		return nil, errProfile
	}
	certs := make([]*x509.Certificate, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if len(value) > 16384 {
			return nil, errProfile
		}
		block, rest := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
			return nil, errProfile
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errProfile
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.N.Bit(0) == 0 || key.E < 3 || key.E > 2147483647 || key.E%2 == 0 || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || seen[string(cert.Raw)] {
			return nil, errProfile
		}
		seen[string(cert.Raw)] = true
		// Retained expired/future rotation pins cannot authorize the selected
		// certificate, but must not disable a different currently valid pin.
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errProfile
	}
	return certs, nil
}

func instant(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return time.Time{}, errProfile
	}
	return t.UTC(), nil
}

func assertionClaims(a *etree.Element, in identityapp.CredentialVerificationRequest) (identityapp.CredentialVerificationResult, error) {
	var result identityapp.CredentialVerificationResult
	if !named(a, assertionNamespace, "Assertion") || !allowedAttrs(a, "ID", "Version", "IssueInstant") || literalAttribute(a, "Version") != "2.0" || !xmlID.MatchString(literalAttribute(a, "ID")) {
		return result, errProfile
	}
	names := []string{"Issuer", "Subject", "Conditions", "AuthnStatement"}
	if len(a.ChildElements()) == 5 {
		names = append(names, "AttributeStatement")
	}
	parts, err := exactChildren(a, assertionNamespace, names...)
	if err != nil || !allowedAttrs(parts[0]) || !allowedAttrs(parts[1]) {
		return result, errProfile
	}
	issuer, err := leaf(parts[0], 4096)
	if err != nil || issuer != in.Provider.Issuer {
		return result, errProfile
	}
	issued, err := instant(literalAttribute(a, "IssueInstant"))
	if err != nil || issued.After(in.Now.Add(time.Minute)) || issued.Before(in.Now.Add(-5*time.Minute)) {
		return result, errProfile
	}
	subject, err := exactChildren(parts[1], assertionNamespace, "NameID", "SubjectConfirmation")
	if err != nil || !allowedAttrs(subject[0], "Format", "NameQualifier", "SPNameQualifier") || !allowedAttrs(subject[1], "Method") || literalAttribute(subject[1], "Method") != subjectConfirmationMethod {
		return result, errProfile
	}
	value, err := leaf(subject[0], 1024)
	if err != nil || value != in.Subject {
		return result, errProfile
	}
	expectedFormat, _ := nameIDFormat(in.SAMLNameIDFormat)
	actualFormat, supported := nameIDFormat(literalAttribute(subject[0], "Format"))
	if !supported || actualFormat != expectedFormat {
		return result, errProfile
	}
	if q := literalAttribute(subject[0], "NameQualifier"); q != "" && q != in.Provider.Issuer {
		return result, errProfile
	}
	if q := literalAttribute(subject[0], "SPNameQualifier"); q != "" && q != in.Provider.ClientID {
		return result, errProfile
	}
	data, err := exactChildren(subject[1], assertionNamespace, "SubjectConfirmationData")
	if err != nil || !allowedAttrs(data[0], "Recipient", "InResponseTo", "NotOnOrAfter") || len(data[0].ChildElements()) != 0 || strings.TrimSpace(data[0].Text()) != "" || literalAttribute(data[0], "Recipient") != in.SAMLRecipient || literalAttribute(data[0], "InResponseTo") != in.SAMLRequestID {
		return result, errProfile
	}
	confirmationEnd, err := instant(literalAttribute(data[0], "NotOnOrAfter"))
	if err != nil || !confirmationEnd.After(in.Now) || !confirmationEnd.After(issued) || confirmationEnd.After(issued.Add(5*time.Minute)) {
		return result, errProfile
	}
	conditions := parts[2]
	if !allowedAttrs(conditions, "NotBefore", "NotOnOrAfter") {
		return result, errProfile
	}
	conditionParts, err := children(conditions, assertionNamespace, "AudienceRestriction", "OneTimeUse")
	if err != nil || len(conditionParts["AudienceRestriction"]) != 1 || len(conditionParts["OneTimeUse"]) > 1 {
		return result, errProfile
	}
	if ones := conditionParts["OneTimeUse"]; len(ones) == 1 && (!allowedAttrs(ones[0]) || len(ones[0].Child) != 0) {
		return result, errProfile
	}
	start, err := instant(literalAttribute(conditions, "NotBefore"))
	if err != nil || start.After(in.Now.Add(time.Minute)) {
		return result, errProfile
	}
	end, err := instant(literalAttribute(conditions, "NotOnOrAfter"))
	if err != nil || !end.After(in.Now) || !end.After(start) || !end.After(issued) || end.After(issued.Add(5*time.Minute)) {
		return result, errProfile
	}
	restriction := conditionParts["AudienceRestriction"][0]
	if !allowedAttrs(restriction) {
		return result, errProfile
	}
	audience, err := exactChildren(restriction, assertionNamespace, "Audience")
	if err != nil || !allowedAttrs(audience[0]) {
		return result, errProfile
	}
	value, err = leaf(audience[0], 4096)
	if err != nil || value != in.Provider.ClientID {
		return result, errProfile
	}
	statement := parts[3]
	if !allowedAttrs(statement, "AuthnInstant", "SessionIndex", "SessionNotOnOrAfter") || len(literalAttribute(statement, "SessionIndex")) > 1024 {
		return result, errProfile
	}
	authenticated, err := instant(literalAttribute(statement, "AuthnInstant"))
	if err != nil || authenticated.After(in.Now.Add(time.Minute)) || authenticated.After(issued) {
		return result, errProfile
	}
	authnContext, err := exactChildren(statement, assertionNamespace, "AuthnContext")
	if err != nil || !allowedAttrs(authnContext[0]) {
		return result, errProfile
	}
	class, err := exactChildren(authnContext[0], assertionNamespace, "AuthnContextClassRef")
	if err != nil || !allowedAttrs(class[0]) {
		return result, errProfile
	}
	if _, err := leaf(class[0], 4096); err != nil {
		return result, errProfile
	}
	if deadline := literalAttribute(statement, "SessionNotOnOrAfter"); deadline != "" {
		result.SessionExpiresAt, err = instant(deadline)
		if err != nil || !result.SessionExpiresAt.After(in.Now) || !result.SessionExpiresAt.After(issued) {
			return identityapp.CredentialVerificationResult{}, errProfile
		}
	}
	if len(parts) == 5 {
		result.Groups, err = attributeGroups(parts[4], in.Provider.GroupsClaim)
		if err != nil {
			return identityapp.CredentialVerificationResult{}, err
		}
	}
	if confirmationEnd.Before(end) {
		end = confirmationEnd
	}
	if !result.SessionExpiresAt.IsZero() && result.SessionExpiresAt.Before(end) {
		end = result.SessionExpiresAt
	}
	result.SAMLAssertionID, result.SAMLInResponseTo, result.SAMLRecipient = literalAttribute(a, "ID"), in.SAMLRequestID, in.SAMLRecipient
	result.IssuedAt, result.ExpiresAt = issued, end
	return result, nil
}

func attributeGroups(statement *etree.Element, claim string) ([]string, error) {
	if !allowedAttrs(statement) {
		return nil, errProfile
	}
	attributes, err := children(statement, assertionNamespace, "Attribute")
	if err != nil || len(attributes["Attribute"]) == 0 || len(attributes["Attribute"]) > 32 {
		return nil, errProfile
	}
	var groups []string
	names, seen := map[string]bool{}, map[string]bool{}
	count := 0
	for _, attribute := range attributes["Attribute"] {
		name := literalAttribute(attribute, "Name")
		if !allowedAttrs(attribute, "Name", "NameFormat", "FriendlyName") || name == "" || len(name) > 1024 || names[name] {
			return nil, errProfile
		}
		names[name] = true
		values, err := children(attribute, assertionNamespace, "AttributeValue")
		if err != nil || len(values["AttributeValue"]) == 0 {
			return nil, errProfile
		}
		for _, el := range values["AttributeValue"] {
			count++
			if count > 64 || !allowedAttrs(el) {
				return nil, errProfile
			}
			value, err := leaf(el, 1024)
			if err != nil || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n\t") {
				return nil, errProfile
			}
			if claim != "" && name == claim {
				if seen[value] {
					return nil, errProfile
				}
				seen[value] = true
				groups = append(groups, value)
			}
		}
	}
	return groups, nil
}
