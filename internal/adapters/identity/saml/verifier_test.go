package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const fixtureAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

type signedFixture struct {
	key *rsa.PrivateKey
	der []byte
	req identityapp.CredentialVerificationRequest
}

// The library's exclusive canonicalizer mutates its input. Fixture signing
// must preserve the original literal ID until the library builds its reference.
type copyingCanonicalizer struct{ dsig.Canonicalizer }

func (c copyingCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	return c.Canonicalizer.Canonicalize(el.Copy())
}

func newSignedFixture(t *testing.T) signedFixture {
	t.Helper()
	now := time.Date(2026, 10, 13, 14, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1010), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return signedFixture{key: key, der: der, req: identityapp.CredentialVerificationRequest{
		Provider: identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "saml", Issuer: "https://idp.example.test", ClientID: "https://sp.example.test", GroupsClaim: "groups", SAMLSigningCertificates: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}},
		Subject:  "subject", SAMLRecipient: "https://sp.example.test/v1/sso/session-exchanges", SAMLRequestID: "_request", Now: now,
	}}
}

func (f signedFixture) assertion() *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", fixtureAssertionNS)
	a.CreateAttr("ID", "_assertion")
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", f.req.Now.Format(time.RFC3339))
	a.CreateElement("saml:Issuer").SetText(f.req.Provider.Issuer)
	s := a.CreateElement("saml:Subject")
	s.CreateElement("saml:NameID").SetText(f.req.Subject)
	c := s.CreateElement("saml:SubjectConfirmation")
	c.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	d := c.CreateElement("saml:SubjectConfirmationData")
	d.CreateAttr("Recipient", f.req.SAMLRecipient)
	d.CreateAttr("InResponseTo", f.req.SAMLRequestID)
	d.CreateAttr("NotOnOrAfter", f.req.Now.Add(4*time.Minute).Format(time.RFC3339))
	conditions := a.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", f.req.Now.Add(-time.Minute).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", f.req.Now.Add(5*time.Minute).Format(time.RFC3339))
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(f.req.Provider.ClientID)
	statement := a.CreateElement("saml:AuthnStatement")
	statement.CreateAttr("AuthnInstant", f.req.Now.Add(-time.Minute).Format(time.RFC3339))
	statement.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	attribute := a.CreateElement("saml:AttributeStatement").CreateElement("saml:Attribute")
	attribute.CreateAttr("Name", "groups")
	attribute.CreateElement("saml:AttributeValue").SetText("engineering")
	return a
}

func (f signedFixture) sign(t *testing.T, a *etree.Element, change func(*dsig.SigningContext)) *etree.Element {
	t.Helper()
	s, err := dsig.NewSigningContext(f.key, [][]byte{f.der})
	if err != nil {
		t.Fatal(err)
	}
	s.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if change != nil {
		change(s)
	}
	s.Canonicalizer = copyingCanonicalizer{s.Canonicalizer}
	signature, err := s.ConstructSignature(a, true)
	if err != nil {
		t.Fatal(err)
	}
	a.InsertChildAt(1, signature)
	return a
}

func assertionText(t *testing.T, a *etree.Element) string {
	t.Helper()
	d := etree.NewDocument()
	d.SetRoot(a)
	raw, err := d.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifierReturnsOnlyVerifiedBoundAssertionFields(t *testing.T) {
	f := newSignedFixture(t)
	a := f.sign(t, f.assertion(), nil)
	if err := signatureProfile(a); err != nil {
		var names []string
		for _, child := range a.SelectElement("ds:Signature").ChildElements() {
			names = append(names, child.Tag)
		}
		t.Fatal("signed fixture does not match signature profile", names, err)
	}
	cert, err := x509.ParseCertificate(f.der)
	if err != nil {
		t.Fatal(err)
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	validation.Clock = dsig.NewFakeClockAt(f.req.Now)
	if _, err := validation.Validate(a); err != nil {
		t.Fatal("signed fixture does not cryptographically validate", err)
	}
	f.req.SAMLAssertion = assertionText(t, a)
	got, err := (Verifier{}).Verify(t.Context(), f.req)
	if err != nil || got.SAMLAssertionID != "_assertion" || got.SAMLInResponseTo != f.req.SAMLRequestID || got.SAMLRecipient != f.req.SAMLRecipient || !got.IssuedAt.Equal(f.req.Now) || !got.ExpiresAt.Equal(f.req.Now.Add(4*time.Minute)) || !reflect.DeepEqual(got.Groups, []string{"engineering"}) {
		t.Fatal("valid signed fixture lost its verified binding", got.Checks, err)
	}
	for _, name := range []string{"saml_assertion_signature", "issuer", "audience", "subject", "saml_assertion_time", "saml_recipient", "saml_response_correlation"} {
		found := false
		for _, check := range got.Checks {
			if check.Name == name && check.Result == "passed" {
				found = true
			}
		}
		if !found {
			t.Fatal("required signed assertion check missing", name)
		}
	}
	in := f.req
	in.SAMLNameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	a = f.assertion()
	a.FindElement("saml:Subject/saml:NameID").CreateAttr("Format", in.SAMLNameIDFormat)
	in.SAMLAssertion = assertionText(t, f.sign(t, a, nil))
	if got, err := (Verifier{}).Verify(t.Context(), in); err != nil || got.SAMLAssertionID != "_assertion" {
		t.Fatal("explicitly configured signed NameID format failed", err)
	}
}

func TestVerifierUsesNamespaceURIsRatherThanPrefixNames(t *testing.T) {
	f := newSignedFixture(t)
	a := f.assertion()
	a.RemoveAttr("xmlns:saml")
	a.CreateAttr("xmlns:ID", fixtureAssertionNS)
	var rename func(*etree.Element)
	rename = func(el *etree.Element) {
		if el.Space == "saml" {
			el.Space = "ID"
		}
		for _, child := range el.ChildElements() {
			rename(child)
		}
	}
	rename(a)
	f.req.SAMLAssertion = assertionText(t, f.sign(t, a, nil))
	if got, err := (Verifier{}).Verify(t.Context(), f.req); err != nil || got.SAMLAssertionID != "_assertion" {
		t.Fatal("valid namespace alias changed assertion identity", got.Checks, err)
	}
}

func TestVerifierRejectsSignedConfusionWrappingAndUnsupportedProfiles(t *testing.T) {
	f := newSignedFixture(t)
	for _, tc := range []struct {
		name   string
		before func(*etree.Element)
		after  func(*etree.Element) *etree.Element
		signer func(*dsig.SigningContext)
	}{
		{name: "issuer", before: func(a *etree.Element) { a.SelectElement("saml:Issuer").SetText("https://foreign.example.test") }},
		{name: "subject", before: func(a *etree.Element) { a.FindElement("saml:Subject/saml:NameID").SetText("foreign") }},
		{name: "subject format confusion", before: func(a *etree.Element) {
			a.FindElement("saml:Subject/saml:NameID").CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
		}},
		{name: "audience", before: func(a *etree.Element) {
			a.FindElement("saml:Conditions/saml:AudienceRestriction/saml:Audience").SetText("foreign")
		}},
		{name: "extra audience", before: func(a *etree.Element) {
			a.FindElement("saml:Conditions/saml:AudienceRestriction").CreateElement("saml:Audience").SetText("foreign")
		}},
		{name: "recipient", before: func(a *etree.Element) {
			a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("Recipient", "https://foreign.example.test/consume")
		}},
		{name: "request correlation", before: func(a *etree.Element) {
			a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("InResponseTo", "_foreign")
		}},
		{name: "expired confirmation", before: func(a *etree.Element) {
			a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("NotOnOrAfter", f.req.Now.Format(time.RFC3339))
		}},
		{name: "future conditions", before: func(a *etree.Element) {
			a.SelectElement("saml:Conditions").CreateAttr("NotBefore", f.req.Now.Add(2*time.Minute).Format(time.RFC3339))
		}},
		{name: "unbounded expiry", before: func(a *etree.Element) {
			a.SelectElement("saml:Conditions").CreateAttr("NotOnOrAfter", f.req.Now.Add(24*time.Hour).Format(time.RFC3339))
		}},
		{name: "authentication after assertion issue", before: func(a *etree.Element) {
			a.SelectElement("saml:AuthnStatement").CreateAttr("AuthnInstant", f.req.Now.Add(30*time.Second).Format(time.RFC3339))
		}},
		{name: "duplicate ID", before: func(a *etree.Element) { a.SelectElement("saml:Subject").CreateAttr("ID", "_assertion") }},
		{name: "duplicate subject", before: func(a *etree.Element) { a.AddChild(a.SelectElement("saml:Subject").Copy()) }},
		{name: "wrong namespace", before: func(a *etree.Element) { a.CreateAttr("xmlns:saml", "urn:foreign") }},
		{name: "misplaced signature", after: func(a *etree.Element) *etree.Element {
			sig := a.SelectElement("ds:Signature")
			a.RemoveChild(sig)
			a.SelectElement("saml:Subject").AddChild(sig)
			return a
		}},
		{name: "second signature", after: func(a *etree.Element) *etree.Element { a.AddChild(a.SelectElement("ds:Signature").Copy()); return a }},
		{name: "wrapping envelope", after: func(a *etree.Element) *etree.Element {
			r := etree.NewElement("samlp:Response")
			r.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
			r.AddChild(a)
			r.AddChild(f.assertion())
			return r
		}},
		{name: "mutated signed field", after: func(a *etree.Element) *etree.Element {
			a.FindElement("saml:Subject/saml:NameID").SetText("foreign")
			return a
		}},
		{name: "another reference", after: func(a *etree.Element) *etree.Element {
			a.FindElement("ds:Signature/ds:SignedInfo/ds:Reference").CreateAttr("URI", "#_foreign")
			return a
		}},
		{name: "SHA1", signer: func(s *dsig.SigningContext) {
			if err := s.SetSignatureMethod(dsig.RSASHA1SignatureMethod); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "inclusive canonicalization", signer: func(s *dsig.SigningContext) { s.Canonicalizer = dsig.MakeC14N11Canonicalizer() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := f.assertion()
			if tc.before != nil {
				tc.before(a)
			}
			a = f.sign(t, a, tc.signer)
			if tc.after != nil {
				a = tc.after(a)
			}
			in := f.req
			in.SAMLAssertion = assertionText(t, a)
			got, err := (Verifier{}).Verify(t.Context(), in)
			if !errors.Is(err, identityapp.ErrVerificationFailed) || got.SAMLAssertionID != "" || got.SAMLInResponseTo != "" || got.SAMLRecipient != "" || len(got.Groups) != 0 || !got.IssuedAt.IsZero() || !got.ExpiresAt.IsZero() {
				t.Fatal("unverified/confused assertion retained signed authority", err)
			}
		})
	}
}

func TestVerifierPreservesTheTightestSignedSessionDeadline(t *testing.T) {
	f := newSignedFixture(t)
	a := f.assertion()
	deadline := f.req.Now.Add(time.Minute)
	a.SelectElement("saml:AuthnStatement").CreateAttr("SessionNotOnOrAfter", deadline.Format(time.RFC3339))
	f.req.SAMLAssertion = assertionText(t, f.sign(t, a, nil))
	got, err := (Verifier{}).Verify(t.Context(), f.req)
	if err != nil || !got.ExpiresAt.Equal(deadline) || !got.SessionExpiresAt.Equal(deadline) {
		t.Fatal("signed session deadline was lost or extended", got.ExpiresAt, got.SessionExpiresAt, err)
	}
}

func replaceFixtureCertificate(t *testing.T, f signedFixture, before, after time.Time, usage x509.KeyUsage) signedFixture {
	t.Helper()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(2020), Subject: pkix.Name{CommonName: "rotation-fixture"}, NotBefore: before, NotAfter: after, KeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &f.key.PublicKey, f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.der = der
	f.req.Provider.SAMLSigningCertificates = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	return f
}

func TestVerifierKeepsSelectedCertificateExpiryAsProofDeadline(t *testing.T) {
	for _, scenario := range []string{"selected expiry", "unrelated overlapping pin", "issue after certificate expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSignedFixture(t)
			deadline := f.req.Now.Add(30 * time.Second)
			f = replaceFixtureCertificate(t, f, f.req.Now.Add(-time.Hour), deadline, x509.KeyUsageDigitalSignature)
			a := f.assertion()
			a.FindElement("saml:AuthnStatement").CreateAttr("SessionNotOnOrAfter", f.req.Now.Add(2*time.Minute).Format(time.RFC3339))
			if scenario == "unrelated overlapping pin" {
				other := newSignedFixture(t)
				other = replaceFixtureCertificate(t, other, f.req.Now.Add(-time.Hour), f.req.Now.Add(time.Second), x509.KeyUsageDigitalSignature)
				f.req.Provider.SAMLSigningCertificates = append(f.req.Provider.SAMLSigningCertificates, other.req.Provider.SAMLSigningCertificates...)
			}
			if scenario == "issue after certificate expiry" {
				a.CreateAttr("IssueInstant", f.req.Now.Add(45*time.Second).Format(time.RFC3339))
			}
			f.req.SAMLAssertion = assertionText(t, f.sign(t, a, nil))
			got, err := (Verifier{}).Verify(t.Context(), f.req)
			if scenario == "issue after certificate expiry" {
				if !errors.Is(err, identityapp.ErrVerificationFailed) || got.SAMLAssertionID != "" {
					t.Fatal("proof issue time exceeded selected trust lifetime", err)
				}
				return
			}
			if err != nil || !got.ExpiresAt.Equal(deadline) || !got.SessionExpiresAt.Equal(f.req.Now.Add(2*time.Minute)) {
				t.Fatal("selected certificate validity was lost or confused with other pins/session lifetime", got.ExpiresAt, got.SessionExpiresAt, err)
			}
		})
	}
}

func TestVerifierCertificatePinsSupportOverlapRemovalAndExclusiveExpiry(t *testing.T) {
	f, rotated := newSignedFixture(t), newSignedFixture(t)
	for _, name := range []string{"overlap", "removed", "untrusted", "exclusive expiry", "future certificate", "encryption-only key", "unused expired pin"} {
		t.Run(name, func(t *testing.T) {
			in := f.req
			signer := f
			in.Provider.SAMLSigningCertificates = append([]string(nil), in.Provider.SAMLSigningCertificates...)
			accept := false
			switch name {
			case "overlap":
				in.Provider.SAMLSigningCertificates = append(in.Provider.SAMLSigningCertificates, rotated.req.Provider.SAMLSigningCertificates...)
				signer, accept = rotated, true
			case "removed":
				in.Provider.SAMLSigningCertificates = rotated.req.Provider.SAMLSigningCertificates
			case "untrusted":
				signer = rotated
			case "exclusive expiry":
				signer = replaceFixtureCertificate(t, f, in.Now.Add(-time.Hour), in.Now, x509.KeyUsageDigitalSignature)
				in.Provider.SAMLSigningCertificates = signer.req.Provider.SAMLSigningCertificates
			case "future certificate":
				signer = replaceFixtureCertificate(t, f, in.Now.Add(time.Minute), in.Now.Add(time.Hour), x509.KeyUsageDigitalSignature)
				in.Provider.SAMLSigningCertificates = signer.req.Provider.SAMLSigningCertificates
			case "encryption-only key":
				signer = replaceFixtureCertificate(t, f, in.Now.Add(-time.Hour), in.Now.Add(time.Hour), x509.KeyUsageKeyEncipherment)
				in.Provider.SAMLSigningCertificates = signer.req.Provider.SAMLSigningCertificates
			case "unused expired pin":
				expired := replaceFixtureCertificate(t, rotated, in.Now.Add(-time.Hour), in.Now, x509.KeyUsageDigitalSignature)
				in.Provider.SAMLSigningCertificates = append(in.Provider.SAMLSigningCertificates, expired.req.Provider.SAMLSigningCertificates...)
				accept = true
			}
			in.SAMLAssertion = assertionText(t, signer.sign(t, signer.assertion(), nil))
			got, err := (Verifier{}).Verify(t.Context(), in)
			if accept {
				if err != nil || got.SAMLAssertionID != "_assertion" {
					t.Fatal("current pinned key failed during rotation", err)
				}
			} else if !errors.Is(err, identityapp.ErrVerificationFailed) || got.SAMLAssertionID != "" || len(got.Groups) != 0 {
				t.Fatal("untrusted or inactive certificate retained authority", err)
			}
		})
	}
}

func TestVerifierBoundsXMLBeforeSignatureWorkAndPropagatesCancellation(t *testing.T) {
	f := newSignedFixture(t)
	for _, raw := range []string{"", strings.Repeat("x", 65537), `<!DOCTYPE Assertion [<!ENTITY x "subject">]><Assertion/>`, strings.Repeat("<a>", 40) + strings.Repeat("</a>", 40), `<a ID="one" ID="two"/>`, string([]byte{0xff}), `<a/><a/>`} {
		in := f.req
		in.SAMLAssertion = raw
		if _, err := (Verifier{}).Verify(t.Context(), in); !errors.Is(err, identityapp.ErrVerificationFailed) {
			t.Fatal("unsafe XML shape accepted", err)
		}
	}
	f.req.SAMLAssertion = assertionText(t, f.sign(t, f.assertion(), nil))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := (Verifier{}).Verify(ctx, f.req); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, identityapp.CredentialVerificationResult{}) {
		t.Fatal("cancelled verification retained authority", err)
	}
}
