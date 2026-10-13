package app

import (
	"crypto/rsa"
	"encoding/pem"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type oracleSAMLCanonicalizer struct{ dsig.Canonicalizer }

func (c oracleSAMLCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	return c.Canonicalizer.Canonicalize(el.Copy())
}
func standardOracleSAMLAssertion(t *testing.T, key *rsa.PrivateKey, certificate string, r identitydomain.SAMLAuthenticationRequest, subject string) string {
	t.Helper()
	block, rest := pem.Decode([]byte(certificate))
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid public certificate fixture")
	}
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	a.CreateAttr("ID", "_assertion")
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", r.CreatedAt.Format(time.RFC3339))
	a.CreateElement("saml:Issuer").SetText(r.Issuer)
	s := a.CreateElement("saml:Subject")
	s.CreateElement("saml:NameID").SetText(subject)
	c := s.CreateElement("saml:SubjectConfirmation")
	c.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	d := c.CreateElement("saml:SubjectConfirmationData")
	d.CreateAttr("Recipient", r.Recipient)
	d.CreateAttr("InResponseTo", r.ID)
	d.CreateAttr("NotOnOrAfter", r.CreatedAt.Add(4*time.Minute).Format(time.RFC3339))
	conditions := a.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", r.CreatedAt.Add(-time.Minute).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", r.CreatedAt.Add(5*time.Minute).Format(time.RFC3339))
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(r.Audience)
	authn := a.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", r.CreatedAt.Format(time.RFC3339))
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	signer, err := dsig.NewSigningContext(key, [][]byte{block.Bytes})
	if err != nil {
		t.Fatal(err)
	}
	signer.Canonicalizer = oracleSAMLCanonicalizer{dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")}
	signature, err := signer.ConstructSignature(a, true)
	if err != nil {
		t.Fatal(err)
	}
	a.InsertChildAt(1, signature)
	doc := etree.NewDocument()
	doc.SetRoot(a)
	raw, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
