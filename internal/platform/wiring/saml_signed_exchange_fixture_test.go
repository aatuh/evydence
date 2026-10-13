package wiring

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/jackc/pgx/v5/pgxpool"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type samlSignedExchangeFixture struct {
	store   *postgres.Store
	pool    *pgxpool.Pool
	key     *rsa.PrivateKey
	der     []byte
	now     time.Time
	request identitydomain.SAMLAuthenticationRequest
	input   identityapp.ExchangeSSOCredentialInput
}
type samlFixtureCanonicalizer struct{ dsig.Canonicalizer }

func (c samlFixtureCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	return c.Canonicalizer.Canonicalize(el.Copy())
}

func newSAMLSignedExchangeFixture(t *testing.T) *samlSignedExchangeFixture {
	t.Helper()
	store, pool := openHTMLReportWiringStore(t)
	_ = seedSSOExchangeWiring(t, pool)
	now := time.Now().UTC().Truncate(time.Second)
	key, der := newSAMLFixtureSigningKey(t, now, 1010)
	pins, err := json.Marshal([]string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE sso_providers SET type='saml',jwks='{}',saml_signing_certificates=$1 WHERE id='provider'`, pins); err != nil {
		t.Fatal(err)
	}
	binding, err := BuildSAMLProviderBindingCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.ConfigureSAMLProviderBinding(t.Context(), samlBindingWiringActor(), "provider", identityapp.ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/v1/sso/session-exchanges"}); err != nil {
		t.Fatal(err)
	}
	begin, err := BuildSAMLAuthenticationRequestCommands(store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	request, state, err := begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	f := &samlSignedExchangeFixture{store: store, pool: pool, key: key, der: der, now: now, request: request, input: identityapp.ExchangeSSOCredentialInput{ProviderID: "provider", Subject: "subject", AuthenticationRequestID: request.ID, StateSecret: state}}
	f.input.SAMLAssertion = f.sign(t, f.assertion())
	return f
}

func newSAMLFixtureSigningKey(t *testing.T, now time.Time, serial int64) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic signed exchange fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}
func (f *samlSignedExchangeFixture) assertion() *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	a.CreateAttr("ID", "_assertion")
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", f.now.Format(time.RFC3339))
	a.CreateElement("saml:Issuer").SetText(f.request.Issuer)
	s := a.CreateElement("saml:Subject")
	s.CreateElement("saml:NameID").SetText("subject")
	c := s.CreateElement("saml:SubjectConfirmation")
	c.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	d := c.CreateElement("saml:SubjectConfirmationData")
	d.CreateAttr("Recipient", f.request.Recipient)
	d.CreateAttr("InResponseTo", f.request.ID)
	d.CreateAttr("NotOnOrAfter", f.now.Add(4*time.Minute).Format(time.RFC3339))
	conditions := a.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", f.now.Add(-time.Minute).Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", f.now.Add(5*time.Minute).Format(time.RFC3339))
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(f.request.Audience)
	statement := a.CreateElement("saml:AuthnStatement")
	statement.CreateAttr("AuthnInstant", f.now.Add(-time.Minute).Format(time.RFC3339))
	statement.CreateAttr("SessionNotOnOrAfter", f.now.Add(2*time.Minute).Format(time.RFC3339))
	statement.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	attribute := a.CreateElement("saml:AttributeStatement").CreateElement("saml:Attribute")
	attribute.CreateAttr("Name", "groups")
	attribute.CreateElement("saml:AttributeValue").SetText("security")
	return a
}
func (f *samlSignedExchangeFixture) sign(t *testing.T, a *etree.Element) string {
	t.Helper()
	s, err := dsig.NewSigningContext(f.key, [][]byte{f.der})
	if err != nil {
		t.Fatal(err)
	}
	s.Canonicalizer = samlFixtureCanonicalizer{dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")}
	signature, err := s.ConstructSignature(a, true)
	if err != nil {
		t.Fatal(err)
	}
	a.InsertChildAt(1, signature)
	cert, err := x509.ParseCertificate(f.der)
	if err != nil {
		t.Fatal(err)
	}
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	validator.Clock = dsig.NewFakeClockAt(f.now)
	if _, err := validator.Validate(a); err != nil {
		t.Fatal("synthetic fixture signature is not valid", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(a)
	raw, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f *samlSignedExchangeFixture) counts(t *testing.T) [5]int {
	t.Helper()
	var v [5]int
	if err := f.pool.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM provider_verifications),(SELECT count(*)FROM sso_sessions),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM saml_authentication_requests WHERE consumed_at IS NOT NULL),(SELECT count(*)FROM saml_assertion_consumptions)`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4]); err != nil {
		t.Fatal(err)
	}
	return v
}
