package wiring

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresSAMLSignedExchangeCommitsSingleUseAuthorityAndSurvivesReconstruction(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	canary := newAggregateLoadCanary(t, t.Context(), f.store)
	c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	v, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input)
	want := [5]int{before[0] + 1, before[1] + 1, before[2] + 3, before[3] + 1, before[4] + 1}
	if err != nil || v.Result != "passed" || v.Profile.ID != "provider-identity-saml-bound.v1" || session.ID == "" || secret == "" || !session.ExpiresAt.Equal(f.now.Add(2*time.Minute)) || f.counts(t) != want || !canary.Intact(t.Context()) {
		t.Fatal("native signed SAML lost atomic authority, profile or deadline", v.Result, v.Profile.ID, err)
	}
	restarted, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, session, secret, err := restarted.ExchangeSSOCredential(t.Context(), f.input); !errors.Is(err, identityapp.ErrUnauthorized) || session.ID != "" || secret != "" || f.counts(t) != want {
		t.Fatal("reconstructed runtime accepted signed SAML replay", err)
	}
	// A newly signed proof correlated to fresh state still cannot reuse its ID.
	begin, err := BuildSAMLAuthenticationRequestCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	f.request, secret, err = begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	f.input.AuthenticationRequestID, f.input.StateSecret = f.request.ID, secret
	f.input.SAMLAssertion = f.sign(t, f.assertion())
	want = f.counts(t)
	if _, session, secret, err := restarted.ExchangeSSOCredential(t.Context(), f.input); !errors.Is(err, identityapp.ErrUnauthorized) || session.ID != "" || secret != "" || f.counts(t) != want {
		t.Fatal("fresh correlation erased signed assertion replay protection", err)
	}
}

func TestPostgresSAMLSignedConcurrentExchangesCommitExactlyOnce(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	const attempts = 8
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input)
			if err == nil && (session.ID == "" || secret == "") {
				err = errors.New("successful SAML omitted authority")
			}
			if err != nil && (session.ID != "" || secret != "") {
				err = errors.New("failed SAML returned authority")
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		} else if !errors.Is(err, identityapp.ErrUnauthorized) {
			t.Fatal("unexpected concurrent SAML failure", err)
		}
	}
	if passed != 1 || f.counts(t) != [5]int{before[0] + 1, before[1] + 1, before[2] + 3, before[3] + 1, before[4] + 1} {
		t.Fatal("signed concurrent SAML duplicated durable authority", passed)
	}
}

func TestPostgresSAMLSignedExchangeRollbackKeepsSameProofRetryable(t *testing.T) {
	for _, stage := range []string{"saml_assertion_consumptions", "provider_verifications", "sso_sessions", "audit_chain_entries", "commit"} {
		t.Run(stage, func(t *testing.T) {
			f := newSAMLSignedExchangeFixture(t)
			c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
			if err != nil {
				t.Fatal(err)
			}
			before := f.counts(t)
			table, definition := stage, "CREATE TRIGGER reject_saml_exchange BEFORE INSERT ON "
			if stage == "commit" {
				table, definition = "saml_assertion_consumptions", "CREATE CONSTRAINT TRIGGER reject_saml_exchange AFTER INSERT ON "
			}
			definition += table
			if stage == "commit" {
				definition += " DEFERRABLE INITIALLY DEFERRED"
			}
			if _, err := f.pool.Exec(t.Context(), `CREATE FUNCTION reject_saml_exchange()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic private SAML storage failure';END$$;`+definition+" FOR EACH ROW EXECUTE FUNCTION reject_saml_exchange()"); err != nil {
				t.Fatal(err)
			}
			if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); err == nil || session.ID != "" || secret != "" || f.counts(t) != before {
				t.Fatal("failed signed exchange committed partial authority", err)
			}
			if _, err := f.pool.Exec(t.Context(), "DROP TRIGGER reject_saml_exchange ON "+table); err != nil {
				t.Fatal(err)
			}
			if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); err != nil || session.ID == "" || secret == "" || f.counts(t) != [5]int{before[0] + 1, before[1] + 1, before[2] + 3, before[3] + 1, before[4] + 1} {
				t.Fatal("rolled-back signed assertion was not retryable", err)
			}
		})
	}
}

func TestPostgresSAMLInvalidSignatureCannotConsumeProofOrIssueAuthority(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	in := f.input
	in.SAMLAssertion = strings.Replace(in.SAMLAssertion, ">subject<", ">tampered-subject<", 1)
	v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
	if !errors.Is(err, identityapp.ErrVerificationFailed) || v.Result != "failed" || session.ID != "" || secret != "" || f.counts(t) != [5]int{before[0] + 1, before[1], before[2] + 1, before[3], before[4]} {
		t.Fatal("invalid signature consumed SAML state or conferred authority", err)
	}
	if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); err != nil || session.ID == "" || secret == "" {
		t.Fatal("invalid signature attempt consumed the valid proof", err)
	}
}

func TestPostgresSAMLSignedBindingConfusionCannotIssueSessions(t *testing.T) {
	for _, field := range []string{"subject", "issuer", "audience", "recipient", "correlation"} {
		t.Run(field, func(t *testing.T) {
			f := newSAMLSignedExchangeFixture(t)
			a := f.assertion()
			switch field {
			case "subject":
				a.FindElement("saml:Subject/saml:NameID").SetText("foreign-subject")
			case "issuer":
				a.FindElement("saml:Issuer").SetText("https://foreign.example.test")
			case "audience":
				a.FindElement("saml:Conditions/saml:AudienceRestriction/saml:Audience").SetText("foreign-client")
			case "recipient":
				a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("Recipient", "https://foreign.example.test/consume")
			case "correlation":
				a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("InResponseTo", "foreign-request")
			}
			f.input.SAMLAssertion = f.sign(t, a)
			c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
			if err != nil {
				t.Fatal(err)
			}
			before := f.counts(t)
			v, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input)
			if !errors.Is(err, identityapp.ErrVerificationFailed) || v.Result != "failed" || session.ID != "" || secret != "" || f.counts(t) != [5]int{before[0] + 1, before[1], before[2] + 1, before[3], before[4]} {
				t.Fatal("valid signature with foreign binding conferred authority", err)
			}
		})
	}
}

func TestPostgresSAMLVerifiedIdentityDenialConsumesSignedProof(t *testing.T) {
	for _, field := range []string{"user", "link"} {
		t.Run(field, func(t *testing.T) {
			f := newSAMLSignedExchangeFixture(t)
			statement := `UPDATE human_users SET status='deactivated' WHERE tenant_id='tenant' AND id='user'`
			if field == "link" {
				statement = `UPDATE user_identity_links SET verified=false WHERE tenant_id='tenant' AND id='link'`
			}
			if _, err := f.pool.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
			c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
			if err != nil {
				t.Fatal(err)
			}
			before := f.counts(t)
			v, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input)
			want := [5]int{before[0] + 1, before[1], before[2] + 2, before[3] + 1, before[4] + 1}
			if !errors.Is(err, identityapp.ErrVerificationFailed) || v.Result != "failed" || session.ID != "" || secret != "" || f.counts(t) != want {
				t.Fatal("verified denial retained replayable proof or issued authority", err)
			}
			if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); !errors.Is(err, identityapp.ErrUnauthorized) || session.ID != "" || secret != "" || f.counts(t) != want {
				t.Fatal("denied proof could be replayed", err)
			}
		})
	}
}

func TestPostgresSAMLSignedExchangeKeyRotationHonorsOverlapAndRemoval(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	oldKey, oldDER := f.key, f.der
	newKey, newDER := newSAMLFixtureSigningKey(t, f.now, 1020)
	pin := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	trust, err := BuildSSOProviderCommands(f.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOExchangeCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	rotate := func(pins []string) {
		t.Helper()
		if _, err := trust.UpdateSSOProviderTrustMaterial(t.Context(), samlBindingWiringActor(), "provider", identityapp.UpdateSSOProviderTrustMaterialInput{SAMLSigningCertificates: pins}); err != nil {
			t.Fatal(err)
		}
	}
	begin, err := BuildSAMLAuthenticationRequestCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(id string) {
		t.Helper()
		var state string
		var err error
		f.request, state, err = begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"})
		if err != nil {
			t.Fatal(err)
		}
		f.input.AuthenticationRequestID, f.input.StateSecret = f.request.ID, state
		a := f.assertion()
		a.CreateAttr("ID", id)
		f.input.SAMLAssertion = f.sign(t, a)
	}
	rotate([]string{pin(oldDER), pin(newDER)})
	before := f.counts(t)
	if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); !errors.Is(err, identityapp.ErrUnauthorized) || session.ID != "" || secret != "" || f.counts(t) != before {
		t.Fatal("trust rotation left old pending request usable", err)
	}
	for i := range 2 {
		if i == 1 {
			f.key, f.der = newKey, newDER
		}
		issue([]string{"_overlap_old", "_overlap_new"}[i])
		if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); err != nil || session.ID == "" || secret == "" {
			t.Fatal("configured rotation overlap rejected a trusted signer", i, err)
		}
	}
	rotate([]string{pin(newDER)})
	f.key, f.der = oldKey, oldDER
	issue("_removed_old")
	before = f.counts(t)
	if v, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); !errors.Is(err, identityapp.ErrVerificationFailed) || v.Result != "failed" || session.ID != "" || secret != "" || f.counts(t) != [5]int{before[0] + 1, before[1], before[2] + 1, before[3], before[4]} {
		t.Fatal("removed SAML signer retained authority", err)
	}
	f.key, f.der = newKey, newDER
	a := f.assertion()
	a.CreateAttr("ID", "_rotated_new")
	f.input.SAMLAssertion = f.sign(t, a)
	if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); err != nil || session.ID == "" || secret == "" {
		t.Fatal("remaining signer could not use unconsumed state", err)
	}
}

type samlDeadlineTransactions struct {
	native  ssoExchangeTransactions
	advance func()
}
type samlDeadlineTransaction struct {
	identityapp.SSOExchangeTransaction
	identityapp.SAMLAuthenticationRequestConsumer
	advance func()
}

func (t samlDeadlineTransactions) ExecuteSSOExchange(ctx context.Context, run func(context.Context, identityapp.SSOExchangeTransaction) error) error {
	return t.native.ExecuteSSOExchange(ctx, func(ctx context.Context, tx identityapp.SSOExchangeTransaction) error {
		consumer, ok := tx.(identityapp.SAMLAuthenticationRequestConsumer)
		if !ok {
			return identityapp.ErrValidation
		}
		return run(ctx, samlDeadlineTransaction{tx, consumer, t.advance})
	})
}
func (t samlDeadlineTransaction) ValidateSSOExchangeState(ctx context.Context, s identityapp.SSOExchangeSnapshot) error {
	if err := t.SSOExchangeTransaction.ValidateSSOExchangeState(ctx, s); err != nil {
		return err
	}
	t.advance()
	return nil
}

func TestPostgresSAMLSelectedCertificateExpiryAfterLocksCannotIssueAuthority(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	certificate, err := x509.ParseCertificate(f.der)
	if err != nil {
		t.Fatal(err)
	}
	deadline := f.now.Add(30 * time.Second)
	certificate.NotAfter = deadline
	f.der, err = x509.CreateCertificate(rand.Reader, certificate, certificate, &f.key.PublicKey, f.key)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := json.Marshal([]string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der}))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE sso_providers SET saml_signing_certificates=$1 WHERE id='provider'`, pins); err != nil {
		t.Fatal(err)
	}
	begin, err := BuildSAMLAuthenticationRequestCommands(f.store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	f.request, f.input.StateSecret, err = begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	f.input.AuthenticationRequestID = f.request.ID
	f.input.SAMLAssertion = f.sign(t, f.assertion())
	credentials, err := buildAuthenticationCredentials("exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	current := time.Now().UTC()
	if !current.Before(deadline) {
		t.Fatal("fixture certificate expired before test began")
	}
	c, err := identityapp.NewSSOExchangeCommands(identityapp.SSOExchangeCommandConfig{
		Reader: ssoExchangeReader{factory: f.store}, Transactions: samlDeadlineTransactions{ssoExchangeTransactions{factory: f.store}, func() { current = deadline }},
		Credentials: credentials, Verifier: ssoCredentialVerifier{}, VerificationPolicy: app.LocalSSOVerificationPolicy{}, SessionGrants: ssoExchangeGroupPolicy{},
		Clock: application.ClockFunc(func() time.Time { return current }), IDs: application.IDGeneratorFunc(application.NewID), AuthenticationRequests: ssoExchangeReader{factory: f.store}, ProofCredentials: credentials, SAMLAuthentication: ssoExchangeReader{factory: f.store},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	if v, session, secret, err := c.ExchangeSSOCredential(t.Context(), f.input); !errors.Is(err, identityapp.ErrUnauthorized) || v.ID != "" || session.ID != "" || secret != "" || f.counts(t) != before {
		t.Fatal("expired certificate crossed lock boundary into durable authority", err)
	}
}
