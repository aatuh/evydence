package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSSOExchangeCommandsRejectUnboundSAMLBeforeVerification(t *testing.T) {
	s, f, _, _ := exchangeCommandsForTest(t)
	f.provider.Type = "saml"
	in := ExchangeSSOCredentialInput{ProviderID: "provider", Subject: "subject", SAMLAssertion: "raw-saml-assertion"}
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrUnauthorized) || session.ID != "" || secret != "" || f.verificationsCalled != 0 || f.transactions != 0 || len(f.sessions)+len(f.verifications)+len(f.audits) != 0 {
		t.Fatal("unbound SAML reached verification or session authority", err)
	}
}

func (f *exchangeCommandFixture) SAMLProviderBindingByID(_ context.Context, id string) (identitydomain.SAMLProviderBinding, error) {
	if id != f.samlBinding.ProviderID {
		return identitydomain.SAMLProviderBinding{}, ErrNotFound
	}
	b := cloneSAMLProviderBinding(f.samlBinding)
	b.Provider = cloneSSOProvider(f.provider)
	return b, nil
}
func (f *exchangeCommandFixture) ReadSAMLAuthenticationRequest(_ context.Context, tenant, provider, id string) (identitydomain.SAMLAuthenticationRequest, error) {
	r := f.samlRequest
	if r.ID != id || r.TenantID != tenant || r.ProviderID != provider {
		return identitydomain.SAMLAuthenticationRequest{}, ErrNotFound
	}
	if r.ConsumedAt != nil {
		at := *r.ConsumedAt
		r.ConsumedAt = &at
	}
	return r, nil
}
func (f *exchangeCommandFixture) ConsumeSAMLAuthenticationRequest(_ context.Context, expected identitydomain.SAMLAuthenticationRequest, proof identitydomain.SAMLAssertionUse, c application.Clock) (time.Time, error) {
	at := c.Now().UTC()
	if f.phase == "saml consume" || !reflect.DeepEqual(expected, f.samlRequest) || !f.samlRequest.PendingAt(at) || !proof.ValidAt(at) || f.samlUses[proof.AssertionHash] {
		return time.Time{}, ErrUnauthorized
	}
	f.samlRequest.ConsumedAt = &at
	f.samlUses[proof.AssertionHash] = true
	return at, nil
}

func boundSAMLExchangeCommandsForTest(t *testing.T) (*SSOExchangeCommands, *exchangeCommandFixture, ExchangeSSOCredentialInput, time.Time) {
	t.Helper()
	s, f, in, now := exchangeCommandsForTest(t)
	f.provider.Type, f.provider.Issuer, f.provider.ClientID = "saml", "https://idp.example.test", "sp"
	f.provider.SAMLSigningCertificates = []string{"fixture public certificate"}
	f.samlBinding = identitydomain.SAMLProviderBinding{TenantID: "tenant", ProviderID: "provider", Provider: cloneSSOProvider(f.provider), Recipient: "https://sp.example.test/v1/sso/session-exchanges", NameIDFormat: identitydomain.SAMLNameIDUnspecified, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: now}
	fp, err := SAMLProviderTrustFingerprint(f.samlBinding)
	if err != nil {
		t.Fatal(err)
	}
	f.samlRequest = identitydomain.SAMLAuthenticationRequest{ID: "samlreq_fixture", TenantID: "tenant", ProviderID: "provider", Delivery: "api", Issuer: f.provider.Issuer, Audience: f.provider.ClientID, Recipient: f.samlBinding.Recipient, NameIDFormat: f.samlBinding.NameIDFormat, TrustFingerprint: fp, StateHash: f.request.StateHash, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), SchemaVersion: identitydomain.SAMLAuthenticationRequestSchemaVersion}
	f.samlUses = map[string]bool{}
	f.result.Nonce = ""
	f.result.IssuedAt, f.result.ExpiresAt = now, now.Add(4*time.Minute)
	f.result.SAMLAssertionID, f.result.SAMLInResponseTo, f.result.SAMLRecipient = "assertion_fixture", f.samlRequest.ID, f.samlRequest.Recipient
	f.result.SessionExpiresAt = now.Add(2 * time.Minute)
	f.result.Checks = nil
	for _, name := range []string{"saml_assertion_signature", "issuer", "audience", "subject", "saml_assertion_time", "saml_recipient", "saml_response_correlation"} {
		f.result.Checks = append(f.result.Checks, identitydomain.VerificationCheck{Name: name, Result: "passed"})
	}
	s.config.SAMLAuthentication = f
	in.IDToken, in.SAMLAssertion, in.AuthenticationRequestID = "", "raw-saml-assertion", f.samlRequest.ID
	return s, f, in, now
}

func TestSSOExchangeCommandsSAMLConsumesProofAndCapsSignedSessionDeadline(t *testing.T) {
	s, f, in, now := boundSAMLExchangeCommandsForTest(t)
	v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
	if err != nil || v.Result != "passed" || session.ID == "" || secret == "" || !session.ExpiresAt.Equal(now.Add(2*time.Minute)) || f.samlRequest.ConsumedAt == nil || len(f.samlUses) != 1 || len(f.sessions) != 1 || len(f.verifications) != 1 || len(f.audits) != 3 {
		t.Fatal("SAML exchange lost atomic proof effects or signed session deadline", err)
	}
	if f.verifiedRequest.SAMLRequestID != f.samlRequest.ID || f.verifiedRequest.SAMLRecipient != f.samlBinding.Recipient || f.verifiedRequest.SAMLNameIDFormat != f.samlBinding.NameIDFormat || f.verifiedRequest.Subject != "subject" {
		t.Fatal("XML verifier was not given server-owned correlation")
	}
	if f.snapshot.SAMLAuthenticationRequest == nil || f.snapshot.SAMLAssertionUse == nil || f.audits[2].EntryType != "saml_authentication_request.consumed" || f.audits[2].SubjectID != f.samlRequest.ID {
		t.Fatal("SAML proof metadata or consumed audit missing")
	}
	before := [3]int{len(f.sessions), len(f.verifications), len(f.audits)}
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrUnauthorized) || session.ID != "" || secret != "" || before != [3]int{len(f.sessions), len(f.verifications), len(f.audits)} {
		t.Fatal("committed SAML replay issued effects", err)
	}
	// Even a fresh login request cannot reuse the same signed assertion ID.
	f.samlRequest.ID, f.samlRequest.ConsumedAt = "samlreq_fresh", nil
	in.AuthenticationRequestID, f.result.SAMLInResponseTo = f.samlRequest.ID, f.samlRequest.ID
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrUnauthorized) || session.ID != "" || secret != "" || f.samlRequest.ConsumedAt != nil || before != [3]int{len(f.sessions), len(f.verifications), len(f.audits)} {
		t.Fatal("fresh request erased assertion replay protection", err)
	}
}

func TestSSOExchangeCommandsSAMLRejectsUnboundStateAndVerifiedMetadata(t *testing.T) {
	for _, scenario := range []string{"missing ports", "missing state", "wrong state", "wrong delivery", "expired request", "foreign request", "changed recipient", "changed certificate", "assertion id", "correlation", "recipient", "missing signature", "failed check", "missing issue time", "old issue time", "long proof", "expired proof", "expired session", "non-finite session"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, in, now := boundSAMLExchangeCommandsForTest(t)
			switch scenario {
			case "missing ports":
				s.config.SAMLAuthentication = nil
			case "missing state":
				in.StateSecret = ""
			case "wrong state":
				in.StateSecret += "A"
			case "wrong delivery":
				in.Delivery = "browser"
			case "expired request":
				f.samlRequest.CreatedAt, f.samlRequest.ExpiresAt = now.Add(-6*time.Minute), now.Add(-time.Minute)
			case "foreign request":
				f.samlRequest.TenantID = "foreign"
			case "changed recipient":
				f.samlBinding.Recipient = "https://foreign.example.test/consume"
			case "changed certificate":
				f.provider.SAMLSigningCertificates = []string{"rotated certificate"}
			case "assertion id":
				f.result.SAMLAssertionID = ""
			case "correlation":
				f.result.SAMLInResponseTo = "foreign-request"
			case "recipient":
				f.result.SAMLRecipient = "https://foreign.example.test/consume"
			case "missing signature":
				f.result.Checks = f.result.Checks[1:]
			case "failed check":
				f.result.Checks[0].Result = "failed"
			case "missing issue time":
				f.result.IssuedAt = time.Time{}
			case "old issue time":
				f.result.IssuedAt = now.Add(-2 * time.Minute)
			case "long proof":
				f.result.ExpiresAt = now.Add(6 * time.Minute)
			case "expired proof":
				f.result.ExpiresAt = now
			case "expired session":
				f.result.SessionExpiresAt = now
			case "non-finite session":
				f.result.SessionExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrUnauthorized) || session.ID != "" || secret != "" || f.samlRequest.ConsumedAt != nil || len(f.samlUses)+len(f.sessions)+len(f.verifications)+len(f.audits) != 0 {
				t.Fatal("unbound or metadata-only SAML granted authority/effects", err)
			}
		})
	}
}

func TestSSOExchangeCommandsSAMLRollbackKeepsProofRetryable(t *testing.T) {
	for _, phase := range []string{"stale", "saml consume", "verification write", "verification audit", "session write", "session audit", "commit"} {
		s, f, in, _ := boundSAMLExchangeCommandsForTest(t)
		f.phase = phase
		if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); err == nil || session.ID != "" || secret != "" || f.samlRequest.ConsumedAt != nil || len(f.samlUses)+len(f.sessions)+len(f.verifications)+len(f.audits) != 0 {
			t.Fatal("failed SAML transaction retained partial proof or authority", phase, err)
		}
		f.phase = ""
		if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); err != nil || session.ID == "" || secret == "" || f.samlRequest.ConsumedAt == nil || len(f.samlUses) != 1 {
			t.Fatal("rolled-back SAML proof was not retryable", phase, err)
		}
	}
}

func TestSSOExchangeCommandsSAMLConsumesVerifiedDenialButNotInvalidSignature(t *testing.T) {
	for _, scenario := range []string{"deactivated user", "unverified link", "verifier"} {
		s, f, in, _ := boundSAMLExchangeCommandsForTest(t)
		switch scenario {
		case "deactivated user":
			f.user.Status = "deactivated"
		case "unverified link":
			f.link.Verified = false
		case "verifier":
			f.phase = "verifier"
		}
		if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrVerificationFailed) || session.ID != "" || secret != "" || len(f.verifications) != 1 || len(f.sessions) != 0 {
			t.Fatal("SAML denial retained session authority", scenario, err)
		}
		if wantConsumed := scenario != "verifier"; (f.samlRequest.ConsumedAt != nil) != wantConsumed || (len(f.samlUses) == 1) != wantConsumed {
			t.Fatal("SAML denial consumed invalid proof or retained valid proof", scenario)
		}
	}
}

func TestSSOExchangeCommandsSAMLWithholdsLateCommittedDelivery(t *testing.T) {
	for _, scenario := range []string{"proof", "request", "cancel"} {
		s, f, in, now := boundSAMLExchangeCommandsForTest(t)
		// Keep the session alive beyond both short-lived proof windows.
		f.result.SessionExpiresAt = now.Add(time.Hour)
		current := now
		s.config.Clock = application.ClockFunc(func() time.Time { return current })
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		f.commitHook = func() {
			switch scenario {
			case "proof":
				current = f.result.ExpiresAt
			case "request":
				current = f.samlRequest.ExpiresAt
			case "cancel":
				cancel()
			}
		}
		_, session, secret, err := s.ExchangeSSOCredential(ctx, in)
		want := ErrUnauthorized
		if scenario == "cancel" {
			want = context.Canceled
		}
		if !errors.Is(err, want) || session.ID != "" || secret != "" || f.samlRequest.ConsumedAt == nil || len(f.sessions) != 1 || len(f.samlUses) != 1 {
			t.Fatal("late committed SAML delivery leaked material or reversed durable state", scenario, err)
		}
	}
}

func TestSSOExchangeCommandsSAMLRollsBackWhenProofExpiresDuringWrites(t *testing.T) {
	s, f, in, now := boundSAMLExchangeCommandsForTest(t)
	f.result.SessionExpiresAt = now.Add(time.Hour)
	current := now
	s.config.Clock = application.ClockFunc(func() time.Time { return current })
	f.auditHook = func(a application.AuditEvent) {
		if a.EntryType == "sso_session.created" {
			current = f.result.ExpiresAt
		}
	}
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrUnauthorized) || session.ID != "" || secret != "" || f.samlRequest.ConsumedAt != nil || len(f.samlUses)+len(f.sessions)+len(f.verifications)+len(f.audits) != 0 {
		t.Fatal("proof expiry inside write callback left partial effects", err)
	}
}
