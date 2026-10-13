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

type samlRequestCommandFixture struct {
	binding              identitydomain.SAMLProviderBinding
	stored, staged       []identitydomain.SAMLAuthenticationRequest
	audits, stagedAudits []application.AuditEvent
	now                  time.Time
	reads                int
	fail                 string
	afterCommit          func()
}

func (f *samlRequestCommandFixture) SAMLProviderBindingByID(context.Context, string) (identitydomain.SAMLProviderBinding, error) {
	f.reads++
	return cloneSAMLProviderBinding(f.binding), nil
}
func (f *samlRequestCommandFixture) ExecuteSAMLAuthenticationRequest(ctx context.Context, fn func(context.Context, SAMLAuthenticationRequestTransaction) error) error {
	f.staged, f.stagedAudits = nil, nil
	if err := fn(ctx, f); err != nil {
		return err
	}
	if f.fail == "commit" {
		return errors.New("fixture commit failure")
	}
	f.stored, f.audits = append(f.stored, f.staged...), append(f.audits, f.stagedAudits...)
	if f.afterCommit != nil {
		f.afterCommit()
	}
	return nil
}
func (f *samlRequestCommandFixture) ValidateSAMLProviderBinding(_ context.Context, b identitydomain.SAMLProviderBinding) error {
	if f.fail == "provider" {
		return ErrConflict
	}
	want, err := SAMLProviderTrustFingerprint(b)
	if err != nil {
		return err
	}
	got, err := SAMLProviderTrustFingerprint(f.binding)
	if err != nil || want != got {
		return ErrConflict
	}
	return nil
}
func (f *samlRequestCommandFixture) InsertSAMLAuthenticationRequest(_ context.Context, r identitydomain.SAMLAuthenticationRequest, _ time.Time) error {
	if f.fail == "insert" {
		return errors.New("fixture insert failure")
	}
	f.staged = append(f.staged, r)
	return nil
}
func (f *samlRequestCommandFixture) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, errors.New("fixture audit failure")
	}
	f.stagedAudits = append(f.stagedAudits, a)
	return application.AuditReceipt{ID: a.ID}, nil
}
func samlRequestCommandsForTest(t *testing.T) (*SAMLAuthenticationRequestCommands, *samlRequestCommandFixture, *HMACAuthenticationCredentials) {
	t.Helper()
	now := time.Date(2026, 10, 13, 17, 0, 0, 0, time.UTC)
	f := &samlRequestCommandFixture{now: now, binding: identitydomain.SAMLProviderBinding{TenantID: "tenant", ProviderID: "provider", Recipient: "https://sp.example.test/v1/sso/session-exchanges", NameIDFormat: identitydomain.SAMLNameIDUnspecified, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: now,
		Provider: identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "saml", Status: "active", Issuer: "https://idp.example.test", ClientID: "sp", SAMLSigningCertificates: []string{"fixture-public-certificate"}}}}
	credentials, err := NewHMACAuthenticationCredentials("fixture SAML login state pepper")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewSAMLAuthenticationRequestCommands(SAMLAuthenticationRequestCommandConfig{Reader: f, Transactions: f, Credentials: credentials, Clock: application.ClockFunc(func() time.Time { return f.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_fixture" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, credentials
}

func TestSAMLAuthenticationRequestCommitsConfiguredBindingsAndHashBeforeDelivery(t *testing.T) {
	for _, delivery := range []string{"api", "browser"} {
		c, f, credentials := samlRequestCommandsForTest(t)
		r, state, err := c.BeginSAMLAuthentication(t.Context(), BeginSAMLAuthenticationInput{ProviderID: "provider", Delivery: delivery})
		if err != nil || state == "" || len(f.stored) != 1 || len(f.audits) != 1 {
			t.Fatal("SAML state was not committed before delivery", err)
		}
		stored := f.stored[0]
		if r.StateHash != "" || r.TrustFingerprint != "" || stored.StateHash != credentials.Hash(state) || stored.TrustFingerprint == "" || !stored.PendingAt(f.now) || stored.Recipient != f.binding.Recipient || stored.NameIDFormat != f.binding.NameIDFormat || stored.Issuer != f.binding.Provider.Issuer || stored.Audience != f.binding.Provider.ClientID || stored.Delivery != delivery || !stored.ExpiresAt.Equal(f.now.Add(5*time.Minute)) {
			t.Fatal("SAML request lost private state, owner or configured bindings")
		}
		if f.audits[0].ActorID == state || f.audits[0].TenantID != "tenant" || r.ID != f.audits[0].ActorID {
			t.Fatal("SAML request audit lost ownership or exposed a secret")
		}
	}
}

func TestSAMLAuthenticationRequestFailuresWithholdSecretsAndRollback(t *testing.T) {
	for _, phase := range []string{"provider", "insert", "audit", "commit"} {
		c, f, _ := samlRequestCommandsForTest(t)
		f.fail = phase
		r, state, err := c.BeginSAMLAuthentication(t.Context(), BeginSAMLAuthenticationInput{ProviderID: "provider"})
		if err == nil || state != "" || !reflect.DeepEqual(r, identitydomain.SAMLAuthenticationRequest{}) || len(f.stored)+len(f.audits) != 0 {
			t.Fatal("failed SAML creation published state or partial history", err)
		}
	}
}

func TestSAMLAuthenticationRequestRejectsInvalidInputAndUnboundProvider(t *testing.T) {
	for _, in := range []BeginSAMLAuthenticationInput{{}, {ProviderID: "provider\x00"}, {ProviderID: "provider", Delivery: "redirect"}} {
		c, f, _ := samlRequestCommandsForTest(t)
		if _, state, err := c.BeginSAMLAuthentication(t.Context(), in); !errors.Is(err, ErrValidation) || state != "" || f.reads != 0 {
			t.Fatal("invalid SAML input reached trust or state creation", err)
		}
	}
	for _, edit := range []func(*identitydomain.SAMLProviderBinding){
		func(b *identitydomain.SAMLProviderBinding) { b.TenantID = "foreign" },
		func(b *identitydomain.SAMLProviderBinding) { b.Provider.Type = "oidc" },
		func(b *identitydomain.SAMLProviderBinding) { b.Provider.Status = "inactive" },
		func(b *identitydomain.SAMLProviderBinding) { b.Recipient = "http://sp.example.test/consume" },
		func(b *identitydomain.SAMLProviderBinding) {
			b.Recipient = "https://sp.example.test/consume?return=foreign"
		},
		func(b *identitydomain.SAMLProviderBinding) { b.NameIDFormat = "unknown" },
	} {
		c, f, _ := samlRequestCommandsForTest(t)
		edit(&f.binding)
		if _, state, err := c.BeginSAMLAuthentication(t.Context(), BeginSAMLAuthenticationInput{ProviderID: "provider"}); err == nil || state != "" || len(f.staged) != 0 {
			t.Fatal("unbound SAML provider allocated login authority", err)
		}
	}
}

func TestSAMLAuthenticationRequestWithholdsLateOrCancelledCommittedDelivery(t *testing.T) {
	for _, phase := range []string{"expiry", "cancel"} {
		c, f, _ := samlRequestCommandsForTest(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		f.afterCommit = func() {
			if phase == "expiry" {
				f.now = f.now.Add(5 * time.Minute)
			} else {
				cancel()
			}
		}
		if _, state, err := c.BeginSAMLAuthentication(ctx, BeginSAMLAuthenticationInput{ProviderID: "provider"}); err == nil || state != "" || len(f.stored) != 1 || len(f.audits) != 1 {
			t.Fatal("late delivery disclosed state or erased committed history", err)
		}
	}
}

func TestSAMLTrustFingerprintIncludesBindingAndCertificateRotation(t *testing.T) {
	_, f, _ := samlRequestCommandsForTest(t)
	before, err := SAMLProviderTrustFingerprint(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*identitydomain.SAMLProviderBinding){
		func(b *identitydomain.SAMLProviderBinding) { b.Recipient = "https://other.example.test/consume" },
		func(b *identitydomain.SAMLProviderBinding) {
			b.NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		},
		func(b *identitydomain.SAMLProviderBinding) {
			b.Provider.SAMLSigningCertificates[0] = "rotated-public-certificate"
		},
		func(b *identitydomain.SAMLProviderBinding) { b.UpdatedAt = b.UpdatedAt.Add(time.Second) },
	} {
		b := cloneSAMLProviderBinding(f.binding)
		edit(&b)
		after, err := SAMLProviderTrustFingerprint(b)
		if err != nil || after == before {
			t.Fatal("SAML trust change retained a pending request's authority", err)
		}
	}
}

func TestSAMLAssertionFingerprintNamespacesReplayByTenantProviderAndIssuer(t *testing.T) {
	r := identitydomain.SAMLAuthenticationRequest{TenantID: "tenant", ProviderID: "provider", Issuer: "https://idp.example.test"}
	before, err := SAMLAssertionFingerprint(r, "_assertion")
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*identitydomain.SAMLAuthenticationRequest){
		func(v *identitydomain.SAMLAuthenticationRequest) { v.TenantID = "other" },
		func(v *identitydomain.SAMLAuthenticationRequest) { v.ProviderID = "other" },
		func(v *identitydomain.SAMLAuthenticationRequest) { v.Issuer = "https://other.example.test" },
	} {
		v := r
		edit(&v)
		after, err := SAMLAssertionFingerprint(v, "_assertion")
		if err != nil || after == before {
			t.Fatal("replay identity crossed a configured authority boundary", err)
		}
	}
	if _, err := SAMLAssertionFingerprint(r, "bad:identifier"); !errors.Is(err, ErrValidation) {
		t.Fatal("ambiguous assertion identity reached replay hashing", err)
	}
}
