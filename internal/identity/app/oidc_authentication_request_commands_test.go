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

type oidcRequestCommandFixture struct {
	provider     identitydomain.SSOProvider
	stored       []identitydomain.OIDCAuthenticationRequest
	audits       []application.AuditEvent
	staged       []identitydomain.OIDCAuthenticationRequest
	stagedAudits []application.AuditEvent
	now          time.Time
	reads        int
	fail         string
	afterCommit  func()
}

func (f *oidcRequestCommandFixture) SSOProviderByID(context.Context, string) (identitydomain.SSOProvider, error) {
	f.reads++
	return cloneSSOProvider(f.provider), nil
}
func (f *oidcRequestCommandFixture) ExecuteOIDCAuthenticationRequest(ctx context.Context, fn func(context.Context, OIDCAuthenticationRequestTransaction) error) error {
	f.staged = nil
	f.stagedAudits = nil
	if err := fn(ctx, f); err != nil {
		return err
	}
	if f.fail == "commit" {
		return errors.New("fixture commit failure")
	}
	f.stored = append(f.stored, f.staged...)
	f.audits = append(f.audits, f.stagedAudits...)
	if f.afterCommit != nil {
		f.afterCommit()
	}
	return nil
}
func (f *oidcRequestCommandFixture) ValidateOIDCProvider(_ context.Context, p identitydomain.SSOProvider) error {
	if f.fail == "provider" {
		return ErrConflict
	}
	if p.ID != f.provider.ID || p.TenantID != f.provider.TenantID {
		return ErrConflict
	}
	return nil
}
func (f *oidcRequestCommandFixture) InsertOIDCAuthenticationRequest(_ context.Context, r identitydomain.OIDCAuthenticationRequest, _ time.Time) error {
	if f.fail == "insert" {
		return errors.New("fixture insert failure")
	}
	f.staged = append(f.staged, r)
	return nil
}
func (f *oidcRequestCommandFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, errors.New("fixture audit failure")
	}
	f.stagedAudits = append(f.stagedAudits, e)
	return application.AuditReceipt{ID: e.ID}, nil
}
func oidcRequestCommandsForTest(t *testing.T) (*OIDCAuthenticationRequestCommands, *oidcRequestCommandFixture, *HMACAuthenticationCredentials) {
	t.Helper()
	f := &oidcRequestCommandFixture{provider: identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "oidc", Status: "active", Issuer: "https://issuer.example.test", ClientID: "client", JWKS: map[string]any{"keys": []any{map[string]any{"kid": "fixture-key"}}}}, now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	credentials, err := NewHMACAuthenticationCredentials("fixture authentication state pepper")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewOIDCAuthenticationRequestCommands(OIDCAuthenticationRequestCommandConfig{Reader: f, Transactions: f, Credentials: credentials, Clock: application.ClockFunc(func() time.Time { return f.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_fixture" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, credentials
}

func TestOIDCAuthenticationRequestCreationCommitsHashesAndDeliversOnce(t *testing.T) {
	for _, delivery := range []string{"api", "browser"} {
		t.Run(delivery, func(t *testing.T) {
			c, f, credentials := oidcRequestCommandsForTest(t)
			r, state, nonce, err := c.BeginOIDCAuthentication(t.Context(), BeginOIDCAuthenticationInput{ProviderID: " provider ", Delivery: delivery})
			if err != nil || len(f.stored) != 1 || len(f.audits) != 1 || state == nonce || state == "" || nonce == "" {
				t.Fatal("authentication request was not committed before delivery", err)
			}
			stored := f.stored[0]
			if stored.StateHash != credentials.Hash(state) || stored.NonceHash != credentials.Hash(nonce) || r.StateHash != "" || r.NonceHash != "" || r.TrustFingerprint != "" {
				t.Fatal("authentication request retained raw values or exposed hashes")
			}
			if stored.Delivery != delivery || stored.TenantID != "tenant" || stored.ProviderID != "provider" || stored.TrustFingerprint == "" || !stored.PendingAt(f.now) || !stored.ExpiresAt.Equal(f.now.Add(5*time.Minute)) {
				t.Fatal("request ownership, trust or finite lifetime was not bound")
			}
			if f.audits[0].ActorID == state || f.audits[0].ActorID == nonce || f.audits[0].TenantID != "tenant" {
				t.Fatal("request audit exposed a secret or wrong tenant")
			}
		})
	}
}

func TestOIDCAuthenticationRequestFailureWithholdsSecretsAndRollsBack(t *testing.T) {
	for _, failure := range []string{"provider", "insert", "audit", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, _ := oidcRequestCommandsForTest(t)
			f.fail = failure
			r, state, nonce, err := c.BeginOIDCAuthentication(t.Context(), BeginOIDCAuthenticationInput{ProviderID: "provider", Delivery: "api"})
			if err == nil || state != "" || nonce != "" || !reflect.DeepEqual(r, identitydomain.OIDCAuthenticationRequest{}) || len(f.stored)+len(f.audits) != 0 {
				t.Fatal("failed request published secrets or durable effects")
			}
		})
	}
}

func TestOIDCAuthenticationRequestRejectsInvalidInputBeforeTrustRead(t *testing.T) {
	for _, in := range []BeginOIDCAuthenticationInput{{ProviderID: ""}, {ProviderID: "provider", Delivery: "redirect"}, {ProviderID: "provider\x00"}} {
		c, f, _ := oidcRequestCommandsForTest(t)
		if _, state, nonce, err := c.BeginOIDCAuthentication(t.Context(), in); !errors.Is(err, ErrValidation) || state != "" || nonce != "" || f.reads != 0 {
			t.Fatal("invalid request reached trust or secret delivery")
		}
	}
}

func TestOIDCAuthenticationRequestWithholdsExpiredCommittedDelivery(t *testing.T) {
	c, f, _ := oidcRequestCommandsForTest(t)
	f.afterCommit = func() { f.now = f.now.Add(5 * time.Minute) }
	if _, state, nonce, err := c.BeginOIDCAuthentication(t.Context(), BeginOIDCAuthenticationInput{ProviderID: "provider"}); err == nil || state != "" || nonce != "" || len(f.stored) != 1 {
		t.Fatal("late commit returned expired authentication material")
	}
}

func TestOIDCAuthenticationRequestRejectsLifetimeOverflowBeforeStorage(t *testing.T) {
	c, f, _ := oidcRequestCommandsForTest(t)
	f.now = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	if _, state, nonce, err := c.BeginOIDCAuthentication(t.Context(), BeginOIDCAuthenticationInput{ProviderID: "provider"}); !errors.Is(err, ErrValidation) || state != "" || nonce != "" || len(f.stored) != 0 || len(f.staged) != 0 {
		t.Fatal("unsupported expiry reached storage or secret delivery", err)
	}
}
