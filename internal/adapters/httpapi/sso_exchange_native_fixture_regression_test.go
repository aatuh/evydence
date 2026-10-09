package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var errSSOExchangeFixture = errors.New("private exchange fixture failure")

type ssoExchangeFailureFactory struct {
	app.UnitOfWorkFactory
	phase    string
	failures int
}
type ssoExchangeFailureUnit struct {
	app.UnitOfWork
	factory *ssoExchangeFailureFactory
	wrote   bool
	audits  int
}

func (f *ssoExchangeFailureFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	u, err := f.UnitOfWorkFactory.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	return &ssoExchangeFailureUnit{UnitOfWork: u, factory: f}, nil
}
func (u *ssoExchangeFailureUnit) Repositories() app.Repositories {
	r := u.UnitOfWork.Repositories()
	if u.factory.phase != "" {
		r.Identity = ssoExchangeFailureIdentity{IdentityRepository: r.Identity, SSOExchangeReader: r.Identity.(identityapp.SSOExchangeReader), unit: u}
		r.Audit = ssoExchangeFailureAudit{r.Audit, u}
	}
	return r
}
func (u *ssoExchangeFailureUnit) Commit(ctx context.Context) error {
	if u.wrote && u.factory.phase == "commit" {
		u.factory.failures++
		return errSSOExchangeFixture
	}
	return u.UnitOfWork.Commit(ctx)
}

type ssoExchangeFailureIdentity struct {
	app.IdentityRepository
	identityapp.SSOExchangeReader
	unit *ssoExchangeFailureUnit
}

func (r ssoExchangeFailureIdentity) InsertProviderVerification(ctx context.Context, v domain.ProviderVerification) error {
	if err := r.IdentityRepository.InsertProviderVerification(ctx, v); err != nil {
		return err
	}
	r.unit.wrote = true
	if r.unit.factory.phase == "receipt" {
		r.unit.factory.failures++
		return errSSOExchangeFixture
	}
	return nil
}
func (r ssoExchangeFailureIdentity) InsertSSOSession(ctx context.Context, v domain.SSOSession) error {
	if err := r.IdentityRepository.InsertSSOSession(ctx, v); err != nil {
		return err
	}
	r.unit.wrote = true
	if r.unit.factory.phase == "session" {
		r.unit.factory.failures++
		return errSSOExchangeFixture
	}
	return nil
}

type ssoExchangeFailureAudit struct {
	app.AuditRepository
	unit *ssoExchangeFailureUnit
}

func (r ssoExchangeFailureAudit) Append(ctx context.Context, v domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	v, err := r.AuditRepository.Append(ctx, v)
	if err != nil {
		return v, err
	}
	r.unit.audits++
	if r.unit.factory.phase == "verification-audit" && r.unit.audits == 1 || r.unit.factory.phase == "session-audit" && r.unit.audits == 2 {
		r.unit.factory.failures++
		return v, errSSOExchangeFixture
	}
	return v, nil
}

func signedSSOExchangeNativeFixture(t *testing.T, transactions app.UnitOfWorkFactory) (*app.Ledger, ssoProviderFixtureScope, string) {
	t.Helper()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: transactions, Now: peripheralFixtureQueryClock})
	owner := seedProviderVerificationFixture(t, ledger, "Owner")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	commands := ssoProviderFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: providerVerificationFixtureClock()}
	p, err := commands.UpdateSSOProviderTrustMaterial(t.Context(), owner.actor, owner.provider.ID, identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "exchange-fixture", "x": base64.RawURLEncoding.EncodeToString(pub)}}}})
	if err != nil {
		t.Fatal(err)
	}
	owner.provider = domain.SSOProvider(p)
	token := signedRouterIDToken(t, priv, "exchange-fixture", map[string]any{"iss": p.Issuer, "aud": p.ClientID, "sub": "subject-Owner", "email": owner.user.Email, "email_verified": true, "groups": []string{"token-reviewers"}, "exp": peripheralFixtureQueryClock().Add(time.Hour).Unix()})
	return ledger, owner, token
}

func TestSSOExchangeNativeFixtureRollsBackEveryLateFailureWithoutCookieOrReplay(t *testing.T) {
	for _, phase := range []string{"receipt", "verification-audit", "session", "session-audit", "commit"} {
		t.Run(phase, func(t *testing.T) {
			base := app.NewMemoryUnitOfWorkFactory()
			factory := &ssoExchangeFailureFactory{UnitOfWorkFactory: base}
			ledger, owner, token := signedSSOExchangeNativeFixture(t, factory)
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.bindSSOSessionFixtureResources("fixture-pepper", providerVerificationFixtureClock())
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			factory.phase = phase
			body, err := json.Marshal(map[string]any{"provider_id": owner.provider.ID, "subject": "subject-Owner", "id_token": token})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			request := httptest.NewRequest("POST", "/v1/sso/session-exchanges", strings.NewReader(string(body))).WithContext(t.Context())
			server.Handler().ServeHTTP(w, request)
			if w.Code != 500 || factory.failures != 1 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), "private exchange") || strings.Contains(w.Body.String(), `"data"`) {
				t.Fatal("failed real exchange disclosed result or changed cookie", w.Code, w.Body.String())
			}
			after, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("failed exchange committed receipt, session, audit, replay or other effects", err)
			}
		})
	}
}

func TestSSOExchangeNativeFixtureDenialsCommitOnlySafeVerification(t *testing.T) {
	for _, denial := range []string{"bad-signature", "missing-link", "deactivated-user"} {
		t.Run(denial, func(t *testing.T) {
			base := app.NewMemoryUnitOfWorkFactory()
			ledger, owner, token := signedSSOExchangeNativeFixture(t, base)
			in := identityapp.ExchangeSSOCredentialInput{ProviderID: owner.provider.ID, Subject: "subject-Owner", IDToken: token}
			if denial == "bad-signature" {
				in.IDToken = "malformed-token-canary"
			}
			if denial == "missing-link" {
				in.Subject = "unlinked-subject"
			}
			if denial == "deactivated-user" {
				u := owner.user
				at := peripheralFixtureQueryClock()
				u.Status, u.DeactivatedAt = "deactivated", &at
				if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error { return r.Identity.DeactivateHumanUser(ctx, u) }); err != nil {
					t.Fatal(err)
				}
			}
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			commands := ssoSessionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, credentials: fixtureSessionCredentials("fixture-pepper"), clock: providerVerificationFixtureClock()}
			v, session, secret, err := commands.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, app.ErrVerificationFailed) || v.ID == "" || !reflect.DeepEqual(session, identitydomain.SSOSession{}) || secret != "" {
				t.Fatal("denial lost safe receipt or returned session/secret", v, session, err)
			}
			after, err := base.Snapshot()
			if err != nil || len(after.ProviderVerifications) != 1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(after.ProviderVerifications[v.ID], app.ProviderVerificationFromIdentity(v)) {
				t.Fatal("denial did not commit exactly its complete receipt and audit", err)
			}
			if strings.Contains(fmt.Sprint(after), in.IDToken) {
				t.Fatal("denial retained credential")
			}
			after.ProviderVerifications = before.ProviderVerifications
			after.AuditEntries = before.AuditEntries
			if !reflect.DeepEqual(before, after) {
				t.Fatal("denial committed session, replay, links, grants or unrelated state")
			}
		})
	}
}

type ssoExchangeChangingCredentials struct {
	*identityapp.HMACAuthenticationCredentials
	change func()
}

func (c ssoExchangeChangingCredentials) GenerateSession() (identityapp.Credential, error) {
	v, err := c.HMACAuthenticationCredentials.GenerateSession()
	if err == nil {
		c.change()
	}
	return v, err
}

func TestSSOExchangeNativeFixtureRejectsCurrentStateChangesBeforeCommit(t *testing.T) {
	for _, mutation := range []string{"trust", "user", "grants"} {
		t.Run(mutation, func(t *testing.T) {
			base := app.NewMemoryUnitOfWorkFactory()
			ledger, owner, token := signedSSOExchangeNativeFixture(t, base)
			var changed app.MemoryUnitOfWorkSnapshot
			credentials := ssoExchangeChangingCredentials{HMACAuthenticationCredentials: fixtureSessionCredentials("fixture-pepper"), change: func() {
				switch mutation {
				case "trust":
					c := ssoProviderFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: providerVerificationFixtureClock()}
					if _, err := c.UpdateSSOProviderTrustMaterial(t.Context(), owner.actor, owner.provider.ID, identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: publicSSOFixtureJWKS("changed-after-verification")}); err != nil {
						t.Fatal(err)
					}
				case "user":
					u := owner.user
					at := peripheralFixtureQueryClock()
					u.Status, u.DeactivatedAt = "deactivated", &at
					if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error { return r.Identity.DeactivateHumanUser(ctx, u) }); err != nil {
						t.Fatal(err)
					}
				case "grants":
					grantFixtureSessionUser(t, ledger, owner)
				}
				var err error
				changed, err = base.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
			}}
			commands := ssoSessionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, credentials: credentials, clock: providerVerificationFixtureClock()}
			v, session, secret, err := commands.ExchangeSSOCredential(t.Context(), identityapp.ExchangeSSOCredentialInput{ProviderID: owner.provider.ID, Subject: "subject-Owner", IDToken: token})
			if !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, identitydomain.ProviderVerification{}) || !reflect.DeepEqual(session, identitydomain.SSOSession{}) || secret != "" {
				t.Fatal("changed decision snapshot committed or exposed partial result", v, session, err)
			}
			after, err := base.Snapshot()
			if err != nil || changed.Tenants == nil || !reflect.DeepEqual(changed, after) {
				t.Fatal("failed stale exchange changed state beyond the independent mutation", err)
			}
		})
	}
}

func TestSSOExchangeNativeFixtureCommitsSignedLoginAndRepeatsWithoutSecretReplay(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	ledger, owner, token := signedSSOExchangeNativeFixture(t, base)
	commands := ssoSessionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, credentials: fixtureSessionCredentials("fixture-pepper"), clock: providerVerificationFixtureClock()}
	in := identityapp.ExchangeSSOCredentialInput{ProviderID: owner.provider.ID, Subject: "subject-Owner", IDToken: token}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	first, session, secret, err := commands.ExchangeSSOCredential(t.Context(), in)
	if err != nil || first.Result != "passed" || session.Hash != "" || secret == "" || session.ProviderID != owner.provider.ID || session.UserID != owner.user.ID || !session.CreatedAt.Equal(peripheralFixtureQueryClock()) || !session.ExpiresAt.Equal(peripheralFixtureQueryClock().Add(8*time.Hour)) {
		t.Fatal("signed exchange lost complete session or verification result", first, session, err)
	}
	saved, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	stored := saved.SSOSessions[session.ID]
	if stored.Hash != fixtureSessionCredentials("fixture-pepper").Hash(secret) {
		t.Fatal("exchange credential hash does not match issued secret")
	}
	stored.Hash = ""
	if !reflect.DeepEqual(stored, domain.SSOSession(session)) || !reflect.DeepEqual(saved.ProviderVerifications[first.ID], app.ProviderVerificationFromIdentity(first)) || len(saved.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 {
		t.Fatal("exchange DTO differs from persisted metadata or lost atomic audits")
	}
	actor, err := fixtureSessionAuthenticator(ledger, "fixture-pepper", providerVerificationFixtureClock()).Authenticate(t.Context(), secret)
	if err != nil || actor.UserID != owner.user.ID || len(actor.ResourceGrants) != 1 || actor.ResourceGrants[0].Role != "security_engineer" {
		t.Fatal("native exchange secret did not authenticate current group grants", actor, err)
	}
	second, next, nextSecret, err := commands.ExchangeSSOCredential(t.Context(), in)
	if err != nil || second.ID == first.ID || next.ID == session.ID || nextSecret == secret {
		t.Fatal("repeated exchange reused receipt, session or secret", err)
	}
	state, err := base.Snapshot()
	if err != nil || len(state.Idempotency) != 0 || len(state.SSOSessions) != 2 || len(state.ProviderVerifications) != 2 {
		t.Fatal("exchange became an idempotency-replay surface", err)
	}
	for _, sensitive := range []string{token, secret, nextSecret} {
		if strings.Contains(fmt.Sprint(state), sensitive) {
			t.Fatal("exchange state retained a plaintext credential")
		}
	}
}
