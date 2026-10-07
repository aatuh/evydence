package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

type failingSSOSessionFixture struct {
	ssoSessionFixtureCommands
	changedID, secret string
	isolated          bool
}

func (f *failingSSOSessionFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private session fixture failure after write")
}
func (f *failingSSOSessionFixture) CreateSSOSession(ctx context.Context, a domain.Actor, in identityapp.CreateSSOSessionInput) (identitydomain.SSOSession, string, error) {
	v, secret, err := f.ssoSessionFixtureCommands.CreateSSOSession(ctx, a, in)
	f.secret = secret
	return v, secret, f.fail(ctx, v.ID, err)
}
func (f *failingSSOSessionFixture) RevokeSSOSession(ctx context.Context, a domain.Actor, id string) (identitydomain.SSOSession, error) {
	v, err := f.ssoSessionFixtureCommands.RevokeSSOSession(ctx, a, id)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingSSOSessionFixture) RevokeCurrentSSOSession(ctx context.Context, a domain.Actor) (identitydomain.SSOSession, error) {
	v, err := f.ssoSessionFixtureCommands.RevokeCurrentSSOSession(ctx, a)
	return v, f.fail(ctx, v.ID, err)
}

func fixtureSessionPost(t *testing.T, s *Server, secret, path, key, body string, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer "+secret)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatal("session HTTP status", w.Code, want, w.Body.String())
	}
	return w
}
func seedFixtureSession(t *testing.T, l *app.Ledger, f ssoProviderFixtureScope) (domain.SSOSession, string) {
	t.Helper()
	grantFixtureSessionUser(t, l, f)
	v, secret, err := l.CreateSSOSession(t.Context(), f.actor, app.CreateSSOSessionInput{UserID: f.user.ID, ProviderID: f.provider.ID, ExpiresAt: time.Date(2026, 10, 8, 16, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return v, secret
}

func grantFixtureSessionUser(t *testing.T, l *app.Ledger, f ssoProviderFixtureScope) {
	t.Helper()
	if _, err := l.CreateRoleBinding(t.Context(), f.actor, app.CreateRoleBindingInput{SubjectType: "user", SubjectID: f.user.ID, Role: "release_manager", ResourceType: "tenant", ResourceID: f.actor.TenantID}); err != nil {
		t.Fatal(err)
	}
}

func TestSSOSessionFixturesRollbackSecretsLifecycleAuditsAndCookies(t *testing.T) {
	for _, action := range []string{"issue", "revoke", "logout"} {
		t.Run(action, func(t *testing.T) {
			ledger, factory, _ := ssoFixtureLedger()
			owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
			session, secret := seedFixtureSession(t, ledger, owner)
			actor := owner.actor
			path, body := "/v1/sso/sessions", fmt.Sprintf(`{"user_id":%q,"provider_id":%q,"expires_at":"2026-10-08T16:00:00Z"}`, owner.user.ID, owner.provider.ID)
			if action == "revoke" {
				path, body = "/v1/sso/sessions/"+session.ID+"/revoke", `{}`
			}
			if action == "logout" {
				path, body = "/v1/sso/logout", `{}`
				actor = domain.Actor{TenantID: owner.actor.TenantID, UserID: owner.user.ID, SessionID: session.ID}
			}
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			s.authn = &configuredAuthenticator{actor: actor}
			commands := &failingSSOSessionFixture{ssoSessionFixtureCommands: ssoSessionFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			s.ssoSessionCommands, s.ssoSessionRevocationCommands = commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			w := fixtureSessionPost(t, s, "fixture-auth", path, "failed-session", body, 500)
			if commands.changedID == "" || !commands.isolated || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "private session") || strings.Contains(w.Body.String(), `"data"`) || commands.secret != "" && strings.Contains(w.Body.String(), commands.secret) {
				t.Fatal("failed session write leaked metadata/secret, bypassed isolation or changed cookie")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed session write lost failure receipt")
			}
			for _, r := range after.Idempotency {
				if r.State != app.IdempotencyFailed || r.Response != nil || r.Status != 0 {
					t.Fatal("failure receipt exposed partial session")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed session write changed session, revocation, audit, credential or job state")
			}
			if _, err := ledger.Authenticate(t.Context(), secret); err != nil {
				t.Fatal("failed command invalidated existing session", err)
			}
			if commands.secret != "" {
				if _, err := ledger.Authenticate(t.Context(), commands.secret); !errors.Is(err, app.ErrUnauthorized) {
					t.Fatal("failed issuance produced usable credential", err)
				}
			}
		})
	}
}

func TestSSOSessionIssuanceFixtureReplaysMetadataWithoutReissuingSecret(t *testing.T) {
	ledger, factory, _ := ssoFixtureLedger()
	owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
	foreign := seedSSOProviderFixtureScope(t, ledger, "Foreign")
	grantFixtureSessionUser(t, ledger, owner)
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := owner.actor
	human.KeyID, human.UserID = "", owner.user.ID
	human.Scopes = []string{"identity:admin"}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"identity:admin"}}}
	auth := &configuredAuthenticator{actor: human}
	s.authn = auth
	body := fmt.Sprintf(`{"user_id":%q,"provider_id":%q,"expires_at":"2026-10-08T16:00:00Z"}`, owner.user.ID, owner.provider.ID)
	first := fixtureSessionPost(t, s, "fixture-auth", "/v1/sso/sessions", "same-session", body, 201)
	secret := nestedDataField(t, first.Body.String(), "secret")
	id := dataFieldFromNestedObject(t, first.Body.String(), "session", "id")
	saved, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	session := saved.SSOSessions[id]
	if session.Hash == "" {
		t.Fatal("issued session was not durably hashed")
	}
	session.Hash = ""
	want, err := json.Marshal(map[string]any{"data": map[string]any{"session": session, "secret": secret}, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), first.Body.String())
	if first.Header().Get("Set-Cookie") != "" {
		t.Fatal("administrative issuance unexpectedly set browser cookie")
	}
	if actor, err := ledger.Authenticate(t.Context(), secret); err != nil || actor.UserID != owner.user.ID {
		t.Fatal("fresh session credential is not usable", err)
	}
	replay := fixtureSessionPost(t, s, "fixture-auth", "/v1/sso/sessions", "same-session", body, 201)
	want, err = json.Marshal(map[string]any{"data": map[string]any{"session": session}, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), replay.Body.String())
	// The full snapshot contains a structured-key idempotency map, so use
	// Go's complete representation rather than an unsupported JSON encoding.
	if strings.Contains(fmt.Sprintf("%#v", saved), secret) {
		t.Fatal("session plaintext secret was persisted in state/receipt")
	}
	postRaw(t, s, "fixture-auth", "/v1/sso/sessions", "same-session", append([]byte(body), ' '), 409)
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"identity:admin"}}}} {
		auth.actor.ResourceGrants = grants
		postRaw(t, s, "fixture-auth", "/v1/sso/sessions", "same-session", []byte(body), 403)
		postRaw(t, s, "fixture-auth", "/v1/sso/sessions", "new-session", []byte(body), 403)
	}
	auth.actor = human
	for label, bad := range map[string]string{"user": strings.ReplaceAll(body, owner.user.ID, foreign.user.ID), "provider": strings.ReplaceAll(body, owner.provider.ID, foreign.provider.ID)} {
		postRaw(t, s, "fixture-auth", "/v1/sso/sessions", "foreign-session-"+label, []byte(bad), 404)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(saved, after) {
		t.Fatal("issuance replay/conflict/revocation/foreign preflight changed session or receipt state", err)
	}
}

func TestSSOSessionRevocationFixtureReplaysPublicMetadataAndLogoutInvalidatesAccess(t *testing.T) {
	for _, self := range []bool{false, true} {
		t.Run(fmt.Sprint("self-", self), func(t *testing.T) {
			ledger, factory, _ := ssoFixtureLedger()
			owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
			foreign := seedSSOProviderFixtureScope(t, ledger, "Foreign")
			session, secret := seedFixtureSession(t, ledger, owner)
			other, _ := seedFixtureSession(t, ledger, foreign)
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			actor := owner.actor
			path := "/v1/sso/sessions/" + session.ID + "/revoke"
			if self {
				actor = domain.Actor{TenantID: owner.actor.TenantID, UserID: owner.user.ID, SessionID: session.ID}
				path = "/v1/sso/logout"
			}
			auth := &configuredAuthenticator{actor: actor}
			s.authn = auth
			first := fixtureSessionPost(t, s, "fixture-auth", path, "same-revoke", `{}`, 200)
			saved, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			wantSession := saved.SSOSessions[session.ID]
			wantSession.Hash = ""
			want, err := json.Marshal(map[string]any{"data": wantSession, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), first.Body.String())
			if self {
				cookies := first.Result().Cookies()
				if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
					t.Fatal("committed logout did not safely clear cookie")
				}
			} else if first.Header().Get("Set-Cookie") != "" {
				t.Fatal("administrative revocation changed cookie")
			}
			if _, err := ledger.Authenticate(t.Context(), secret); !errors.Is(err, app.ErrUnauthorized) {
				t.Fatal("committed revocation left old credential usable", err)
			}
			// The configured actor isolates receipt authorization from transport
			// authentication; actual old-credential HTTP authentication below is 401.
			replay := fixtureSessionPost(t, s, "fixture-auth", path, "same-revoke", `{}`, 200)
			assertTrustHTTPReplay(t, first.Body.String(), replay.Body.String())
			postRaw(t, s, "fixture-auth", path, "same-revoke", []byte("{ }"), 409)
			if self {
				auth.actor.SessionID = other.ID
				postRaw(t, s, "fixture-auth", path, "foreign-revoke", []byte(`{}`), 404)
				auth.actor = actor
				auth.actor.KeyID = owner.actor.KeyID
				postRaw(t, s, "fixture-auth", path, "key-logout", []byte(`{}`), 403)
			} else {
				auth.actor.Scopes = nil
				postRaw(t, s, "fixture-auth", path, "same-revoke", []byte(`{}`), 403)
				auth.actor = actor
				postRaw(t, s, "fixture-auth", "/v1/sso/sessions/"+other.ID+"/revoke", "foreign-revoke", []byte(`{}`), 404)
			}
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(saved, after) {
				t.Fatal("revocation replay/conflict/denial changed stored state", err)
			}
			s.authn = ledger
			failed := fixtureSessionPost(t, s, secret, path, "same-revoke", `{}`, 401)
			if failed.Header().Get("Set-Cookie") != "" {
				t.Fatal("unauthenticated retry changed cookie")
			}
		})
	}
}

func TestSSOSessionFixtureGuardsArePureCancellableAndKeepExplicitPorts(t *testing.T) {
	ledger, factory, _ := ssoFixtureLedger()
	owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
	session, _ := seedFixtureSession(t, ledger, owner)
	f := ssoSessionFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	self := domain.Actor{TenantID: owner.actor.TenantID, UserID: owner.user.ID, SessionID: session.ID}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{func(ctx context.Context) error {
		return f.AuthorizeCreateSSOSession(ctx, owner.actor, identityapp.CreateSSOSessionInput{UserID: owner.user.ID, ProviderID: owner.provider.ID, ExpiresAt: session.ExpiresAt})
	}, func(ctx context.Context) error { return f.AuthorizeRevokeSSOSession(ctx, owner.actor, session.ID) }, func(ctx context.Context) error { return f.AuthorizeRevokeCurrentSSOSession(ctx, self) }} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("focused session guard rejected owned subject", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("session guard ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("session preflight wrote state", err)
	}
	issue, revoke, exchange := &sessionHTTPFake{}, &sessionRevocationHTTPFake{}, &exchangeTransportStub{}
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{SSOSessionCommands: issue, SSOSessionRevocationCommands: revoke, SSOExchangeCommands: exchange, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if s.ssoSessionCommands != issue || s.ssoSessionRevocationCommands != revoke || s.ssoExchangeCommands != exchange {
		t.Fatal("fixture binder replaced explicit session ports")
	}
}

func TestSSOExchangeFixtureMappingPreservesCompleteDetachedVerification(t *testing.T) {
	v := domain.ProviderVerification{ID: "receipt", TenantID: "tenant", ProviderType: "oidc", ProviderID: "provider", Subject: "subject", Result: "passed", Checks: []domain.VerifyCheck{{Name: "signature", Result: "passed", Detail: "public check"}}, Profile: domain.VerificationProfile{ID: "profile", Version: "v1", RequiredChecks: []string{"signature"}, TrustMaterial: []string{"public-root"}, IdentityPolicy: "identity-policy", TransparencyProof: "not-required", PayloadScope: "identity", PayloadDigest: "sha256:public", Limitations: []string{"profile-limit"}}, Limitations: []string{"receipt-limit"}, SchemaVersion: "verification.v1", CreatedAt: time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)}
	projected := ssoFixtureVerificationModel(v)
	if got := app.ProviderVerificationFromIdentity(projected); !reflect.DeepEqual(got, v) {
		t.Fatal("exchange fixture dropped a verification or assurance field", got)
	}
	projected.Checks[0].Detail = "modified"
	projected.Profile.RequiredChecks[0] = "modified"
	projected.Profile.TrustMaterial[0] = "modified"
	projected.Profile.Limitations[0] = "modified"
	projected.Limitations[0] = "modified"
	if v.Checks[0].Detail != "public check" || v.Profile.RequiredChecks[0] != "signature" || v.Profile.TrustMaterial[0] != "public-root" || v.Profile.Limitations[0] != "profile-limit" || v.Limitations[0] != "receipt-limit" {
		t.Fatal("exchange fixture verification mapping shares metadata")
	}
}
