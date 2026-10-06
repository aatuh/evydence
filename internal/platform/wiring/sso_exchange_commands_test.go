package wiring

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func seedSSOExchangeWiring(t *testing.T, pool *pgxpool.Pool) identityapp.ExchangeSSOCredentialInput {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "exchange-test", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(public)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
INSERT INTO tenants(id,name)VALUES('tenant','Exchange'),('other','Other');
INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES('user','tenant','person@example.test','User','active','human-user.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,groups_claim,role_mapping,status,schema_version,created_at,jwks)VALUES('provider','tenant','Provider','oidc','https://issuer.example.test','client','groups','{"security":"security_engineer"}','active','sso-provider.v1',now(),'{}');
INSERT INTO user_identity_links(id,tenant_id,user_id,provider_id,subject,email,verified,schema_version,created_at)VALUES('link','tenant','user','provider','subject','person@example.test',true,'user-identity-link.v1',now());
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES('grant','tenant','user','user','release_manager','tenant','tenant','role-binding.v1',now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE sso_providers SET jwks=$1 WHERE id='provider'`, jwks); err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "exchange-test", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{"iss": "https://issuer.example.test", "aud": "client", "sub": "subject", "email": "person@example.test", "email_verified": true, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(), "groups": []string{"security"}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(unsigned)))
	return identityapp.ExchangeSSOCredentialInput{ProviderID: "provider", Subject: "subject", IDToken: token}
}

func exchangeWiringCounts(t *testing.T, pool *pgxpool.Pool) [4]int {
	t.Helper()
	var out [4]int
	if err := pool.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM provider_verifications),(SELECT count(*)FROM sso_sessions),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records)`).Scan(&out[0], &out[1], &out[2], &out[3]); err != nil {
		t.Fatal(err)
	}
	return out
}
func newExchangeWiringServer(t *testing.T, store *postgres.Store) (*httpapi.Server, *decisionHTTPNoReloadStore) {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "exchange-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.SSOExchangeCommands == nil {
		t.Fatal("exchange remains Ledger-backed", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	ledger, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), ledger, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, noReload
}

func TestPostgresSSOExchangeHTTPAuthenticatesWithoutLedgerOrSecretReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	in := seedSSOExchangeWiring(t, pool)
	// The HTTP contract uses snake_case, not the exported application DTO names.
	body, err := json.Marshal(map[string]any{"provider_id": in.ProviderID, "subject": in.Subject, "id_token": in.IDToken})
	if err != nil {
		t.Fatal(err)
	}
	var previous string
	for range 2 {
		s, noReload := newExchangeWiringServer(t, store)
		r := httptest.NewRequest("POST", "/v1/sso/session-exchanges", bytes.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "not-a-secret-replay-surface")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 201 || noReload.loads != 1 || strings.Contains(w.Body.String(), in.IDToken) {
			t.Fatal("exchange failed, reloaded state or leaked provider token", w.Code, noReload.loads)
		}
		var out struct {
			Data struct {
				Verification map[string]any `json:"verification"`
				Session      map[string]any `json:"session"`
				Secret       string         `json:"secret"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Data.Verification["result"] != "passed" || out.Data.Session["tenant_id"] != "tenant" || out.Data.Secret == "" || out.Data.Secret == previous || out.Data.Session["hash"] != nil {
			t.Fatal("exchange public contract or credential freshness lost")
		}
		var profileJSON []byte
		if err := pool.QueryRow(t.Context(), `SELECT assurance_profile FROM provider_verifications WHERE id=$1`, out.Data.Verification["id"]).Scan(&profileJSON); err != nil {
			t.Fatal(err)
		}
		var storedProfile map[string]any
		if err := json.Unmarshal(profileJSON, &storedProfile); err != nil {
			t.Fatal(err)
		}
		if storedProfile["id"] == "" || !reflect.DeepEqual(storedProfile, out.Data.Verification["profile"]) {
			t.Fatal("public/persisted assurance profile mapping changed")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Value != out.Data.Secret || cookies[0].Name != "evydence_session" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Path != "/v1" || cookies[0].SameSite != http.SameSiteStrictMode {
			t.Fatal("exchange cookie contract changed")
		}
		expires, err := time.Parse(time.RFC3339Nano, out.Data.Session["expires_at"].(string))
		if err != nil || !cookies[0].Expires.Equal(expires.Truncate(time.Second)) {
			t.Fatal("cookie and session expiry differ", err)
		}
		authn, err := BuildAuthenticator(store, store, "exchange-test-pepper", false)
		if err != nil {
			t.Fatal(err)
		}
		actor, err := authn.Authenticate(t.Context(), out.Data.Secret)
		if err != nil || actor.TenantID != "tenant" || actor.UserID != "user" || actor.SessionID != out.Data.Session["id"] {
			t.Fatal("issued credential cannot authenticate", err)
		}
		var storedHash string
		if err := pool.QueryRow(t.Context(), `SELECT hash FROM sso_sessions WHERE id=$1`, actor.SessionID).Scan(&storedHash); err != nil || len(storedHash) != 64 || storedHash == out.Data.Secret {
			t.Fatal("session hash format changed", err)
		}
		previous = out.Data.Secret
	}
	if counts := exchangeWiringCounts(t, pool); counts != [4]int{2, 2, 4, 0} {
		t.Fatal("exchange created replay material or partial effects", counts)
	}
}

func TestPostgresSSOExchangeWriteAuditAndDeferredCommitFailuresReturnNoCookie(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	in := seedSSOExchangeWiring(t, pool)
	body, err := json.Marshal(map[string]any{"provider_id": in.ProviderID, "subject": in.Subject, "id_token": in.IDToken})
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"provider_verifications", "sso_sessions", "audit_chain_entries", "commit"} {
		var setup, teardown string
		if stage == "commit" {
			setup = `CREATE OR REPLACE FUNCTION reject_exchange_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private exchange storage';END$$;CREATE CONSTRAINT TRIGGER reject_exchange_stage AFTER INSERT ON sso_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_exchange_stage()`
			teardown = `DROP TRIGGER reject_exchange_stage ON sso_sessions`
		} else {
			setup = `CREATE OR REPLACE FUNCTION reject_exchange_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private exchange storage';END$$;CREATE TRIGGER reject_exchange_stage BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_exchange_stage()`
			teardown = `DROP TRIGGER reject_exchange_stage ON ` + stage
		}
		if _, err := pool.Exec(t.Context(), setup); err != nil {
			t.Fatal(err)
		}
		before := exchangeWiringCounts(t, pool)
		s, noReload := newExchangeWiringServer(t, store)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/sso/session-exchanges", bytes.NewReader(body)).WithContext(t.Context()))
		if w.Code != 500 || w.Header().Get("Set-Cookie") != "" || noReload.loads != 1 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), in.IDToken) || strings.Contains(w.Body.String(), "private exchange storage") || exchangeWiringCounts(t, pool) != before {
			t.Fatal("failed exchange leaked cookie/result or effects", stage, w.Code)
		}
		if _, err := pool.Exec(t.Context(), teardown); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresSSOExchangeReadsAreBoundedOwnedAndFailClosed(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	in := seedSSOExchangeWiring(t, pool)
	reader := ssoExchangeReader{factory: store}
	provider, err := reader.SSOProviderByID(t.Context(), "provider")
	if err != nil || provider.SAMLSigningCertificates != nil {
		t.Fatal("empty trust metadata representation differs from command snapshot", err)
	}
	if _, found, err := reader.IdentityLink(t.Context(), "other", "provider", "subject"); err != nil || found {
		t.Fatal("foreign identity link returned", err)
	}
	if _, err := reader.User(t.Context(), "other", "user"); !errors.Is(err, identityapp.ErrNotFound) {
		t.Fatal("foreign human user returned", err)
	}
	if grants, err := reader.UserGrants(t.Context(), "other", "user"); err != nil || len(grants) != 0 {
		t.Fatal("foreign grants returned", err)
	}
	c, err := BuildSSOExchangeCommands(store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE sso_providers SET name=repeat('x',9437184) WHERE id='provider'`,
		`UPDATE user_identity_links SET email=repeat('x',9437184) WHERE id='link'`,
		`UPDATE human_users SET display_name=repeat('x',9437184) WHERE id='user'`,
		`UPDATE role_bindings SET resource_id=repeat('x',9437184) WHERE id='grant'`,
		`INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,schema_version,created_at)SELECT 'extra-'||n,'tenant','user','user','release_manager','role-binding.v1',now()FROM generate_series(1,256)n`,
	} {
		if _, err := pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		before := exchangeWiringCounts(t, pool)
		v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
		if !errors.Is(err, identityapp.ErrConflict) || v.ID != "" || session.ID != "" || secret != "" || exchangeWiringCounts(t, pool) != before {
			t.Fatal("oversized exchange projection did not fail closed", err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE sso_providers SET name='Provider' WHERE id='provider';UPDATE user_identity_links SET email='person@example.test' WHERE id='link';UPDATE human_users SET display_name='User' WHERE id='user';UPDATE role_bindings SET resource_id='tenant' WHERE id='grant';DELETE FROM role_bindings WHERE id LIKE 'extra-%'`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresSSOExchangeDenialsPersistOnlySafeVerificationAndNoCookie(t *testing.T) {
	for _, scenario := range []string{"bad credential", "missing link", "inactive user", "no grants"} {
		store, pool := openHTMLReportWiringStore(t)
		in := seedSSOExchangeWiring(t, pool)
		want := 422
		var mutation string
		switch scenario {
		case "bad credential":
			in.IDToken = "not-a-valid-token"
		case "missing link":
			mutation = `DELETE FROM user_identity_links WHERE id='link'`
		case "inactive user":
			mutation = `UPDATE human_users SET status='inactive' WHERE id='user'`
		case "no grants":
			mutation = `DELETE FROM role_bindings WHERE id='grant';UPDATE sso_providers SET role_mapping='{}' WHERE id='provider'`
			want = 403
		}
		if mutation != "" {
			if _, err := pool.Exec(t.Context(), mutation); err != nil {
				t.Fatal(err)
			}
		}
		body, err := json.Marshal(map[string]any{"provider_id": in.ProviderID, "subject": in.Subject, "id_token": in.IDToken})
		if err != nil {
			t.Fatal(err)
		}
		s, noReload := newExchangeWiringServer(t, store)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/sso/session-exchanges", bytes.NewReader(body)).WithContext(t.Context()))
		if w.Code != want || w.Header().Get("Set-Cookie") != "" || noReload.loads != 1 || strings.Contains(w.Body.String(), in.IDToken) || exchangeWiringCounts(t, pool) != [4]int{1, 0, 1, 0} {
			t.Fatal("denied exchange issued credentials or lost safe receipt", scenario, w.Code)
		}
		var result string
		var checks []byte
		if err := pool.QueryRow(t.Context(), `SELECT result,checks FROM provider_verifications`).Scan(&result, &checks); err != nil || result == "passed" || bytes.Contains(checks, []byte(in.IDToken)) {
			t.Fatal("failed verification receipt is unsafe", err)
		}
	}
}

type exchangeRaceFactory struct {
	app.UnitOfWorkFactory
	hook func(context.Context) error
}
type exchangeRaceUnit struct {
	app.UnitOfWork
	repos app.Repositories
}

func (u exchangeRaceUnit) Repositories() app.Repositories { return u.repos }

type exchangeRaceIdentity struct {
	app.IdentityRepository
	identityapp.SSOExchangeReader
	factory *exchangeRaceFactory
}

func (r exchangeRaceIdentity) ValidateSSOExchangeState(ctx context.Context, s app.SSOExchangeSnapshot) error {
	if r.factory.hook != nil {
		fn := r.factory.hook
		r.factory.hook = nil
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return r.IdentityRepository.ValidateSSOExchangeState(ctx, s)
}
func (f *exchangeRaceFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	u, err := f.UnitOfWorkFactory.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	r := u.Repositories()
	r.Identity = exchangeRaceIdentity{IdentityRepository: r.Identity, SSOExchangeReader: r.Identity.(identityapp.SSOExchangeReader), factory: f}
	return exchangeRaceUnit{UnitOfWork: u, repos: r}, nil
}
func TestPostgresSSOExchangeRejectsIdentityChangesAfterVerification(t *testing.T) {
	for _, mutation := range []string{`UPDATE sso_providers SET jwks='{}' WHERE id='provider'`, `UPDATE user_identity_links SET verified=false WHERE id='link'`, `UPDATE human_users SET status='inactive' WHERE id='user'`, `DELETE FROM role_bindings WHERE id='grant'`} {
		store, pool := openHTMLReportWiringStore(t)
		in := seedSSOExchangeWiring(t, pool)
		factory := &exchangeRaceFactory{UnitOfWorkFactory: store, hook: func(ctx context.Context) error { _, err := pool.Exec(ctx, mutation); return err }}
		c, err := BuildSSOExchangeCommands(factory, "exchange-test-pepper", false)
		if err != nil {
			t.Fatal(err)
		}
		v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
		if !errors.Is(err, identityapp.ErrConflict) || v.ID != "" || session.ID != "" || secret != "" || exchangeWiringCounts(t, pool) != [4]int{} {
			t.Fatal("changed identity snapshot issued a session", err)
		}
	}
}
