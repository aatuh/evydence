package wiring

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSessionReplacementKeepsHistoryAndInvalidatesOldCredential(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedSSOExchangeWiring(t, pool)
	options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "rotation-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "fixture-operator", Scopes: []string{"admin"}}
	input := identityapp.CreateSSOSessionInput{UserID: "user", ProviderID: "provider", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	old, oldSecret, err := options.SSOSessionCommands.CreateSSOSession(t.Context(), actor, input)
	if err != nil {
		t.Fatal(err)
	}
	fresh, freshSecret, err := options.SSOSessionCommands.CreateSSOSession(t.Context(), actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if old.ID == fresh.ID || oldSecret == freshSecret || old.Hash != "" || fresh.Hash != "" {
		t.Fatal("replacement reused credential material or exposed hashes")
	}
	for _, secret := range []string{oldSecret, freshSecret} {
		if principal, err := options.Authenticator.Authenticate(t.Context(), secret); err != nil || principal.UserID != "user" {
			t.Fatal("issued session was not usable", err)
		}
	}
	var beforeUsed time.Time
	var beforeHash string
	if err := pool.QueryRow(t.Context(), `SELECT last_used_at,hash FROM sso_sessions WHERE id=$1`, old.ID).Scan(&beforeUsed, &beforeHash); err != nil {
		t.Fatal(err)
	}
	revoked, err := options.SSOSessionRevocationCommands.RevokeSSOSession(t.Context(), actor, old.ID)
	if err != nil || revoked.RevokedAt == nil || revoked.Hash != "" {
		t.Fatal("replacement revocation failed", err)
	}
	if principal, err := options.Authenticator.Authenticate(t.Context(), oldSecret); !errors.Is(err, identityapp.ErrUnauthorized) || principal.UserID != "" {
		t.Fatal("old credential remained usable", err)
	}
	if principal, err := options.Authenticator.Authenticate(t.Context(), freshSecret); err != nil || principal.SessionID != fresh.ID {
		t.Fatal("replacement credential was invalidated", err)
	}
	var used, created, expiry time.Time
	var hash string
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT last_used_at,created_at,expires_at,hash,(SELECT count(*) FROM sso_sessions) FROM sso_sessions WHERE id=$1`, old.ID).Scan(&used, &created, &expiry, &hash, &count); err != nil {
		t.Fatal(err)
	}
	if count != 2 || !used.Equal(beforeUsed) || !created.Equal(old.CreatedAt) || !expiry.Equal(old.ExpiresAt) || hash != beforeHash {
		t.Fatal("rotation rewrote session history or lost committed use")
	}
}

func TestPostgresSessionLifecycleHTTPRejectsInactiveCookieAndBearerCredentials(t *testing.T) {
	for _, profile := range []string{"active", "expired", "idle", "revoked", "inactive user", "inactive provider", "over lifetime"} {
		for _, transport := range []string{"cookie", "bearer"} {
			t.Run(profile+"/"+transport, func(t *testing.T) {
				store, pool := openHTMLReportWiringStore(t)
				seedSSOExchangeWiring(t, pool)
				if _, err := pool.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin' WHERE id='grant'`); err != nil {
					t.Fatal(err)
				}
				policy := identitydomain.SessionPolicy{MaximumLifetime: time.Hour, IdleTimeout: 5 * time.Minute}
				options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, SessionPolicy: policy}, "lifecycle-http-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
				if err != nil {
					t.Fatal(err)
				}
				actor := identitydomain.Actor{TenantID: "tenant", KeyID: "fixture-operator", Scopes: []string{"admin"}}
				session, secret, err := options.SSOSessionCommands.CreateSSOSession(t.Context(), actor, identityapp.CreateSSOSessionInput{UserID: "user", ProviderID: "provider", ExpiresAt: time.Now().UTC().Add(time.Hour)})
				if err != nil || session.MaximumLifetimeSeconds != 3600 || session.IdleTimeoutSeconds != 300 || session.LastUsedAt == nil || session.Hash != "" {
					t.Fatal("runtime lifecycle policy was not applied", err)
				}
				statement := ""
				switch profile {
				case "expired":
					statement = `UPDATE sso_sessions SET expires_at=now()-interval '1 second' WHERE id=$1`
				case "idle":
					statement = `UPDATE sso_sessions SET created_at=now()-interval '10 minutes',last_used_at=NULL,expires_at=now()+interval '30 minutes' WHERE id=$1`
				case "revoked":
					statement = `UPDATE sso_sessions SET revoked_at=now() WHERE id=$1`
				case "inactive user":
					statement = `UPDATE human_users SET status='deactivated' WHERE id=(SELECT user_id FROM sso_sessions WHERE id=$1)`
				case "inactive provider":
					statement = `UPDATE sso_providers SET status='inactive' WHERE id=(SELECT provider_id FROM sso_sessions WHERE id=$1)`
				case "over lifetime":
					statement = `UPDATE sso_sessions SET expires_at=created_at+interval '61 minutes' WHERE id=$1`
				}
				if statement != "" {
					if _, err := pool.Exec(t.Context(), statement, session.ID); err != nil {
						t.Fatal(err)
					}
				}
				var before sql.NullTime
				if err := pool.QueryRow(t.Context(), `SELECT last_used_at FROM sso_sessions WHERE id=$1`, session.ID).Scan(&before); err != nil {
					t.Fatal(err)
				}
				noReload := newAggregateLoadCanary(t, t.Context(), store)
				server, err := newNativeHTTPFixture(t.Context(), options)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest("GET", "/v1/role-bindings", nil)
				if transport == "cookie" {
					request.AddCookie(&http.Cookie{Name: "evydence_session", Value: secret})
				} else {
					request.Header.Set("Authorization", "Bearer "+secret)
				}
				response := httptest.NewRecorder()
				server.Handler().ServeHTTP(response, request)
				want := http.StatusUnauthorized
				if profile == "active" {
					want = http.StatusOK
				}
				if response.Code != want || strings.Contains(response.Body.String(), secret) || !noReload.Intact(t.Context()) {
					t.Fatalf("lifecycle response=%d want=%d; aggregate canary=%t", response.Code, want, noReload.Intact(t.Context()))
				}
				if transport == "cookie" && profile != "active" {
					cookies := response.Result().Cookies()
					if len(cookies) != 1 || cookies[0].Name != "evydence_session" || cookies[0].MaxAge != -1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/v1" {
						t.Fatal("inactive cookie was not cleared safely")
					}
				}
				var after sql.NullTime
				if err := pool.QueryRow(t.Context(), `SELECT last_used_at FROM sso_sessions WHERE id=$1`, session.ID).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if profile != "active" && (before.Valid != after.Valid || before.Valid && !before.Time.Equal(after.Time)) {
					t.Fatal("denied authentication refreshed activity")
				}
			})
		}
	}
}
