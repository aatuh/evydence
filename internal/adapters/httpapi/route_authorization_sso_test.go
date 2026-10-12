package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func newNativeSSOAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory, discovery := ssoFixtureLedger()
	owner, foreign := seedSSOProviderFixtureScope(t, ledger, "Owner"), seedSSOProviderFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product}, operationsFixtureScope{actor: foreign.actor, product: foreign.product})
	f.sso = owner
	f.session, f.sessionSecret = seedFixtureSession(t, ledger, owner)
	f.server.bindSSOSessionFixtureResources("fixture-pepper", providerVerificationFixtureClock())
	// Discovery is an explicit external-I/O fake. Application authorization,
	// credential issuance, current grants, repositories and transactions stay
	// native; this scenario does not establish provider truth or real discovery.
	f.server.bindSSOProviderFixtureResources(discovery, providerVerificationFixtureClock())
	return f
}

func addNativeSSOAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation      string
		index, foreign int
	}{
		{"createSSOProvider", 0, 0}, {"updateSSOProviderTrustMaterial", 1, 404}, {"refreshSSOProviderOIDCTrustMaterial", 2, 404}, {"linkSSOIdentity", 3, 404},
	} {
		status := 201
		if tc.index == 1 || tc.index == 2 {
			status = 200
		}
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeSSOAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := ssoProviderFixtureRequests(f.sso)[tc.index]
			return r.path, []byte(r.body)
		}, status, tc.foreign)
	}
	cases["createSSOSession"] = nativeMutationAuthorizationFixtureCase("createSSOSession", newNativeSSOAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/sso/sessions", []byte(fmt.Sprintf(`{"user_id":%q,"provider_id":%q,"expires_at":"2026-10-08T16:00:00Z"}`, f.sso.user.ID, f.sso.provider.ID))
	}, nativeMutationExpectation{status: 201, foreignStatus: 404, resultField: "session", auditDelta: 1})
	cases["revokeSSOSession"] = nativeWriteAuthorizationFixtureCase("revokeSSOSession", newNativeSSOAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/sso/sessions/" + f.session.ID + "/revoke", []byte(`{}`)
	}, 200, 404)
	cases["logoutSSOSession"] = func(t *testing.T) {
		f := newNativeSSOAuthorizationFixture(t)
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		own := domain.Actor{TenantID: f.owner.actor.TenantID, UserID: f.sso.user.ID, SessionID: f.session.ID}
		for _, tc := range []struct {
			actor  domain.Actor
			status int
		}{
			{f.owner.actor, 403}, // administrative API capability is not a self-session
			{domain.Actor{TenantID: f.owner.actor.TenantID, UserID: f.sso.user.ID}, 403},
			{domain.Actor{TenantID: f.owner.actor.TenantID, UserID: "another-user", SessionID: f.session.ID}, 404},
			{domain.Actor{TenantID: f.foreign.actor.TenantID, UserID: f.sso.user.ID, SessionID: f.session.ID}, 404},
		} {
			out := f.request(t, "logoutSSOSession", http.MethodPost, "/v1/sso/logout", tc.actor, []byte(`{}`), tc.status)
			if strings.Contains(out.Body.String(), `"data"`) || out.Header().Get("Set-Cookie") != "" {
				t.Fatal("non-owner logout returned data or changed the cookie")
			}
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("non-owner logout changed session or audit state", err)
			}
		}
		out := f.request(t, "logoutSSOSession", http.MethodPost, "/v1/sso/logout", own, []byte(`{}`), 200)
		after, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		session := after.SSOSessions[f.session.ID]
		if session.RevokedAt == nil || session.TenantID != own.TenantID || session.UserID != own.UserID || session.Hash != before.SSOSessions[own.SessionID].Hash || len(after.AuditEntries[own.TenantID]) != len(before.AuditEntries[own.TenantID])+1 || !strings.Contains(out.Header().Get("Set-Cookie"), "Max-Age=0") {
			t.Fatal("self logout did not revoke and audit its current session and clear the cookie")
		}
		entry := after.AuditEntries[own.TenantID][len(after.AuditEntries[own.TenantID])-1]
		if entry.ActorID != own.UserID || entry.SubjectID != own.SessionID {
			t.Fatal("self logout audit lost its principal/session binding")
		}
		cookies := out.Result().Cookies()
		if dataField(t, out.Body.String(), "id") != own.SessionID || len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/v1" || strings.Contains(out.Body.String(), f.sessionSecret) || strings.Contains(out.Body.String(), session.Hash) {
			t.Fatal("self logout returned a wrong session, private credential, or unsafe cookie")
		}
		if _, err := fixtureSessionAuthenticator(f.ledger, "fixture-pepper", providerVerificationFixtureClock()).Authenticate(t.Context(), f.sessionSecret); !errors.Is(err, app.ErrUnauthorized) {
			t.Fatal("logout left its old native credential usable", err)
		}
		if len(after.Idempotency) != len(before.Idempotency)+1 {
			t.Fatal("self logout lost its exact replay receipt")
		}
		for key, receipt := range after.Idempotency {
			if _, existed := before.Idempotency[key]; existed {
				continue
			}
			if key.TenantID != own.TenantID || key.Method != http.MethodPost || key.Path != "/v1/sso/logout" || receipt.State != app.IdempotencyCompleted || receipt.Status != 200 || receipt.Response == nil {
				t.Fatal("logout receipt lost owned completion/status")
			}
			delete(after.Idempotency, key)
		}
		after.SSOSessions[own.SessionID] = before.SSOSessions[own.SessionID]
		after.AuditEntries[own.TenantID] = before.AuditEntries[own.TenantID]
		if !reflect.DeepEqual(before, after) {
			t.Fatal("self logout changed unrelated repository state")
		}
	}
}
