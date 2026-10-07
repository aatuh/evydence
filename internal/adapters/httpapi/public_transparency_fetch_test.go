package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type transparencyFetchHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *transparencyFetchHTTPFake) AuthorizeFetchPublicTransparencyLogEntryProof(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}
func (f *transparencyFetchHTTPFake) FetchAndVerifyPublicTransparencyLogEntry(_ context.Context, a identitydomain.Actor, id string) (d.PublicTransparencyLogEntry, error) {
	f.calls++
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	hash := "sha256:" + strings.Repeat("a", 64)
	v, err := e.BuildPublicTransparencyVerification(d.PublicTransparencyLogEntry{ID: id, TenantID: a.TenantID, LogID: "log", CheckpointID: "checkpoint", MerkleBatchID: "batch", ExternalID: "external", EntryHash: hash, State: "published", SchemaVersion: d.PublicTransparencyEntryVersion, CreatedAt: at}, e.PublicTransparencyProofInput{RootHash: hash, TreeSize: 1}, "fetched", at)
	if err != nil {
		return v, err
	}
	return v, f.runErr
}
func TestPublicTransparencyFetchHTTPStrictBodyPrivateErrorsAndCookiePolicy(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	f := &transparencyFetchHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyFetchCommands: f}); err == nil {
		t.Fatal("fetch bypassed durable replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyFetchCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/public-transparency-log-entries/entry/fetch-proof"
	for i, bad := range []string{`null`, `[]`, `{`, `{} {}`, `{"source":"fetched"}`, `{"endpoint":"https://attacker.example.test"}`, `{"leaf_hash":null}`, `{"source":"x","source":"y"}`} {
		before := f.guards + f.calls
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
		if f.guards+f.calls != before {
			t.Fatal("nonempty input reached fetch", bad)
		}
	}
	for i, body := range []string{"", "  ", "{}", " { } "} {
		out := postRaw(t, s, secret, path, fmt.Sprintf("valid-%d", i), []byte(body), 200)
		if !strings.Contains(out, `"state":"inclusion_verified"`) || !strings.Contains(out, "public_log_proof_source") {
			t.Fatal("fetched response changed", out)
		}
	}
	postRaw(t, s, "", path, "unauth", nil, 401)
	for i, tc := range []struct {
		err    error
		status int
	}{{e.ErrValidation, 400}, {e.ErrNotFound, 404}, {e.ErrConflict, 409}, {e.ErrVerificationFailed, 422}, {application.ErrForbidden, 403}, {errors.New("private fetch credentials"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = tc.err
			} else {
				f.runErr = tc.err
			}
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", phase, i), nil, tc.status)
			if strings.Contains(out, "private fetch credentials") || strings.Contains(out, `"inclusion_proof_hash":`) {
				t.Fatal("fetch failure exposed success/private input", out)
			}
		}
	}
	f.guardErr, f.runErr = nil, nil
	for _, bearer := range []bool{false, true} {
		r := httptest.NewRequest("POST", "https://api.example.test"+path, nil)
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
		r.Header.Set("Idempotency-Key", fmt.Sprint(bearer))
		want := 403
		if bearer {
			r.Header.Set("Authorization", "Bearer "+secret)
			want = 200
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal("cookie/bearer fetch policy changed", bearer, w.Code, w.Body.String())
		}
	}
}

func TestPublicTransparencyFetchHTTPLocalReplayDoesNotRefetchOrKeepRevokedAuthority(t *testing.T) {
	f := &fakeTransparencyProofHTTP{}
	l := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", Transparency: f})
	_, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	log, err := l.CreatePublicTransparencyLog(t.Context(), a, app.CreatePublicTransparencyLogInput{Name: "fixture", Endpoint: "https://log.example.test", PublicKey: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.CreateMerkleBatch(t.Context(), a, app.CreateMerkleBatchInput{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := l.CreateTransparencyCheckpoint(t.Context(), a, app.CreateTransparencyCheckpointInput{BatchID: b.ID, Provider: "internal", ExternalID: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := l.PublishPublicTransparencyLogEntry(t.Context(), a, app.PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: cp.ID, ExternalID: "external"})
	if err != nil {
		t.Fatal(err)
	}
	f.result = app.TransparencyProofResult{RootHash: v.EntryHash, TreeSize: 1}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"keys:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), l, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/public-transparency-log-entries/" + v.ID + "/fetch-proof"
	first := postRaw(t, s, secret, path, "replay", nil, 200)
	f.err = errors.New("private provider unavailable")
	if replay := postRaw(t, s, secret, path, "replay", nil, 200); replay != first {
		t.Fatal("local replay refetched/changed proof")
	}
	postRaw(t, s, secret, path, "replay", []byte("{}"), 409)
	auth.actor.ResourceGrants[0].ResourceType, auth.actor.ResourceGrants[0].ResourceID = "product", "product"
	postRaw(t, s, secret, path, "replay", nil, 403)
	postRaw(t, s, secret, path, "new", nil, 403)
}
