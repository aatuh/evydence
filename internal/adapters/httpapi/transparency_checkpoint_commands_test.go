package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type recordedCheckpointHTTPFake struct {
	calls, guards int
	err, guardErr error
}

func (f *recordedCheckpointHTTPFake) AuthorizeTransparencyCheckpoint(_ context.Context, _ identitydomain.Actor, _ string) error {
	f.guards++
	return f.guardErr
}

func (f *recordedCheckpointHTTPFake) CreateTransparencyCheckpoint(_ context.Context, a identitydomain.Actor, in verificationapp.CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	f.calls++
	return verificationdomain.TransparencyCheckpoint{ID: "durable_checkpoint", TenantID: a.TenantID, BatchID: in.BatchID, Provider: in.Provider, ExternalID: in.ExternalID, ExternalURL: in.ExternalURL, State: "recorded", TimestampHash: "sha256:assertion", SchemaVersion: verificationdomain.TransparencyCheckpointVersion}, f.err
}

func TestRecordedCheckpointHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &recordedCheckpointHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{TransparencyCheckpointCommands: f}); err == nil {
		t.Fatal("focused checkpoint accepted Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{TransparencyCheckpointCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.verification, s.idempotency = nil, nil, nil
	body := `{"batch_id":" batch ","provider":" provider ","external_id":" record "}`
	one := postRaw(t, s, secret, "/v1/transparency-checkpoints", "native", []byte(body), 201)
	if dataField(t, one, "batch_id") != "batch" || dataField(t, one, "provider") != "provider" || dataField(t, one, "external_id") != "record" || dataField(t, one, "state") != "recorded" {
		t.Fatal("checkpoint normalization or assurance changed", one)
	}
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/transparency-checkpoints", "native", []byte(body), 201))
	postRaw(t, s, secret, "/v1/transparency-checkpoints", "native", []byte(body+" "), 409)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("replay recreated checkpoint or skipped current guard", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private-checkpoint SQL password=secret"), 500}} {
		f.guardErr = tc.err
		before := f.calls
		out := postRaw(t, s, secret, "/v1/transparency-checkpoints", fmt.Sprintf("denied-%d", i), []byte(body), tc.status)
		if f.calls != before || strings.Contains(out, "private-checkpoint") || strings.Contains(out, `"data"`) {
			t.Fatal("checkpoint guard failed open or leaked", out)
		}
	}
}

func TestRecordedCheckpointHTTPStrictInputBeforeGuardInBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &recordedCheckpointHTTPFake{}
		if native {
			s.transparencyCheckpointCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{`null`, `[]`, `{} {}`, `{}`, `{"batch_id":"batch","provider":"provider"}`, `{"BATCH_ID":"batch","provider":"provider","external_id":"record"}`, `{"batch_id":"batch","PROVIDER":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":"record","EXTERNAL_ID":"other"}`, `{"batch_id":null,"provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":null}`, `{"batch_id":"batch","provider":"provider","external_url":null,"external_id":"record"}`, `{"batch_id":"batch","batch_id":"batch","provider":"provider","external_id":"record"}`, `{"batch_id":1,"provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":"record","extra":true}`, `{"batch_id":"` + strings.Repeat(" ", 1024) + `b","provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":"bad\u0000id"}`, `{"batch_id":"batch","provider":"provider","external_id":"` + string([]byte{255}) + `"}`, strings.Repeat(" ", 65537)} {
			postRaw(t, s, secret, "/v1/transparency-checkpoints", fmt.Sprintf("invalid-%d", i), []byte(body), 400)
		}
		if f.calls+f.guards != 0 {
			t.Fatal("invalid input reached checkpoint execution", f)
		}
	}
}

func TestRecordedCheckpointHTTPCookieProtectionInBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		base, secret := testServer(t)
		f := &recordedCheckpointHTTPFake{}
		batchID := "batch"
		if native {
			base.transparencyCheckpointCommands = f
			base.durableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		} else {
			batchID = dataField(t, postJSON(t, base, secret, "/v1/merkle-batches", "cookie-source", map[string]any{}, 201), "id")
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://api.example/v1/transparency-checkpoints", strings.NewReader(fmt.Sprintf(`{"batch_id":%q,"provider":"provider","external_id":"record"}`, batchID)))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.calls + f.guards
			base.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" || tc.status == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe checkpoint cookie mutation", native, w.Code, w.Body.String())
			}
		}
	}
}

func TestRecordedCheckpointHTTPLocalReplayRechecksCurrentTenantGrant(t *testing.T) {
	base, secret := testServer(t)
	batchID := dataField(t, postJSON(t, base, secret, "/v1/merkle-batches", "source", map[string]any{}, 201), "id")
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"keys:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"batch_id": batchID, "provider": "provider", "external_id": "record"}
	one := postJSON(t, s, secret, "/v1/transparency-checkpoints", "local", body, 201)
	assertTrustHTTPReplay(t, one, postJSON(t, s, secret, "/v1/transparency-checkpoints", "local", body, 201))
	auth.actor.ResourceGrants = nil
	postJSON(t, s, secret, "/v1/transparency-checkpoints", "local", body, 403)
}
func TestRecordedTransparencyCheckpointHTTPUsesFocusedCommandAndSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &recordedCheckpointHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{TransparencyCheckpointCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.verification = nil
	body := map[string]any{"batch_id": "batch", "provider": "provider", "external_id": "record"}
	first := postJSON(t, s, secret, "/v1/transparency-checkpoints", "focused-checkpoint", body, http.StatusCreated)
	if !strings.Contains(first, `"id":"durable_checkpoint"`) || !strings.Contains(first, `"state":"recorded"`) || strings.Contains(first, `"state":"passed"`) || f.calls != 1 {
		t.Fatal(first, f)
	}
	assertTrustHTTPReplay(t, first, postJSON(t, s, secret, "/v1/transparency-checkpoints", "focused-checkpoint", body, http.StatusCreated))
	if f.calls != 1 {
		t.Fatal("duplicate checkpoint", f)
	}
	for i, bad := range []string{`null`, `[]`, `{"batch_id":null,"provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":null,"external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":null}`, `{"batch_id":"batch","provider":"provider","external_url":null,"external_id":"record"}`, `{"batch_id":1,"provider":"provider","external_id":"record"}`, `{"batch_id":"a","batch_id":"b","provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":"record","extra":1}`, `{"batch_id":"batch","provider":"provider","external_id":"record"} {}`} {
		postRaw(t, s, secret, "/v1/transparency-checkpoints", fmt.Sprintf("bad-checkpoint-%d", i), []byte(bad), http.StatusBadRequest)
	}
	if f.calls != 1 {
		t.Fatal("malformed checkpoint reached command", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrForbidden, 403}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {errors.New("private SQL checkpoint root"), 500}} {
		f.err = tc.err
		before := f.calls
		response := postJSON(t, s, secret, "/v1/transparency-checkpoints", fmt.Sprintf("failed-checkpoint-%d", i), body, tc.status)
		if f.calls != before+1 || strings.Contains(response, "private SQL") || strings.Contains(response, "durable_checkpoint") {
			t.Fatal(response, f)
		}
	}
}
