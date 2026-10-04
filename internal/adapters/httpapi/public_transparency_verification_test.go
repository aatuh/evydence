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

type transparencyVerificationHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *transparencyVerificationHTTPFake) AuthorizeVerifyPublicTransparencyLogEntry(context.Context, identitydomain.Actor, string, e.PublicTransparencyProofInput) error {
	f.guards++
	return f.guardErr
}
func (f *transparencyVerificationHTTPFake) VerifyPublicTransparencyLogEntry(_ context.Context, a identitydomain.Actor, id string, in e.PublicTransparencyProofInput) (d.PublicTransparencyLogEntry, error) {
	f.calls++
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	v, err := e.BuildPublicTransparencyVerification(d.PublicTransparencyLogEntry{ID: id, TenantID: a.TenantID, LogID: "log", CheckpointID: "checkpoint", MerkleBatchID: "batch", ExternalID: "external", EntryHash: "sha256:" + strings.Repeat("a", 64), State: "published", SchemaVersion: d.PublicTransparencyEntryVersion, CreatedAt: at}, in, "", at)
	if err != nil {
		return v, err
	}
	return v, f.runErr
}
func TestPublicTransparencyVerificationHTTPFocusedInputAndPrivateFailures(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	f := &transparencyVerificationHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyProofCommands: f}); err == nil {
		t.Fatal("proof command bypassed durable replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyProofCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/public-transparency-log-entries/entry/verify"
	body := `{"root_hash":"sha256:` + strings.Repeat("a", 64) + `","leaf_index":0,"tree_size":1,"inclusion_proof":[]}`
	for i, bad := range []string{
		"null", "[]", "{}", body + " {}",
		strings.Replace(body, `"root_hash"`, `"Root_Hash"`, 1),
		strings.TrimSuffix(body, "}") + `,"source":"fetched"}`,
		strings.TrimSuffix(body, "}") + `,"leaf_index":0}`,
		strings.Replace(body, `"leaf_index":0`, `"leaf_index":null`, 1),
		strings.Replace(body, `"leaf_index":0,`, "", 1),
		strings.Replace(body, `"inclusion_proof":[]`, `"inclusion_proof":null`, 1),
		strings.Replace(body, `"inclusion_proof":[]`, `"inclusion_proof":[null]`, 1),
		strings.Replace(body, `"inclusion_proof":[]`, `"inclusion_proof":["sha256:bad"]`, 1),
		strings.Replace(body, `"leaf_index":0`, `"leaf_index":-1`, 1),
		strings.Replace(body, `"tree_size":1`, `"tree_size":9223372036854775808`, 1),
		strings.Replace(body, `sha256:`, `sha256:\u0000`, 1),
	} {
		before := f.calls + f.guards
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
		if f.calls+f.guards != before {
			t.Fatal("malformed proof reached service", bad)
		}
	}
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	failed := postRaw(t, s, secret, path, "invalid-proof", []byte(strings.Replace(body, `"tree_size":1`, `"tree_size":2`, 1)), 200)
	if !strings.Contains(failed, `"state":"inclusion_not_verified"`) {
		t.Fatal("incorrect proof did not preserve failed-assessment contract", failed)
	}
	out := postRaw(t, s, secret, path, "valid", []byte(body), 200)
	if !strings.Contains(out, `"state":"inclusion_verified"`) || !strings.Contains(out, `"inclusion_proof_hash":`) || strings.Contains(out, "InclusionProofHash") {
		t.Fatal("wire assessment changed", out)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{e.ErrNotFound, 404}, {e.ErrValidation, 400}, {e.ErrConflict, 409}, {application.ErrForbidden, 403}, {errors.New("private proof SQL secret"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = tc.err
			} else {
				f.runErr = tc.err
			}
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", phase, tc.status), []byte(body), tc.status)
			if strings.Contains(out, "private proof SQL secret") || strings.Contains(out, `"inclusion_proof_hash":`) {
				t.Fatal("failed proof exposed success/private error", out)
			}
		}
	}
}
func TestPublicTransparencyVerificationHTTPCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	f := &transparencyVerificationHTTPFake{}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyProofCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"root_hash":"sha256:` + strings.Repeat("a", 64) + `","leaf_index":0,"tree_size":1,"inclusion_proof":[]}`
	for _, bearer := range []bool{false, true} {
		r := httptest.NewRequest("POST", "https://api.example.test/v1/public-transparency-log-entries/entry/verify", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
		r.Header.Set("Idempotency-Key", fmt.Sprint(bearer))
		r.Header.Set("Content-Type", "application/json")
		want := 403
		if bearer {
			r.Header.Set("Authorization", "Bearer "+secret)
			want = 200
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal("cookie/bearer policy changed", bearer, w.Code, w.Body.String())
		}
	}
}

func TestPublicTransparencyVerificationHTTPLocalReplayRequiresCurrentTenantAuthority(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	log, err := base.ledger.CreatePublicTransparencyLog(t.Context(), a, app.CreatePublicTransparencyLogInput{Name: "fixture", Endpoint: "https://log.example.test", PublicKey: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := base.ledger.CreateMerkleBatch(t.Context(), a, app.CreateMerkleBatchInput{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := base.ledger.CreateTransparencyCheckpoint(t.Context(), a, app.CreateTransparencyCheckpointInput{BatchID: b.ID, Provider: "internal", ExternalID: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := base.ledger.PublishPublicTransparencyLogEntry(t.Context(), a, app.PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: cp.ID, ExternalID: "external"})
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
	path := "/v1/public-transparency-log-entries/" + v.ID + "/verify"
	body := []byte(fmt.Sprintf(`{"root_hash":%q,"leaf_index":0,"tree_size":1,"inclusion_proof":[]}`, v.EntryHash))
	first := postRaw(t, s, secret, path, "replay", body, 200)
	if next := postRaw(t, s, secret, path, "replay", body, 200); next != first {
		t.Fatal("local replay changed assessment")
	}
	postRaw(t, s, secret, path, "replay", append(append([]byte(nil), body...), ' '), 409)
	auth.actor.ResourceGrants[0].ResourceType, auth.actor.ResourceGrants[0].ResourceID = "product", "product"
	postRaw(t, s, secret, path, "replay", body, 403)
	postRaw(t, s, secret, path, "new", body, 403)
}
