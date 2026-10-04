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

type merkleCreationHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	err      error
}

func (f *merkleCreationHTTPFake) AuthorizeMerkleCreation(context.Context, identitydomain.Actor) error {
	f.guards++
	return f.guardErr
}

func (f *merkleCreationHTTPFake) CreateMerkleBatch(_ context.Context, a identitydomain.Actor, _ verificationapp.CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	f.calls++
	return verificationdomain.MerkleBatch{ID: "durable_batch", TenantID: a.TenantID, FromSequence: 1, ToSequence: 1, EntryCount: 1, RootHash: "root", LeafHashes: []string{"root"}, SignatureRefs: []string{"sig"}, SchemaVersion: verificationdomain.MerkleBatchSchemaVersion}, f.err
}
func TestMerkleCreationHTTPUsesFocusedCommandAndPreservesSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &merkleCreationHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{MerkleCreationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.verification = nil
	first := postJSON(t, s, secret, "/v1/merkle-batches", "durable-merkle", map[string]any{}, http.StatusCreated)
	if !strings.Contains(first, `"id":"durable_batch"`) || !strings.Contains(first, `"root_hash":"root"`) || f.calls != 1 {
		t.Fatal(first, f)
	}
	assertTrustHTTPReplay(t, first, postJSON(t, s, secret, "/v1/merkle-batches", "durable-merkle", map[string]any{}, 201))
	if f.calls != 1 {
		t.Fatal("duplicate batch on replay", f)
	}
	for i, bad := range []string{`null`, `[]`, `{"from_sequence":null}`, `{"to_sequence":null}`, `{"from_sequence":"1"}`, `{"to_sequence":9223372036854775808}`, `{"from_sequence":1,"from_sequence":2}`, `{"unknown":1}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/merkle-batches", fmt.Sprintf("bad-merkle-%d", i), []byte(bad), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed input reached signer", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrForbidden, 403}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {verificationapp.ErrNotFound, 404}, {errors.New("private SQL signing key bytes"), 500}} {
		f.err = tc.err
		before := f.calls
		body := postJSON(t, s, secret, "/v1/merkle-batches", fmt.Sprintf("failed-merkle-%d", i), map[string]any{}, tc.status)
		if f.calls != before+1 || strings.Contains(body, "private SQL") || strings.Contains(body, "durable_batch") {
			t.Fatal(body, f)
		}
	}
}

func TestMerkleCreationHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &merkleCreationHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{MerkleCreationCommands: f}); err == nil {
		t.Fatal("focused Merkle creation accepted Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{MerkleCreationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.verification, s.idempotency = nil, nil, nil
	one := postRaw(t, s, secret, "/v1/merkle-batches", "native", []byte(`{}`), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/merkle-batches", "native", []byte(`{}`), 201))
	postRaw(t, s, secret, "/v1/merkle-batches", "native", []byte(`{"from_sequence":1}`), 409)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("replay reran signer or skipped guard", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private-merkle SQL password=secret"), 500}} {
		f.guardErr = tc.err
		before := f.calls
		out := postRaw(t, s, secret, "/v1/merkle-batches", fmt.Sprintf("guard-%d", i), []byte(`{}`), tc.status)
		if f.calls != before || strings.Contains(out, "private-merkle") || strings.Contains(out, `"data"`) {
			t.Fatal("guard failed open or leaked", out)
		}
	}
}

func TestMerkleCreationHTTPRejectsStrictInvalidFieldsInBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &merkleCreationHTTPFake{}
		if native {
			s.merkleCreationCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{`null`, `[]`, `{} {}`, `{"unknown":1}`, `{"FROM_SEQUENCE":1}`, `{"from_sequence":1,"FROM_SEQUENCE":2}`, `{"from_sequence":null}`, `{"to_sequence":null}`, `{"to_sequence":9223372036854775808}`, `{"from_sequence":1.5}`, `{"from_sequence":-1}`, `{"to_sequence":-1}`, `{"from_sequence":2,"to_sequence":1}`, `{"from_sequence":"` + string([]byte{255}) + `"}`, strings.Repeat(" ", 65537)} {
			postRaw(t, s, secret, "/v1/merkle-batches", fmt.Sprintf("invalid-%d", i), []byte(body), 400)
		}
		if f.guards+f.calls != 0 {
			t.Fatal("bad input reached Merkle guard/signer", f)
		}
	}
}

func TestMerkleCreationHTTPBothProfilesCookieAndLocalReplayAuthority(t *testing.T) {
	for _, native := range []bool{false, true} {
		base, secret := testServer(t)
		f := &merkleCreationHTTPFake{}
		opts := ServerOptions{}
		if native {
			opts.MerkleCreationCommands = f
			opts.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://api.example/v1/merkle-batches", strings.NewReader(`{}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.guards + f.calls
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" || tc.status == 403 && f.guards+f.calls != before {
				t.Fatal("unsafe cookie Merkle mutation", native, w.Code, w.Body.String())
			}
		}
	}
	base, secret := testServer(t)
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
	one := postRaw(t, s, secret, "/v1/merkle-batches", "local", []byte(`{}`), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/merkle-batches", "local", []byte(`{}`), 201))
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/merkle-batches", "local", []byte(`{}`), 403)
}
