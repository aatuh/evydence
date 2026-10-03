package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signingKeyHTTPFake struct {
	rotations, revocations int
	err                    error
}

func (f *signingKeyHTTPFake) RotateSigningKey(_ context.Context, actor identitydomain.Actor, _ string) (verificationdomain.SigningKey, error) {
	f.rotations++
	status, _ := verificationdomain.ParseSigningKeyStatus("active")
	return verificationdomain.SigningKey{ID: "key_focused", TenantID: actor.TenantID, Version: 2, Status: status, PublicKey: "public"}, f.err
}
func (f *signingKeyHTTPFake) RevokeSigningKey(_ context.Context, actor identitydomain.Actor, id string, input verificationapp.SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	f.revocations++
	status, _ := verificationdomain.ParseSigningKeyStatus("revoked")
	return verificationdomain.SigningKey{ID: id, TenantID: actor.TenantID, Status: status, RevocationReason: input.Reason}, f.err
}
func TestSigningKeyHandlersUseFocusedCommandsAndReplay(t *testing.T) {
	server, secret := testServer(t)
	commands := &signingKeyHTTPFake{}
	server.signingKeyCommands = commands
	input := map[string]any{"reason": "scheduled"}
	response := postJSON(t, server, secret, "/v1/signing-keys/rotate", "focused-rotate", input, http.StatusCreated)
	if dataField(t, response, "id") != "key_focused" || dataField(t, response, "status") != "active" {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, "/v1/signing-keys/rotate", "focused-rotate", input, http.StatusCreated); replay != response || commands.rotations != 1 {
		t.Fatal("rotation replay reran command")
	}
	response = postJSON(t, server, secret, "/v1/signing-keys/key_focused/revoke", "focused-revoke", input, http.StatusOK)
	if dataField(t, response, "status") != "revoked" {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, "/v1/signing-keys/key_focused/revoke", "focused-revoke", input, http.StatusOK); replay != response || commands.revocations != 1 {
		t.Fatal("revocation replay reran command")
	}
	for i, bad := range []string{`{}`, `null`, `{"reason":null}`, `{"reason":" "}`, `{"reason":1}`, `{"reason":"a","reason":"b"}`, `{"reason":"a","unknown":true}`, `[]`, `{} {}`} {
		for _, path := range []string{"/v1/signing-keys/rotate", "/v1/signing-keys/key_focused/revoke"} {
			postRaw(t, server, secret, path, "bad-key-"+string(rune('a'+i))+path, []byte(bad), http.StatusBadRequest)
		}
	}
	if commands.rotations != 1 || commands.revocations != 1 {
		t.Fatal("malformed input reached key commands")
	}
	for i, bad := range []string{`{"reason":"incident","semantics":null}`, `{"reason":"incident","historical_validity_policy":null}`} {
		postRaw(t, server, secret, "/v1/signing-keys/key_focused/revoke", "bad-null-key-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.revocations != 1 {
		t.Fatal("null lifecycle policy reached key command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{application.ErrForbidden, http.StatusForbidden}, {verificationapp.ErrNotFound, http.StatusNotFound}, {verificationapp.ErrConflict, http.StatusConflict}, {errors.New("private SQL and key material"), http.StatusInternalServerError}} {
		commands.err = tc.err
		for _, path := range []string{"/v1/signing-keys/rotate", "/v1/signing-keys/key_focused/revoke"} {
			response := postJSON(t, server, secret, path, "error-key-"+string(rune('a'+i))+path, input, tc.status)
			if strings.Contains(response, "private SQL") || strings.Contains(response, `"data"`) {
				t.Fatal("key command error leaked internal data", response)
			}
		}
	}
}
