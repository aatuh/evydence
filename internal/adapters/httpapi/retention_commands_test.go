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

type retentionHTTPFake struct {
	creates, verifies int
	input             verificationapp.CreateObjectRetentionPolicyInput
	err               error
}

func (f *retentionHTTPFake) CreateObjectRetentionPolicy(_ context.Context, actor identitydomain.Actor, input verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	f.creates++
	f.input = input
	return verificationdomain.ObjectRetentionPolicy{ID: "policy_focused", TenantID: actor.TenantID, Name: input.Name, Status: "configured"}, f.err
}
func (f *retentionHTTPFake) VerifyObjectRetentionPolicy(_ context.Context, actor identitydomain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	f.verifies++
	return verificationdomain.ObjectRetentionPolicy{ID: id, TenantID: actor.TenantID, Status: "not_verified", VerificationHash: "receipt"}, f.err
}
func TestRetentionHandlersUseFocusedCommandsAndReplayWithoutFallback(t *testing.T) {
	server, secret := testServer(t)
	commands := &retentionHTTPFake{}
	server.retentionCommands = commands
	input := map[string]any{"name": "lock", "mode": "governance", "retention_days": 30}
	path := "/v1/object-retention-policies"
	response := postJSON(t, server, secret, path, "focused-retention-create", input, http.StatusCreated)
	if dataField(t, response, "id") != "policy_focused" || commands.input.Name != "lock" {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, path, "focused-retention-create", input, http.StatusCreated); replay != response || commands.creates != 1 {
		t.Fatal("create replay reran command")
	}
	path += "/policy_focused/verify"
	response = postJSON(t, server, secret, path, "focused-retention-verify", map[string]any{}, http.StatusOK)
	if dataField(t, response, "verification_hash") != "receipt" {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, path, "focused-retention-verify", map[string]any{}, http.StatusOK); replay != response || commands.verifies != 1 {
		t.Fatal("verify replay reran command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("provider password=private-secret"), 500}} {
		commands.err = tc.err
		for _, path := range []string{"/v1/object-retention-policies", "/v1/object-retention-policies/policy_focused/verify"} {
			body := input
			if strings.HasSuffix(path, "/verify") {
				body = map[string]any{}
			}
			response := postJSON(t, server, secret, path, "retention-error-"+string(rune('a'+i))+path, body, tc.status)
			if strings.Contains(response, "private-secret") || strings.Contains(response, `"data"`) {
				t.Fatal("error leaked or fell back", response)
			}
		}
	}
}
func TestRetentionHandlersRejectMalformedBodiesBeforeCommandsInBothProfiles(t *testing.T) {
	for _, focused := range []bool{false, true} {
		server, secret := testServer(t)
		commands := &retentionHTTPFake{}
		if focused {
			server.retentionCommands = commands
		}
		for i, bad := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"name":null,"mode":"governance","retention_days":30}`, `{"name":"lock","mode":null,"retention_days":30}`, `{"name":"lock","mode":"governance","retention_days":null}`, `{"name":"lock","name":"other","mode":"governance","retention_days":30}`, `{"name":"lock","mode":"governance","retention_days":1.5}`, `{"name":"lock","mode":"governance","retention_days":9223372036854775808}`, `{"name":"lock","mode":"governance","retention_days":30,"object_key":null}`, `{"name":"lock","mode":"governance","retention_days":30,"object_prefix":null}`, `{"name":"lock","mode":"governance","retention_days":30,"require_legal_hold":null}`, `{"name":"lock","mode":"governance","retention_days":30,"max_verification_age_hours":null}`, `{"name":"lock","mode":"governance","retention_days":30,"max_verification_age_hours":0}`} {
			postRaw(t, server, secret, "/v1/object-retention-policies", "bad-create-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
		}
		for i, bad := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"mode":"governance"}`} {
			postRaw(t, server, secret, "/v1/object-retention-policies/missing/verify", "bad-verify-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
		}
		if commands.creates != 0 || commands.verifies != 0 {
			t.Fatal("malformed request reached focused command")
		}
	}
}
