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

type trustConfigurationHTTPFake struct {
	providers, roots int
	providerInput    verificationapp.CreateSigningProviderInput
	rootInput        verificationapp.CreateDSSETrustRootInput
	err              error
}

func (f *trustConfigurationHTTPFake) CreateSigningProvider(_ context.Context, actor identitydomain.Actor, input verificationapp.CreateSigningProviderInput) (verificationdomain.SigningProvider, error) {
	f.providers++
	f.providerInput = input
	return verificationdomain.SigningProvider{ID: "focused_provider", TenantID: actor.TenantID, Name: input.Name, KeyRef: input.KeyRef, Type: input.Type, Status: "active", Encrypted: input.Encrypted}, f.err
}
func (f *trustConfigurationHTTPFake) CreateDSSETrustRoot(_ context.Context, actor identitydomain.Actor, input verificationapp.CreateDSSETrustRootInput) (verificationdomain.DSSETrustRoot, error) {
	f.roots++
	f.rootInput = input
	return verificationdomain.DSSETrustRoot{ID: "focused_root", TenantID: actor.TenantID, Name: input.Name, KeyID: input.KeyID, PublicKey: input.PublicKey, RequiredClaims: input.RequiredClaims, ExpectedBuilderIDs: input.ExpectedBuilderIDs, Status: "active"}, f.err
}
func TestTrustConfigurationHandlersUseFocusedCommandsAndPreserveReplay(t *testing.T) {
	server, secret := testServer(t)
	commands := &trustConfigurationHTTPFake{}
	server.trustConfigurationCommands = commands
	provider := map[string]any{"name": "KMS", "type": "aws_kms", "key_ref": "key", "encrypted": true}
	root := map[string]any{"name": "Builder", "key_id": "builder-key", "algorithm": "Ed25519", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "allowed_predicate_types": []string{"https://slsa.dev/provenance/v1"}, "expected_builder_ids": []string{"builder"}, "required_claims": []string{"builder_id"}}
	for _, tc := range []struct {
		path, id string
		input    map[string]any
	}{{"/v1/signing-providers", "focused_provider", provider}, {"/v1/dsse-trust-roots", "focused_root", root}} {
		response := postJSON(t, server, secret, tc.path, "focused"+tc.path, tc.input, http.StatusCreated)
		if dataField(t, response, "id") != tc.id {
			t.Fatal("not focused", response)
		}
		if replay := postJSON(t, server, secret, tc.path, "focused"+tc.path, tc.input, http.StatusCreated); replay != response {
			t.Fatal("replay changed")
		}
	}
	if commands.providers != 1 || commands.roots != 1 || commands.providerInput.KeyRef != "key" || commands.rootInput.ExpectedBuilderIDs[0] != "builder" {
		t.Fatal("inputs lost or replay duplicated command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("SQL password=private-secret"), 500}} {
		commands.err = tc.err
		for _, route := range []struct {
			path  string
			input map[string]any
		}{{"/v1/signing-providers", provider}, {"/v1/dsse-trust-roots", root}} {
			response := postJSON(t, server, secret, route.path, "error-"+string(rune('a'+i))+route.path, route.input, tc.status)
			if strings.Contains(response, "private-secret") || strings.Contains(response, `"data"`) {
				t.Fatal("error leaked or fallback ran", response)
			}
		}
	}
}
func TestTrustConfigurationHandlersRejectMalformedAndNullFieldsInBothProfiles(t *testing.T) {
	for _, focused := range []bool{false, true} {
		server, secret := testServer(t)
		commands := &trustConfigurationHTTPFake{}
		if focused {
			server.trustConfigurationCommands = commands
		}
		for _, path := range []string{"/v1/signing-providers", "/v1/dsse-trust-roots"} {
			for i, bad := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"name":"a","name":"b"}`, `{"name":1}`} {
				postRaw(t, server, secret, path, "bad-"+string(rune('a'+i))+path, []byte(bad), 400)
			}
		}
		for i, field := range []string{"name", "type", "key_ref", "encrypted"} {
			input := map[string]any{"name": "KMS", "type": "aws_kms", "key_ref": "key", "encrypted": true}
			input[field] = nil
			postJSON(t, server, secret, "/v1/signing-providers", "null-provider-"+string(rune('a'+i)), input, 400)
		}
		for i, field := range []string{"name", "key_id", "algorithm", "public_key", "allowed_predicate_types", "expected_builder_ids", "required_claims"} {
			input := map[string]any{"name": "Builder", "key_id": "key", "algorithm": "Ed25519", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "allowed_predicate_types": []string{"https://slsa.dev/provenance/v1"}, "expected_builder_ids": []string{"builder"}, "required_claims": []string{"builder_id"}}
			input[field] = nil
			postJSON(t, server, secret, "/v1/dsse-trust-roots", "null-root-"+string(rune('a'+i)), input, 400)
		}
		if commands.providers != 0 || commands.roots != 0 {
			t.Fatal("malformed input reached commands")
		}
	}
}
