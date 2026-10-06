package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type trustConfigurationHTTPFake struct {
	providers, roots, guards int
	providerInput            verificationapp.CreateSigningProviderInput
	rootInput                verificationapp.CreateDSSETrustRootInput
	err                      error
	guardErr                 error
}

func (f *trustConfigurationHTTPFake) AuthorizeTrustConfiguration(context.Context, identitydomain.Actor) error {
	f.guards++
	return f.guardErr
}

// Use the real replay algorithm instead of a fake that invokes every command.
type trustHTTPReplayExecutor struct{ factory app.UnitOfWorkFactory }

func newTrustHTTPReplayExecutor(t *testing.T, server *Server, secret string) trustHTTPReplayExecutor {
	t.Helper()
	a, err := server.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	f := app.NewMemoryUnitOfWorkFactory()
	if err := app.ExecuteUnitOfWork(t.Context(), f, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: a.TenantID, Name: "Tenant", CreatedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)})
	}); err != nil {
		t.Fatal(err)
	}
	return trustHTTPReplayExecutor{f}
}

func assertTrustHTTPReplay(t *testing.T, first, replay string) {
	t.Helper()
	// Durable reload reconstructs the same JSON object with a different key
	// order. Compare every field/value (with exact numbers), not serialization.
	var left, right any
	a, b := json.NewDecoder(strings.NewReader(first)), json.NewDecoder(strings.NewReader(replay))
	a.UseNumber()
	b.UseNumber()
	if a.Decode(&left) != nil || b.Decode(&right) != nil || !reflect.DeepEqual(left, right) {
		t.Fatal("replay changed original JSON result")
	}
}

func (e trustHTTPReplayExecutor) WithBody(ctx context.Context, a domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	x := app.IdempotencyUnitOfWork{Transactions: e.factory, Authorize: func(ctx context.Context, _ app.Repositories) error { return authorize(ctx) }}
	return x.WithBody(ctx, a, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) { return run(ctx) })
}

func (e trustHTTPReplayExecutor) WithBodyReplayAuthorization(ctx context.Context, a domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, authorizeReplay func(context.Context, any) error, run func(context.Context) (int, any, error)) (int, any, error) {
	x := app.IdempotencyUnitOfWork{Transactions: e.factory, Authorize: func(ctx context.Context, _ app.Repositories) error { return authorize(ctx) }, AuthorizeReplay: func(ctx context.Context, _ app.Repositories, response any) error {
		return authorizeReplay(ctx, response)
	}}
	return x.WithBody(ctx, a, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) { return run(ctx) })
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
	server.durableCommandExecutor = newTrustHTTPReplayExecutor(t, server, secret)
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
		assertTrustHTTPReplay(t, response, postJSON(t, server, secret, tc.path, "focused"+tc.path, tc.input, http.StatusCreated))
	}
	if commands.providers != 1 || commands.roots != 1 || commands.guards != 4 || commands.providerInput.KeyRef != "key" || commands.rootInput.ExpectedBuilderIDs[0] != "builder" {
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
			server.durableCommandExecutor = newTrustHTTPReplayExecutor(t, server, secret)
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

func TestTrustConfigurationHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &trustConfigurationHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{TrustConfigurationCommands: f}); err == nil {
		t.Fatal("focused trust configuration accepted Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{TrustConfigurationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.verification, s.idempotency = nil, nil, nil
	routes := []struct{ path, body string }{
		{"/v1/signing-providers", `{"name":" KMS ","type":" aws_kms ","key_ref":" key ","encrypted":true}`},
		{"/v1/dsse-trust-roots", `{"name":" Builder ","key_id":" key ","algorithm":" Ed25519 ","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_predicate_types":["https://slsa.dev/provenance/v1"],"expected_builder_ids":[" other "," builder "],"required_claims":["external_parameters","builder_id"]}`},
	}
	for _, route := range routes {
		one := postRaw(t, s, secret, route.path, "native", []byte(route.body), 201)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, route.path, "native", []byte(route.body), 201))
	}
	if f.providers != 1 || f.roots != 1 || f.guards != 4 || f.providerInput.Name != "KMS" || f.providerInput.Type != "aws_kms" || f.rootInput.KeyID != "key" || !reflect.DeepEqual(f.rootInput.ExpectedBuilderIDs, []string{"builder", "other"}) || f.rootInput.RequiredClaims[0] != "builder_id" {
		t.Fatal("normalized input or replay was lost")
	}
	for i, ec := range []struct {
		err    error
		status int
	}{
		{verificationapp.ErrNotFound, 404}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private trust SQL password=secret"), 500},
	} {
		f.guardErr = ec.err
		for _, route := range routes {
			before := f.providers + f.roots
			out := postRaw(t, s, secret, route.path, fmt.Sprintf("denied-%d", i), []byte(route.body), ec.status)
			if f.providers+f.roots != before || strings.Contains(out, "private trust") || strings.Contains(out, `"data"`) {
				t.Fatal("guard failed open or leaked", out)
			}
		}
	}
}

func TestTrustConfigurationHTTPStrictFieldsBeforeCommandsInBothProfiles(t *testing.T) {
	for _, focused := range []bool{false, true} {
		s, secret := testServer(t)
		f := &trustConfigurationHTTPFake{}
		if focused {
			s.trustConfigurationCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for _, route := range []struct {
			path   string
			fields map[string]any
		}{
			{"/v1/signing-providers", map[string]any{"name": "KMS", "type": "aws_kms", "key_ref": "key", "encrypted": true}},
			{"/v1/dsse-trust-roots", map[string]any{"name": "Builder", "key_id": "key", "algorithm": "Ed25519", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "allowed_predicate_types": []string{"https://slsa.dev/provenance/v1"}, "expected_builder_ids": []string{"builder"}, "required_claims": []string{"builder_id"}}},
		} {
			base, err := json.Marshal(route.fields)
			if err != nil {
				t.Fatal(err)
			}
			bad := []string{strings.Repeat(" ", 65537), strings.Replace(string(base), `"name":"`, `"name":"`+string([]byte{255}), 1)}
			for field := range route.fields {
				bad = append(bad, strings.TrimSuffix(string(base), "}")+fmt.Sprintf(",%q:null}", strings.ToUpper(field)))
				bad = append(bad, strings.TrimSuffix(string(base), "}")+fmt.Sprintf(",%q:null}", field))
			}
			for field, value := range route.fields {
				if _, ok := value.(string); ok {
					for _, invalid := range []string{"", " ", "bad\x00", strings.Repeat(" ", 4096) + value.(string)} {
						route.fields[field] = invalid
						b, err := json.Marshal(route.fields)
						if err != nil {
							t.Fatal(err)
						}
						bad = append(bad, string(b))
					}
				} else if _, ok := value.([]string); ok {
					first := value.([]string)[0]
					for _, invalid := range []any{[]any{nil, first}, []string{strings.Repeat("b", 4097)}, []string{}, []string{"", first}, []string{first, first}, []string{" " + first + " ", first}} {
						route.fields[field] = invalid
						b, err := json.Marshal(route.fields)
						if err != nil {
							t.Fatal(err)
						}
						bad = append(bad, string(b))
					}
				}
				route.fields[field] = value
			}
			for i, body := range bad {
				postRaw(t, s, secret, route.path, fmt.Sprintf("strict-%d", i), []byte(body), 400)
			}
		}
		if f.guards+f.providers+f.roots != 0 {
			t.Fatal("bad input reached native commands")
		}
	}
}

func TestTrustConfigurationHTTPBothProfilesCookieAndLocalReplayAuthority(t *testing.T) {
	base, secret := testServer(t)
	for _, focused := range []bool{false, true} {
		f := &trustConfigurationHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.TrustConfigurationCommands = f
			opts.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/v1/signing-providers", "/v1/dsse-trust-roots"} {
			for i, tc := range []struct {
				origin string
				bearer bool
				status int
			}{
				{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201},
			} {
				body := `{"name":"KMS","type":"aws_kms","key_ref":"key"}`
				if path == "/v1/dsse-trust-roots" {
					body = fmt.Sprintf(`{"name":"Builder","key_id":%q,"algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_predicate_types":["https://slsa.dev/provenance/v1"],"expected_builder_ids":["builder"],"required_claims":["builder_id"]}`, fmt.Sprintf("cookie-%t-%d", focused, i))
				}
				r := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%t-%d", focused, i))
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				before := f.providers + f.roots + f.guards
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" || tc.status == 403 && f.providers+f.roots+f.guards != before {
					t.Fatal("unsafe cookie trust mutation", focused, path, w.Code, w.Body.String())
				}
			}
		}
	}
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"keys:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"name":"KMS","type":"aws_kms","key_ref":"key"}`
	one := postRaw(t, s, secret, "/v1/signing-providers", "local-replay", []byte(body), 201)
	if two := postRaw(t, s, secret, "/v1/signing-providers", "local-replay", []byte(body), 201); one != two {
		t.Fatal("local replay differs")
	}
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/signing-providers", "local-replay", []byte(body), 403)
}
