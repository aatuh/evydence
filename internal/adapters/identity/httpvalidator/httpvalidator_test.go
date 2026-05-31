package httpvalidator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestValidateProviderIdentityPostsSafeRequestAndReturnsChecks(t *testing.T) {
	var gotAuth string
	var gotRequest validationRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(validationResponse{
			Subject: "sub-1",
			Groups:  []string{"security", "security", "engineering"},
			Checks:  []domain.VerifyCheck{{Name: "github_team_membership", Result: "passed"}},
			Limitations: []string{
				"Gateway checked provider membership with operator-managed credentials.",
			},
		})
	}))
	defer server.Close()

	validator, err := New(Config{Endpoint: server.URL, BearerToken: "gateway-token", AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{
		TenantID:     "ten_1",
		ProviderID:   "sso_1",
		ProviderType: "oidc",
		Issuer:       "https://idp.example.test",
		Subject:      "sub-1",
		GroupsClaim:  "groups",
		AccessToken:  "access-token-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer gateway-token" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotRequest.AccessToken != "access-token-secret" || !gotRequest.AccessTokenPresent || gotRequest.Subject != "sub-1" {
		t.Fatalf("request = %#v", gotRequest)
	}
	if len(result.Groups) != 2 || result.Groups[0] != "security" || result.Groups[1] != "engineering" {
		t.Fatalf("groups = %#v", result.Groups)
	}
	if len(result.Checks) < 3 || result.Checks[0].Name != "provider_validation_gateway" || result.Checks[0].Result != "passed" {
		t.Fatalf("checks = %#v", result.Checks)
	}
}

func TestValidateProviderIdentityRejectsSubjectMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(validationResponse{Subject: "other"})
	}))
	defer server.Close()

	validator, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{Subject: "sub-1"})
	if err == nil {
		t.Fatal("expected subject mismatch to fail")
	}
	if len(result.Checks) != 1 || result.Checks[0].Name != "provider_validation_gateway_subject" || result.Checks[0].Result != "failed" {
		t.Fatalf("checks = %#v", result.Checks)
	}
}

func TestValidateProviderIdentityRejectsUnknownResponseFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"subject":"sub-1","unexpected":"nope"}`))
	}))
	defer server.Close()

	validator, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{Subject: "sub-1"}); err == nil {
		t.Fatal("expected strict response decoding to reject unknown fields")
	}
}

func TestValidateProviderIdentityHidesGatewayBodyAndTokensFromErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "access-token-secret rejected", http.StatusUnauthorized)
	}))
	defer server.Close()

	validator, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{Subject: "sub-1", AccessToken: "access-token-secret"})
	if err == nil {
		t.Fatal("expected provider validation failure")
	}
	if strings.Contains(err.Error(), "access-token-secret") {
		t.Fatalf("error leaked access token: %v", err)
	}
}

func TestNewRequiresHTTPSEndpointExceptLocalhostOverride(t *testing.T) {
	if _, err := New(Config{Endpoint: "http://example.com/provider"}); err == nil {
		t.Fatal("expected remote HTTP endpoint to be rejected")
	}
	if _, err := New(Config{Endpoint: "http://127.0.0.1/provider", AllowInsecureForLocalhost: true}); err != nil {
		t.Fatalf("localhost override should be accepted: %v", err)
	}
}
