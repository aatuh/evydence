package oidcuserinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestValidateProviderIdentityFetchesUserInfoAndGroups(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"userinfo_endpoint": "http://" + r.Host + "/userinfo"})
		case "/userinfo":
			gotAuth = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "sub-1", "groups": []string{"security", "engineering"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	validator := New(Config{AllowInsecureForLocalhost: true})
	result, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{
		ProviderType: "oidc",
		Issuer:       server.URL,
		Subject:      "sub-1",
		GroupsClaim:  "groups",
		AccessToken:  "secret-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("authorization header = %q", gotAuth)
	}
	if len(result.Groups) != 2 || result.Groups[0] != "security" {
		t.Fatalf("groups = %#v", result.Groups)
	}
	if len(result.Checks) < 4 || result.Checks[2].Name != "oidc_userinfo_subject" || result.Checks[2].Result != "passed" {
		t.Fatalf("checks = %#v", result.Checks)
	}
}

func TestValidateProviderIdentityRejectsSubjectMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"userinfo_endpoint": "http://" + r.Host + "/userinfo"})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "other"})
		}
	}))
	defer server.Close()

	validator := New(Config{AllowInsecureForLocalhost: true})
	result, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{ProviderType: "oidc", Issuer: server.URL, Subject: "sub-1", AccessToken: "secret-token"})
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if len(result.Checks) != 3 || result.Checks[2].Result != "failed" {
		t.Fatalf("checks = %#v", result.Checks)
	}
}

func TestValidateProviderIdentityRequiresHTTPSExceptLocalhostOverride(t *testing.T) {
	validator := New(Config{})
	if _, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{ProviderType: "oidc", Issuer: "http://example.com", Subject: "sub-1", AccessToken: "secret-token"}); err == nil {
		t.Fatal("expected insecure remote issuer to be rejected")
	}
}

func TestValidateProviderIdentityHidesBearerTokenFromErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token secret-token rejected", http.StatusUnauthorized)
	}))
	defer server.Close()

	validator := New(Config{AllowInsecureForLocalhost: true})
	_, err := validator.ValidateProviderIdentity(t.Context(), app.ProviderIdentityValidationRequest{ProviderType: "oidc", Issuer: server.URL, Subject: "sub-1", AccessToken: "secret-token"})
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaked token: %v", err)
	}
}
