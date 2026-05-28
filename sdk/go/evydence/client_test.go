package evydence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostSendsAuthenticatedIdempotentRequest(t *testing.T) {
	var saw bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = true
		if r.Method != http.MethodPost || r.URL.Path != "/v1/evidence" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer evy_secret" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("Idempotency-Key"); got != "idem-1" {
			t.Fatalf("idempotency header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["title"] != "Build" {
			t.Fatalf("body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"data":{"id":"ev_1"}}`))
	}))
	defer server.Close()

	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	client := Client{BaseURL: server.URL + "/", APIKey: " evy_secret ", HTTP: server.Client()}
	if err := client.Post(context.Background(), "/v1/evidence", "idem-1", map[string]string{"title": "Build"}, &out); err != nil {
		t.Fatalf("post: %v", err)
	}
	if !saw || out.Data.ID != "ev_1" {
		t.Fatalf("saw=%v out=%#v", saw, out)
	}
}

func TestPostRejectsInvalidInputsBeforeNetwork(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, APIKey: "secret", HTTP: server.Client()}
	if err := client.Post(context.Background(), "/evidence", "idem-1", map[string]string{}, nil); err == nil {
		t.Fatal("expected invalid path error")
	}
	if err := client.Post(context.Background(), "/v1/evidence", "   ", map[string]string{}, nil); err == nil {
		t.Fatal("expected invalid idempotency key error")
	}
	if called {
		t.Fatal("invalid client input should not make a network request")
	}
}

func TestPostReturnsSafeStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "secret body should not be returned", http.StatusForbidden)
	}))
	defer server.Close()

	err := Client{BaseURL: server.URL, APIKey: "secret", HTTP: server.Client()}.
		Post(context.Background(), "/v1/evidence", "idem-1", map[string]string{"title": "Build"}, nil)
	if err == nil {
		t.Fatal("expected status error")
	}
	if !strings.Contains(err.Error(), "status 403") || strings.Contains(err.Error(), "secret body") {
		t.Fatalf("unsafe or unexpected error: %v", err)
	}
}

func TestCreateSSOProviderUsesTypedRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sso/providers" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Idempotency-Key"); got != "sso-provider-1" {
			t.Fatalf("idempotency header = %q", got)
		}
		var body CreateSSOProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Name != "Okta" || body.Type != "oidc" || body.Issuer != "https://idp.example.test" || body.ClientID != "client" {
			t.Fatalf("body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"data":{"id":"sso_1","name":"Okta"}}`))
	}))
	defer server.Close()

	var out map[string]any
	err := Client{BaseURL: server.URL, APIKey: "secret", HTTP: server.Client()}.
		CreateSSOProvider(context.Background(), "sso-provider-1", CreateSSOProviderRequest{
			Name:     "Okta",
			Type:     "oidc",
			Issuer:   "https://idp.example.test",
			ClientID: "client",
		}, &out)
	if err != nil {
		t.Fatalf("create sso provider: %v", err)
	}
	if out["data"] == nil {
		t.Fatalf("out = %#v", out)
	}
}

func TestVerifyProviderIdentityUsesTypedRouteAndSafeErrors(t *testing.T) {
	const secretToken = "header.payload.signature"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/provider-verifications" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body VerifyProviderIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.ProviderID != "sso_1" || body.ProviderType != "oidc" || body.Subject != "sub-1" || body.IDToken != secretToken {
			t.Fatalf("body = %#v", body)
		}
		http.Error(w, secretToken, http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	err := Client{BaseURL: server.URL, APIKey: "secret", HTTP: server.Client()}.
		VerifyProviderIdentity(context.Background(), "verify-1", VerifyProviderIdentityRequest{
			ProviderType: "oidc",
			ProviderID:   "sso_1",
			Subject:      "sub-1",
			IDToken:      secretToken,
		}, nil)
	if err == nil {
		t.Fatal("expected verification error")
	}
	if !strings.Contains(err.Error(), "status 422") || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("unsafe or unexpected error: %v", err)
	}
}
