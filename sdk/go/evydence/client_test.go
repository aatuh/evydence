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

func TestReleaseLedgerTypedHelpersUseContractRoutes(t *testing.T) {
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.Method + " " + r.URL.Path
		seen[route] = true
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("Idempotency-Key"); got != "idem-typed" {
			t.Fatalf("idempotency header = %q", got)
		}

		switch route {
		case "POST /v1/products":
			var body CreateProductRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode product: %v", err)
			}
			if body.Name != "API" || body.Slug != "api" {
				t.Fatalf("product body = %#v", body)
			}
		case "POST /v1/releases":
			var body CreateReleaseRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode release: %v", err)
			}
			if body.ProductID != "prod_1" || body.ProjectID != "proj_1" || body.Version != "1.0.0" {
				t.Fatalf("release body = %#v", body)
			}
		case "POST /v1/artifacts":
			var body RegisterArtifactRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact: %v", err)
			}
			if body.ReleaseID != "rel_1" || body.Digest != "sha256:abc" || body.Size != 42 {
				t.Fatalf("artifact body = %#v", body)
			}
		case "POST /v1/builds":
			var body CreateBuildRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode build: %v", err)
			}
			if body.ProjectID != "proj_1" || body.ReleaseID != "rel_1" || body.Provider != "github_actions" || body.CommitSHA != "0123456789abcdef0123456789abcdef01234567" || body.Status != "passed" || len(body.Outputs) != 1 {
				t.Fatalf("build body = %#v", body)
			}
		default:
			t.Fatalf("unexpected route %s", route)
		}
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, APIKey: "secret", HTTP: server.Client()}
	calls := []struct {
		name string
		run  func() error
	}{
		{
			name: "product",
			run: func() error {
				return client.CreateProduct(context.Background(), "idem-typed", CreateProductRequest{Name: "API", Slug: "api"}, nil)
			},
		},
		{
			name: "release",
			run: func() error {
				return client.CreateRelease(context.Background(), "idem-typed", CreateReleaseRequest{ProductID: "prod_1", ProjectID: "proj_1", Version: "1.0.0"}, nil)
			},
		},
		{
			name: "artifact",
			run: func() error {
				return client.RegisterArtifact(context.Background(), "idem-typed", RegisterArtifactRequest{ReleaseID: "rel_1", Digest: "sha256:abc", Size: 42}, nil)
			},
		},
		{
			name: "build",
			run: func() error {
				return client.CreateBuild(context.Background(), "idem-typed", CreateBuildRequest{
					ProjectID: "proj_1",
					ReleaseID: "rel_1",
					Provider:  "github_actions",
					CommitSHA: "0123456789abcdef0123456789abcdef01234567",
					Status:    "passed",
					StartedAt: "2026-05-28T10:00:00Z",
					Outputs:   []BuildOutput{{Digest: "sha256:abc"}},
				}, nil)
			},
		},
	}
	for _, call := range calls {
		t.Run(call.name, func(t *testing.T) {
			if err := call.run(); err != nil {
				t.Fatalf("call failed: %v", err)
			}
		})
	}
	for _, route := range []string{"POST /v1/products", "POST /v1/releases", "POST /v1/artifacts", "POST /v1/builds"} {
		if !seen[route] {
			t.Fatalf("missing route %s", route)
		}
	}
}

func TestReadinessHelpersUseGetAndSafeErrors(t *testing.T) {
	const secretBody = "token=secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		switch r.URL.Path {
		case "/v1/ready":
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("public readiness should not send blank API key authorization header: %q", got)
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/v1/reports/release-readiness":
			if got := r.Header.Get("Authorization"); got != "Bearer secret" {
				t.Fatalf("authorization header = %q", got)
			}
			if got := r.URL.Query().Get("release_id"); got != "rel 1+#" {
				t.Fatalf("release_id query = %q", got)
			}
			http.Error(w, secretBody, http.StatusForbidden)
		default:
			t.Fatalf("unexpected path %s", r.URL.String())
		}
	}))
	defer server.Close()

	var ready map[string]string
	if err := (Client{BaseURL: server.URL, HTTP: server.Client()}).Readiness(context.Background(), &ready); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if ready["status"] != "ok" {
		t.Fatalf("ready = %#v", ready)
	}

	err := (Client{BaseURL: server.URL, APIKey: " secret ", HTTP: server.Client()}).
		ReleaseReadiness(context.Background(), "rel 1+#", nil)
	if err == nil {
		t.Fatal("expected status error")
	}
	if !strings.Contains(err.Error(), "status 403") || strings.Contains(err.Error(), secretBody) {
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
