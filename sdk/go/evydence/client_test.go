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
