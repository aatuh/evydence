package httpgateway

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessGatewayUsesExplicitAuthenticatedReadOnlyEndpoint(t *testing.T) {
	type reply struct {
		status int
		body   string
	}
	var response atomic.Value
	response.Store(reply{http.StatusOK, `{"status":"ok"}`})
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/readiness" || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("health accessed a signing endpoint or omitted authentication")
		}
		current := response.Load().(reply)
		w.WriteHeader(current.status)
		_, _ = w.Write([]byte(current.body))
	}))
	defer server.Close()
	executor, err := New(Config{Endpoint: server.URL + "/sign", ReadinessEndpoint: server.URL + "/readiness", BearerToken: "private-token", VerificationPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)), AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status      int
		body        string
		unavailable bool
	}{
		{200, `{"status":"ok"}`, false},
		{503, `private-provider-details`, true},
		{200, `{"status":"unavailable"}`, true},
		{200, `{"status":"ok","private-token":"secret"}`, true},
		{200, `{"status":"ok"}{}`, true},
		{200, `null`, true},
		{204, "", true},
		{200, `{"status":"ok"}` + strings.Repeat(" ", 4096), true},
		{200, `{"status":"ok"}`, false},
	} {
		response.Store(reply{tc.status, tc.body})
		err := executor.CheckReadiness(t.Context())
		if (err != nil) != tc.unavailable || (err != nil && (strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), server.URL))) {
			t.Fatalf("unavailable=%v err=%v", tc.unavailable, err)
		}
	}
	if calls.Load() != 9 {
		t.Fatalf("readiness calls=%d", calls.Load())
	}
}

func TestReadinessGatewayRejectsCrossOriginOrCredentialBearingURLs(t *testing.T) {
	for _, endpoint := range []string{
		"https://other.example.test/readiness", "http://signer.example.test/readiness",
		"https://signer.example.test:444/readiness", "https://user:private-password@signer.example.test/readiness",
		"https://signer.example.test/readiness?private-token=secret", "https://signer.example.test/readiness#private-fragment", "/readiness",
	} {
		_, err := New(Config{Endpoint: "https://signer.example.test/sign", ReadinessEndpoint: endpoint, VerificationPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))})
		if err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatalf("unsafe health URL accepted/disclosed: %v", err)
		}
	}
}

func TestReadinessGatewayRequiresEndpointAndHonorsDeadlines(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	config := Config{Endpoint: server.URL + "/sign", VerificationPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)), AllowInsecureForLocalhost: true, Timeout: 20 * time.Millisecond}
	executor, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); err == nil || calls.Load() != 0 {
		t.Fatal("missing readiness endpoint triggered network work or reported healthy")
	}
	config.ReadinessEndpoint = server.URL + "/readiness"
	executor, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
	before := calls.Load()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := executor.CheckReadiness(canceled); !errors.Is(err, context.Canceled) || calls.Load() != before {
		t.Fatal("canceled health performed network work", err)
	}
}

func TestReadinessGatewayNeverForwardsCredentialsThroughRedirects(t *testing.T) {
	var sinkCalls atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sinkCalls.Add(1) }))
	defer sink.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	executor, err := New(Config{Endpoint: server.URL + "/sign", ReadinessEndpoint: server.URL + "/ready", BearerToken: "private-token", VerificationPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)), AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); err == nil || strings.Contains(err.Error(), "private-") || sinkCalls.Load() != 0 {
		t.Fatal("health followed or disclosed an authenticated redirect", err)
	}
}
