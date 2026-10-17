package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestTypedSigningGatewayUsesResolvedTokenAndCapturedTLSSettings(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/ready" || request.Header.Get("Authorization") != "Bearer PRIVATE_FILE_TOKEN" {
			t.Error("gateway lost its readiness method, endpoint or resolved credential")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	file := filepath.Join(t.TempDir(), "PRIVATE_TOKEN_FILE")
	if err := os.WriteFile(file, []byte("PRIVATE_FILE_TOKEN\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := apiCapturedEnvironment(t, "EVYDENCE_SIGNING_KEY_MODE=external", "EVYDENCE_SIGNING_EXECUTOR_URL="+server.URL+"/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL="+server.URL+"/ready", "EVYDENCE_SIGNING_EXECUTOR_TOKEN_FILE="+file, "EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64="+base64.StdEncoding.EncodeToString(make([]byte, 32)), "EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST=true")
	p, err := config.Prepare(e, config.API)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.Resolve(t.Context(), p, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_URL", "PRIVATE_INVALID")
	t.Setenv("EVYDENCE_SIGNING_EXECUTOR_TOKEN", "PRIVATE_CHANGED")
	signer, err := openSigningExecutorConfigured(t.Context(), settings.Providers())
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := signer.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				t.Error("close signing fixture")
			}
		}()
	}
	if err := signingConfigurationReadiness(signer)(t.Context()); err != nil || calls.Load() != 1 {
		t.Fatal("typed gateway did not preserve TLS readiness and file credential", err)
	}
}
