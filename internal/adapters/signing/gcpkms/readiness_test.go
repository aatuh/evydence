package gcpkms

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const readinessKeyName = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

func TestReadinessGCPReadsEnabledKeyVersionWithoutSigning(t *testing.T) {
	type reply struct {
		status int
		body   string
	}
	var response atomic.Value
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/"+readinessKeyName || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("health signed, accessed the wrong key, or omitted authentication")
		}
		current := response.Load().(reply)
		w.WriteHeader(current.status)
		_, _ = w.Write([]byte(current.body))
	}))
	defer server.Close()
	var tokenErr error
	executor, err := NewWithTokenSource(Config{Endpoint: server.URL, KeyName: readinessKeyName, Client: server.Client(), TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "signing-only-token"}), ReadinessToken: func(ctx context.Context) (*oauth2.Token, error) {
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("credential probe has no deadline")
		}
		return &oauth2.Token{AccessToken: "private-token"}, tokenErr
	}})
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]any{"name": readinessKeyName, "state": "ENABLED", "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "HSM"}
	encode := func() string {
		t.Helper()
		body, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	check := func(status int, body string, unavailable bool) {
		t.Helper()
		response.Store(reply{status, body})
		err := executor.CheckReadiness(t.Context())
		if (err != nil) != unavailable || (err != nil && (strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), server.URL))) {
			t.Fatalf("unavailable=%v err=%v", unavailable, err)
		}
	}
	check(200, encode(), false)
	check(503, "private-provider-response", true)
	check(200, encode(), false)
	for field, invalid := range map[string]string{"state": "DISABLED", "algorithm": "EC_SIGN_P384_SHA384", "name": "private-other-key"} {
		previous := metadata[field]
		metadata[field] = invalid
		check(200, encode(), true)
		metadata[field] = previous
	}
	for _, body := range []string{"{}", "null", encode() + "{}", strings.Repeat("x", 65537)} {
		check(200, body, true)
	}
	tokenErr = errors.New("private-token-response")
	before := requests.Load()
	check(200, encode(), true)
	if requests.Load() != before {
		t.Fatal("failed credentials triggered a key metadata read")
	}
	tokenErr = nil
	check(200, encode(), false)
}

func TestReadinessGCPRequiresCancellableCredentialsAndDefaultKey(t *testing.T) {
	calls := 0
	config := Config{KeyName: readinessKeyName, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "legacy-token"}), Timeout: 10 * time.Millisecond}
	executor, err := NewWithTokenSource(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); err == nil {
		t.Fatal("contextless token source was used by health")
	}
	config.ReadinessToken = func(ctx context.Context) (*oauth2.Token, error) {
		calls++
		<-ctx.Done()
		return nil, errors.New("private-token-error")
	}
	executor, err = NewWithTokenSource(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("credential deadline lost: %v", err)
	}
	executor.keyName = ""
	if err := executor.CheckReadiness(t.Context()); err == nil || calls != 1 {
		t.Fatal("missing default key triggered credential work or reported healthy")
	}
	executor.keyName = readinessKeyName
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := executor.CheckReadiness(canceled); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled probe triggered credential work", err)
	}
}

type readinessRoundTripper func(*http.Request) (*http.Response, error)

func (f readinessRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestReadinessGCPCredentialsUseRequestContextAndCacheOnlyValidTokens(t *testing.T) {
	for _, credentialJSON := range [][]byte{nil, []byte(`{"type":"authorized_user","client_id":"private-id","client_secret":"private-secret","refresh_token":"private-refresh"}`)} {
		calls := 0
		block := false
		client := &http.Client{Transport: readinessRoundTripper(func(request *http.Request) (*http.Response, error) {
			calls++
			if _, bounded := request.Context().Deadline(); !bounded {
				t.Fatal("credential exchange lost its caller deadline")
			}
			if block {
				<-request.Context().Done()
				return nil, request.Context().Err()
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"private-access","token_type":"Bearer","expires_in":3600}`))}, nil
		})}
		source := newReadinessTokenSource(credentialJSON, client)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		for range 2 {
			token, err := source(ctx)
			if err != nil || token == nil || token.AccessToken != "private-access" {
				t.Fatal("SDK credential exchange failed", err)
			}
		}
		cancel()
		if calls != 1 {
			t.Fatalf("cached token caused %d exchanges", calls)
		}
		if _, err := source(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cached token bypassed cancellation: %v", err)
		}
		block = true
		fresh := newReadinessTokenSource(credentialJSON, client)
		deadline, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
		_, err := fresh(deadline)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("SDK credential request outlived deadline: %v", err)
		}
	}
}

func TestReadinessGCPDefaultConstructorWiresIsolatedCredentialExchange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(file, []byte(`{"type":"authorized_user","client_id":"fixture-id","client_secret":"fixture-secret","refresh_token":"fixture-refresh"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", file)
	tokens, metadata := 0, 0
	client := &http.Client{Transport: readinessRoundTripper(func(request *http.Request) (*http.Response, error) {
		var body string
		switch {
		case request.Method == http.MethodPost && request.URL.Host == "oauth2.googleapis.com":
			tokens++
			body = `{"access_token":"fixture-access","token_type":"Bearer","expires_in":3600}`
		case request.Method == http.MethodGet && request.URL.Host == "cloudkms.googleapis.com" && request.URL.Path == "/v1/"+readinessKeyName:
			metadata++
			if request.Header.Get("Authorization") != "Bearer fixture-access" {
				t.Fatal("default constructor did not use its isolated probe credentials")
			}
			body = `{"name":"` + readinessKeyName + `","state":"ENABLED","algorithm":"EC_SIGN_P256_SHA256"}`
		default:
			t.Fatal("default health used an unexpected provider operation")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	executor, err := New(t.Context(), Config{KeyName: readinessKeyName, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	for range 2 {
		if err := executor.CheckReadiness(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if tokens != 1 || metadata != 2 {
		t.Fatalf("token exchanges=%d metadata reads=%d", tokens, metadata)
	}
}
