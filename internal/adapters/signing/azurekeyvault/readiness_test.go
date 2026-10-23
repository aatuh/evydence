package azurekeyvault

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type readinessCredential func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (c readinessCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return c(ctx, opts)
}

func TestReadinessAzureChecksKeyMetadataAndRecoversWithoutSigning(t *testing.T) {
	curve := elliptic.P256().Params()
	status, body := http.StatusOK, ""
	var requests atomic.Int64
	type reply struct {
		status int
		body   string
	}
	var response atomic.Value
	response.Store(reply{status, body})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/keys/required/version" || r.URL.Query().Get("api-version") != "7.4" || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("health performed an unexpected or unauthenticated request")
		}
		current := response.Load().(reply)
		w.WriteHeader(current.status)
		_, _ = w.Write([]byte(current.body))
	}))
	defer server.Close()
	executor, err := NewWithCredential(Config{VaultURL: server.URL, KeyName: "required", KeyVersion: "version", Credential: staticCredential("private-token"), Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	key := map[string]any{"kid": server.URL + "/keys/required/version", "kty": "EC", "crv": "P-256", "key_ops": []string{"sign", "verify"}, "x": base64.RawURLEncoding.EncodeToString(curve.Gx.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(curve.Gy.FillBytes(make([]byte, 32)))}
	attributes := map[string]any{"enabled": true}
	metadata := map[string]any{"key": key, "attributes": attributes, "tags": map[string]string{"private-label": "private-value"}}
	encode := func() {
		t.Helper()
		value, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		body = string(value)
	}
	check := func(unavailable bool) {
		t.Helper()
		response.Store(reply{status, body})
		err := executor.CheckReadiness(t.Context())
		if (err != nil) != unavailable || (err != nil && (strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), server.URL))) {
			t.Fatalf("unavailable=%v err=%v", unavailable, err)
		}
	}
	encode()
	check(false)
	status, body = http.StatusServiceUnavailable, "private-provider-response"
	check(true)
	status = http.StatusOK
	encode()
	check(false)
	for field, value := range map[string]any{"enabled": false, "exp": time.Now().Add(-time.Hour).Unix(), "nbf": time.Now().Add(time.Hour).Unix()} {
		attributes[field] = value
		encode()
		check(true)
		delete(attributes, field)
		attributes["enabled"] = true
	}
	for field, value := range map[string]any{"kid": server.URL + "/keys/other/version", "kty": "RSA", "crv": "P-384", "key_ops": []string{"verify"}, "x": "broken", "y": "broken"} {
		previous := key[field]
		key[field] = value
		encode()
		check(true)
		key[field] = previous
	}
	for _, invalid := range []string{"{}", "null", "private-malformed", strings.Repeat("x", 65537)} {
		body = invalid
		check(true)
	}
	encode()
	body += "{}"
	check(true)
	encode()
	check(false)
	if requests.Load() == 0 {
		t.Fatal("readiness did not read metadata")
	}
}

func TestReadinessAzureRequiresConfiguredKeyAndCancellableCredentials(t *testing.T) {
	calls := 0
	credential := readinessCredential(func(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
		calls++
		if len(options.Scopes) != 1 || options.Scopes[0] != "https://vault.azure.net/.default" {
			t.Fatal("wrong credential scope")
		}
		<-ctx.Done()
		return azcore.AccessToken{}, errors.New("private-token-error")
	})
	executor, err := NewWithCredential(Config{VaultURL: "https://vault.example.test", Credential: credential, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); err == nil || calls != 0 {
		t.Fatal("missing default key triggered credential access or reported healthy")
	}
	executor.keyName, executor.keyVersion = "required", "version"
	if err := executor.CheckReadiness(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("credential deadline lost: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := executor.CheckReadiness(canceled); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancellation did credential work: calls=%d err=%v", calls, err)
	}
}
