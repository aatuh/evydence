package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

type resolverStub map[string][]netip.Addr

func (r resolverStub) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	addresses, ok := r[host]
	if !ok {
		return nil, errors.New("not found")
	}
	return addresses, nil
}

func ipAddress(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func TestClientRejectsPrivateAndMetadataDestinations(t *testing.T) {
	client, err := New(Config{Resolver: resolverStub{
		"private.example.test":  {ipAddress("10.0.0.4")},
		"metadata.example.test": {ipAddress("169.254.169.254")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"https://private.example.test/path", "https://metadata.example.test/path"} {
		response, err := client.Get(endpoint)
		if response != nil {
			response.Body.Close()
		}
		if !errors.Is(err, ErrDestinationDenied) {
			t.Fatalf("Get(%q) error=%v, want destination denial", endpoint, err)
		}
	}
}

func TestClientRejectsDNSRebindingToLoopbackBeforeDial(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer server.Close()
	client, err := New(Config{Resolver: resolverStub{"provider.example.test": {ipAddress("127.0.0.1")}}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("https://provider.example.test" + server.URL[len("http://127.0.0.1"):])
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("Get error=%v, want destination denial", err)
	}
	if hit {
		t.Fatal("rebinding destination was dialed")
	}
}

func TestClientRejectsRedirectBeforeSensitiveHeadersReachAnotherOrigin(t *testing.T) {
	redirectTargetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("authorization reached redirect target: %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()
	client, err := New(Config{AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer secret")
	response, err := client.Do(request)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("client.Do error=%v, want redirect denial", err)
	}
	if redirectTargetHit {
		t.Fatal("redirect target was called")
	}
}

func TestClientAllowsExplicitLoopbackDevelopmentEndpointOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	client, err := New(Config{AllowInsecureForLocalhost: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestClientRejectsHostOutsideProfileAllowlist(t *testing.T) {
	client, err := New(Config{AllowedHosts: []string{"provider.example.test"}, Resolver: resolverStub{"other.example.test": {ipAddress("8.8.8.8")}}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("https://other.example.test")
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("Get error=%v, want allowlist denial", err)
	}
}

func TestClientStopsResponseAtConfiguredLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("oversized"))
	}))
	defer server.Close()
	client, err := New(Config{AllowInsecureForLocalhost: true, MaxResponseBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("ReadAll error=%v, want response-limit failure", err)
	}
}
