package httpclient

import (
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCloseIdleClosesOwnedCloneAndPreservesBorrowedPool(t *testing.T) {
	verifyOwnedClone(t, func(borrowed *http.Client) (*http.Client, error) {
		return New(Config{Client: borrowed, AllowInsecureForLocalhost: true})
	})
}

func TestCloneOwnedClosesOnlyOwnedTransport(t *testing.T) {
	verifyOwnedClone(t, func(borrowed *http.Client) (*http.Client, error) { return CloneOwned(borrowed), nil })
}

func verifyOwnedClone(t *testing.T, clone func(*http.Client) (*http.Client, error)) {
	t.Helper()
	closed := make(chan string, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, html.EscapeString(r.RemoteAddr))
	}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- conn.RemoteAddr().String()
		}
	}
	server.Start()
	defer server.Close()
	borrowed := &http.Client{Transport: &http.Transport{}}
	defer borrowed.CloseIdleConnections()
	owned, err := clone(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.CloseIdleConnections()
	get := func(client *http.Client) string {
		t.Helper()
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
		return string(data)
	}
	borrowedAddress := get(borrowed)
	ownedAddress := get(owned)
	if borrowedAddress == ownedAddress {
		t.Fatal("policy client reused caller transport pool")
	}
	owned.CloseIdleConnections()
	select {
	case address := <-closed:
		if address != ownedAddress {
			t.Fatal("closed caller-owned connection", address)
		}
	case <-time.After(time.Second):
		t.Fatal("owned transport connection remained open")
	}
	if got := get(borrowed); got != borrowedAddress {
		t.Fatal("caller transport pool was closed", got, borrowedAddress)
	}
}

type borrowedClosingTransport struct{ closes atomic.Int32 }

func (b *borrowedClosingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
}
func (b *borrowedClosingTransport) CloseIdleConnections() { b.closes.Add(1) }

func TestClientCloseIdleNeverClosesBorrowedCustomTransport(t *testing.T) {
	transport := &borrowedClosingTransport{}
	client, err := New(Config{Client: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	client.CloseIdleConnections()
	if transport.closes.Load() != 0 {
		t.Fatal("policy wrapper closed caller-owned custom transport")
	}
	copy := CloneOwned(&http.Client{Transport: transport})
	copy.CloseIdleConnections()
	if transport.closes.Load() != 0 {
		t.Fatal("owned clone closed borrowed custom transport")
	}
}
